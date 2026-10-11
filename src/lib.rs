//! Qualia2FA 的 FFI 层：把 `qualia2fa-core` 暴露为 UniFFI 绑定。
//!
//! # 本 crate 的职责边界
//!
//! 这里**只做搬运**：把 Kotlin/Swift 传进来的原始类型转成核心类型、调用核心、
//! 把结果转回去。**任何加密、解析、校验逻辑出现在本文件里都是设计倒退**——
//! 那些必须留在 `qualia2fa-core` 内，因为只有核心是无 unsafe、可独立审计的。
//!
//! 审查本仓库时的检查项就一条：**有没有把核心的逻辑搬到这里来**。
//!
//! # 为什么不能 `#![forbid(unsafe_code)]`
//!
//! `uniffi::setup_scaffolding!()` 在本 crate 内展开 FFI 边界所需的 unsafe 代码
//! （裸指针解引用、`catch_unwind`、字符串所有权转移）。FFI 边界本身就是 unsafe 的。
//!
//! 安全边界因此划在 **crate 之间**：核心 `forbid(unsafe_code)`，本 crate 是唯一
//! 允许 unsafe 的地方，且必须是薄的。`Cargo.toml` 里把 `unsafe_code` 设为 `warn`
//! 而非 `allow`，是为了让任何新增的 unsafe 在构建时发出声音。
//!
//! # 秘密材料的处理约定
//!
//! 核心的 [`OtpSecret`] **刻意不实现 `Clone`、不暴露裸字节**，且其 `Debug` 连
//! 长度都不打印。跨 FFI 边界时统一以 **Base32 字符串**作为种子的表示形式：
//!
//! - 传入：`&str` → [`OtpSecret::from_base32`]
//! - 传出：[`OtpSecret::to_base32`]
//!
//! 于是种子的字节永远不会以 `Vec<u8>` 形式经过 FFI（那会在两侧各留一份不受
//! 擦除控制的拷贝）。Base32 是核心已选定的「唯一窄出口」，这里沿用同一决定。
//!
//! ⚠️ **已知残留风险**：Base32 字符串在 Kotlin/Swift 侧是普通 `String`，
//! 不受 `secrecy` 的擦除保护，且可能被 GC 复制、进字符串常量池。这是托管语言的
//! 固有限制，**端侧必须自行约定**：种子的 Base32 只在必要作用域内存在，用完立即
//! 丢弃，绝不写入日志或持久化。见 TODO.md 的端侧安全约定。

uniffi::setup_scaffolding!();

use std::sync::Arc;

use qualia2fa_core::auth;
use qualia2fa_core::device::{DevicePublicKey, DeviceSignature};
use qualia2fa_core::flow::{self, DeviceKeys as _, Joiner, Login, SecureStore as _};
use qualia2fa_core::otp::{self, Algorithm, Digits, OtpSecret};
use qualia2fa_core::recovery::KdfParams;
use qualia2fa_core::uri;
use qualia2fa_core::vault::{Entry, MasterKey, VaultFile};
use qualia2fa_core::{Error, ExposeSecret as _, SecretString};

/// 挑战-应答的会话标识长度。
///
/// 核心的 `auth::SESSION_ID_LEN` 是**私有**常量（它属于协议内部，不该被上层依赖），
/// 因此这里按协议长度写死。这个数字不是随手取的：核心 `pairing::SESSION_ID_LEN`
/// 同样是 32，两处一致是有意的——同一条信道上的会话标识必须等长，否则上层做
/// 会话比较时会出现「长度不同所以必然不等」的假阴性。
const AUTH_SESSION_ID_LEN: usize = 32;

/// 挑战-应答的确认标签长度（核心 `auth::CONFIRM_LEN`，同为私有）。
const AUTH_CONFIRM_LEN: usize = 32;

/// 跨 FFI 边界传入的种子字符串的长度上限（字符数）。
///
/// 真实种子是 16–64 字节（Base32 约 26–104 字符）。这里给到 2048，留足非标准
/// 场景的余量，同时挡掉「端侧被诱导传入一个巨大字符串」这类无意义输入。
///
/// **这是防御性上限，不是规范要求**：核心刻意不对种子长度设下限（真实世界存在
/// 短种子），「长度是否达标」的判断属于 UI 层的告警，见
/// [`is_secret_shorter_than_recommended`]。
const MAX_SECRET_CHARS: usize = 2048;

/// 跨 FFI 边界传入的 `otpauth://` URI 的长度上限（字符数）。
///
/// 真实 URI 通常不到 200 字符。二维码容量上限约 2953 字节，故 4096 足以容纳
/// 任何来自二维码的 URI，同时挡住超大输入。
const MAX_URI_CHARS: usize = 4096;

/// 跨 FFI 边界传入的保险库字段长度上限（字符数）。
///
/// 核心对解密后的字段有自己的上限（`Entry::MAX_FIELD_LEN`，64 KiB 字节），但那是
/// **解密后**的防线。这里挡的是从端侧进来的一侧：界面上的文本框不该有理由塞进
/// 比这更长的内容，在边界上拒绝比让它走完一次加密再在核心报错更省事，也避免
/// 「用户输入了几 MB」这种情况进入加密路径。
///
/// 取 8 KiB 字符（而非核心的 64 KiB 字节）：按字符计是因为端侧传来的是字符串，
/// 按字节计会让含中文的备注更容易触发上限，行为不好解释。8 KiB 字符已经远超任何
/// 真实的服务名/账号名/备注。
const MAX_VAULT_FIELD_CHARS: usize = 8 * 1024;

/// 跨 FFI 边界传入的设备标签长度上限（字符数）。
///
/// 标签会进入平台密钥库，而各平台对密钥名的长度限制不同（Windows CNG、Android
/// Keystore、iOS 的 keychain 都有限制，且不都公开）。真实标签是 `qualia2fa-device`
/// 这类短串，256 字符足够，同时挡住「端侧被诱导传入一个巨大的标签」。
const MAX_LABEL_CHARS: usize = 256;

/// 跨 FFI 边界传入的口令长度上限（字符数）。
///
/// 口令会进入 Argon2，而 Argon2 的处理时间随输入长度线性增长。没有上限时，一个
/// 几 MB 的「口令」能让导出/导入长时间占住线程。真实口令远短于此——**限制长度
/// 不是安全措施**（口令的强度来自熵而不是长度），只是拒绝无意义输入。
const MAX_PASSPHRASE_CHARS: usize = 1024;

/// 跨 FFI 边界传入的二维码文本长度上限（字符数）。
///
/// 二维码载荷是 99 字节，Base32 后 159 个字符。给到 512 留出端侧可能带的前后缀
/// （例如用户从聊天记录里连引号一起复制过来）的余量，同时挡住超大输入。
const MAX_QR_TEXT_CHARS: usize = 512;

/// 核心错误的摘要，用于跨 FFI 边界传递。
///
/// # 为什么需要这一层，而不是直接把核心 `Error` 放进去
///
/// UniFFI 要求错误枚举的每个字段都实现 `Lift`/`Lower`/`TypeId`。核心的
/// [`Error`] 是一个 `#[non_exhaustive]` 的富错误枚举（含 `String`、`usize`
/// 等载荷），它并不是一个 UniFFI 类型——除非把它整个标注为
/// `#[uniffi::Error]`，而那会把核心与绑定生成器重新耦合在一起，
/// 正是本项目要避免的（见 TODO.md §4.4）。
///
/// 另一种做法是给错误枚举加 `#[uniffi(flat_error)]`，让所有变体只以
/// `Display` 文本跨边界。那样端侧只剩一个不透明的字符串，**无法按失败原因
/// 分流 UI**（「种子输入错误」要提示用户重输，「周期为 0」是程序缺陷，
/// 「随机源不可用」要提示重试——三者对用户的意义完全不同）。
///
/// 因此这里显式拆出两个字段：
///
/// - `kind`：稳定的机器可读标识，端侧用它分支
/// - `message`：面向用户的文本，仅用于展示与日志
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiCoreError {
    /// 稳定的错误标识，见 [`core_error_kind`] 的约定。
    pub kind: String,
    /// 面向人的错误文本（与核心 `Display` 一致）。
    pub message: String,
}

/// 把核心错误映射为**稳定的**机器可读标识。
///
/// # 稳定性契约
///
/// 这些字符串是端侧 `switch` 的依据，因此**属于公开接口**：可以新增，
/// 但既有值不得改名或改变含义（改名等同于破坏端侧行为）。
///
/// 端侧必须对未知 `kind` 有兜底分支——核心是 `#[non_exhaustive]` 的，
/// 未来会新增变体，旧端侧会遇到没见过的值。
///
/// 这里刻意**不用** `format!("{source:?}")` 或变体名的自动派生：Debug 输出
/// 是实现细节，重命名变体会静默改变端侧行为，且 `Debug` 里可能带载荷内容。
/// 逐个 `match` 写死字符串，是为了让「改了名字」在代码审查时显式可见。
#[must_use]
pub fn core_error_kind(source: &Error) -> &'static str {
    match source {
        Error::Base32InvalidCharacter { .. } => "base32_invalid_character",
        Error::Base32InvalidLength { .. } => "base32_invalid_length",
        Error::Base32InvalidPadding => "base32_invalid_padding",
        Error::SecretEmpty => "secret_empty",
        Error::SecretTooShort { .. } => "secret_too_short",
        Error::UnsupportedAlgorithm { .. } => "unsupported_algorithm",
        Error::UnsupportedDigits { .. } => "unsupported_digits",
        Error::InvalidPeriod => "invalid_period",
        Error::RandomnessUnavailable => "randomness_unavailable",
        Error::UriUnsupportedScheme => "uri_unsupported_scheme",
        Error::UriMissingType => "uri_missing_type",
        Error::UriUnsupportedType { .. } => "uri_unsupported_type",
        Error::UriMissingSecret => "uri_missing_secret",
        Error::UriMissingCounter => "uri_missing_counter",
        Error::UriUnexpectedCounter => "uri_unexpected_counter",
        Error::UriDuplicateParameter { .. } => "uri_duplicate_parameter",
        Error::UriInvalidParameter { .. } => "uri_invalid_parameter",
        Error::UriInvalidPercentEncoding => "uri_invalid_percent_encoding",
        Error::UriIssuerMismatch { .. } => "uri_issuer_mismatch",
        Error::UriAccountContainsColon { .. } => "uri_account_contains_colon",
        // ── M2：保险库 ────────────────────────────────────────────────────
        Error::VaultTruncated => "vault_truncated",
        Error::VaultBadMagic => "vault_bad_magic",
        Error::VaultUnsupportedVersion { .. } => "vault_unsupported_version",
        Error::VaultReservedByteNotZero { .. } => "vault_reserved_byte_not_zero",
        Error::VaultUnknownRecordKind { .. } => "vault_unknown_record_kind",
        Error::VaultRecordTooLong { .. } => "vault_record_too_long",
        Error::VaultTooManyRecords => "vault_too_many_records",
        Error::VaultTrailingBytes { .. } => "vault_trailing_bytes",
        Error::VaultDuplicateEntryId => "vault_duplicate_entry_id",
        // 与「保险库为空」严格区分：界面在「列表是空的，引导添加第一条」与「你正在
        // 操作的那一条已经不在了，刷新列表」之间的动作完全不同。合并两者会让界面
        // 显示一个空列表，而用户刚才明明还在看条目。
        Error::VaultEntryNotFound => "vault_entry_not_found",
        Error::VaultDuplicateField { .. } => "vault_duplicate_field",
        Error::VaultCorrupt => "vault_corrupt",
        Error::VaultInvalidUtf8 => "vault_invalid_utf8",
        // 端侧最需要单独分流的一个：主密钥与文件不匹配。
        Error::VaultDecryptionFailed => "vault_decryption_failed",
        Error::MasterKeyWrongLength { .. } => "master_key_wrong_length",
        Error::FieldTooLong { .. } => "field_too_long",
        Error::VaultIo { .. } => "vault_io",
        // ── M3：设备身份、配对、恢复、挑战-应答 ──────────────────────────
        Error::DevicePublicKeyInvalid { .. } => "device_public_key_invalid",
        Error::DeviceSignatureInvalid { .. } => "device_signature_invalid",
        Error::PairingPayloadMalformed { .. } => "pairing_payload_malformed",
        Error::PairingUnsupportedVersion { .. } => "pairing_unsupported_version",
        // 配对失败的原因**刻意不细分**（密文被改、会话不对、加入方公钥不对都归这里），
        // 免得给攻击者一个区分「差一点就成功」的预言机。端侧的文案也应当保持笼统：
        // 「配对失败，请重新扫码」而不是「密钥错误」。
        Error::PairingAuthenticationFailed => "pairing_authentication_failed",
        Error::RecoveryFileMalformed { .. } => "recovery_file_malformed",
        Error::RecoveryParametersInvalid { .. } => "recovery_parameters_invalid",
        Error::RecoveryPassphraseEmpty => "recovery_passphrase_empty",
        Error::RecoveryAuthenticationFailed => "recovery_authentication_failed",
        Error::RecoveryEncryptionFailed => "recovery_encryption_failed",
        Error::RecoveryKdfFailed => "recovery_kdf_failed",
        Error::UnsupportedFormatVersion { .. } => "unsupported_format_version",
        Error::AuthMessageMalformed { .. } => "auth_message_malformed",
        Error::AuthProofFailed => "auth_proof_failed",
        Error::DeviceKeyMissing => "device_key_missing",
        // 与 `vault_decryption_failed` 严格区分：这个表示「这台设备从来没登录过」，
        // 界面应当引导注册/登录；那个表示「登录过但数据解不开」，界面必须警告数据
        // 可能已丢失。合并两者会让用户在被引导重新注册时永久失去原有条目。
        Error::DeviceNotRegistered => "device_not_registered",
        Error::DeviceIdentityMismatch => "device_identity_mismatch",
        Error::SecureStoreWriteFailed { .. } => "secure_store_write_failed",
        Error::TimestampZero => "timestamp_zero",
        // 兜底分支是**必需**的：核心的 `Error` 标了 `#[non_exhaustive]`，因此它
        // 自己的 crate 之外必须有一个通配分支（去掉这里会报 E0004）。
        //
        // 代价是**新增核心变体时编译器不会提醒**——`"unknown"` 会悄悄兜住它，端侧
        // 收到一个无法分派的 kind。防这个的是一条测试（
        // `every_mapped_error_kind_is_distinct_and_known`），不是编译器：给每个新
        // 变体加一行映射、并把它加进那条测试的列表。
        _ => "unknown",
    }
}

impl FfiError {
    /// 稳定的错误标识，供端侧分派界面文案。
    ///
    /// 端侧本可以直接读 `FfiError.Core.detail.kind`，但那要求每个调用点都先判断
    /// 是哪个变体。这个方法把「边界自身的错误」也纳入同一套标识
    /// （`input_too_long`），于是端侧只需要一个 `when`。
    ///
    /// # 为什么是稳定契约
    ///
    /// 这些字符串是**接口的一部分**：端侧的文案分支按它们分派。改名等于破坏兼容，
    /// 因此只能新增，不能改已有值。
    #[must_use]
    pub fn kind(&self) -> &str {
        match self {
            FfiError::InputTooLong { .. } => "input_too_long",
            FfiError::Core { detail } => &detail.kind,
        }
    }
}

impl From<Error> for FfiCoreError {
    fn from(source: Error) -> Self {
        FfiCoreError {
            kind: core_error_kind(&source).to_owned(),
            message: source.to_string(),
        }
    }
}

/// 让 [`FfiCoreError`] 能以 `Display` 形式参与外层错误的文案。
///
/// 手写而非 derive：`Display` 输出的就是 `message`，不再重复拼 `kind`——
/// `kind` 是给程序看的，把它塞进面向用户的文本只会增加噪音。
///
/// 之所以需要它：`#[error("{source}")]` 要求 `source` 实现 `Display`，
/// 否则 thiserror 会转而把它当作 `Error::source()` 处理并报
/// 「`as_dyn_error` 的 trait 约束未满足」。
impl core::fmt::Display for FfiCoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

/// FFI 边界自身的错误。
///
/// 与核心的 [`Error`] 分开，因为「输入超长」是**边界**的问题，不是核心的语义。
/// 核心错误经 [`FfiCoreError`] 结构化透传，不等同于丢弃分类。
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// 输入超过本层设定的上限。
    #[error("输入过长：{kind} 上限为 {limit} 字符，实际 {actual} 字符")]
    InputTooLong {
        /// 被限制的输入类别（`secret` / `uri`）。
        kind: String,
        /// 允许的最大字符数。
        limit: u64,
        /// 实际字符数。
        actual: u64,
    },

    /// 核心返回的错误。
    ///
    /// **不加 `#[from]`**：`#[from]` 会让 thiserror 生成
    /// `impl From<Error> for FfiError`，但 UniFFI 要求每个字段都是可跨边界的
    /// 类型，而核心 `Error` 不是。转换由手写 `From` 完成，经 [`FfiCoreError`]
    /// 结构化为纯数据后再跨边界。
    ///
    /// 字段名刻意用 `detail` 而非 `source`：thiserror 把名为 `source` 的字段
    /// 一律当作 `Error::source()` 处理（要求实现 `std::error::Error`），
    /// 即使文案里只写 `{source}` 也一样，会报 `as_dyn_error` 约束不满足。
    #[error("{detail}")]
    Core {
        /// 核心错误的结构化摘要。
        detail: FfiCoreError,
    },
}

/// 核心错误 → FFI 错误的转换。
///
/// 手写而非用 `#[from]`，原因见 [`FfiError::Core`] 的说明。
impl From<Error> for FfiError {
    fn from(source: Error) -> Self {
        FfiError::Core {
            detail: source.into(),
        }
    }
}

/// 从 FFI 传入的哈希算法选择。
///
/// 不直接暴露核心的 [`Algorithm`]，原因有二：
///
/// 1. 中间隔一层，端侧枚举命名变化不会影响 Rust 侧 API。
/// 2. 未来核心若改为携带数据的枚举，FFI 契约不受影响。
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiAlgorithm {
    /// HMAC-SHA-1（RFC 6238 默认；几乎所有真实服务端都只支持它）。
    Sha1,
    /// HMAC-SHA-256。
    Sha256,
    /// HMAC-SHA-512。
    Sha512,
}

impl From<FfiAlgorithm> for Algorithm {
    fn from(value: FfiAlgorithm) -> Self {
        match value {
            FfiAlgorithm::Sha1 => Algorithm::Sha1,
            FfiAlgorithm::Sha256 => Algorithm::Sha256,
            FfiAlgorithm::Sha512 => Algorithm::Sha512,
        }
    }
}

/// 验证码位数。
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiDigits {
    /// 6 位（默认）。
    Six,
    /// 7 位（部分银行使用）。
    Seven,
    /// 8 位。
    Eight,
}

impl From<FfiDigits> for Digits {
    fn from(value: FfiDigits) -> Self {
        match value {
            FfiDigits::Six => Digits::Six,
            FfiDigits::Seven => Digits::Seven,
            FfiDigits::Eight => Digits::Eight,
        }
    }
}

/// `otpauth://` 的类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiUriType {
    /// 基于时间。
    Totp,
    /// 基于计数器。
    Hotp,
}

impl From<uri::UriType> for FfiUriType {
    fn from(value: uri::UriType) -> Self {
        match value {
            uri::UriType::Totp => FfiUriType::Totp,
            uri::UriType::Hotp => FfiUriType::Hotp,
        }
    }
}

impl From<FfiUriType> for uri::UriType {
    fn from(value: FfiUriType) -> Self {
        match value {
            FfiUriType::Totp => uri::UriType::Totp,
            FfiUriType::Hotp => uri::UriType::Hotp,
        }
    }
}

/// 解析后的 `otpauth://` 条目。
///
/// 字段与核心的 [`uri::OtpAuth`] 一一对应，唯一区别是 `secret` 以 Base32 字符串
/// 而非 `OtpSecret` 出现（见模块文档）。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiOtpAuth {
    /// TOTP 还是 HOTP。
    pub uri_type: FfiUriType,
    /// 种子，Base32 编码（大写）。
    pub secret_base32: String,
    /// 发行方（服务名），如 `GitHub`。
    pub issuer: Option<String>,
    /// 账号名，如 `alice@example.com`。
    pub account: String,
    /// 使用的哈希算法。
    pub algorithm: FfiAlgorithm,
    /// 验证码位数。
    pub digits: FfiDigits,
    /// 时间步长（秒）。
    ///
    /// **不变量**：HOTP 条目此值恒为核心默认值且无意义（HOTP 按计数器推进）。
    /// 与核心 [`uri::OtpAuth::period`] 的约定一致。
    pub period: u64,
    /// HOTP 的计数器。TOTP 时为 `None`。
    pub counter: Option<u64>,
}

/// 检查字符串长度上限，超限则报 [`FfiError::InputTooLong`]。
///
/// 按**字符数**而非字节数计——端侧传来的字符串可能含多字节字符，按字节计会让
/// 含中文 issuer 的 URI 更容易触发上限，行为难以向用户解释。
fn check_len(kind: &str, value: &str, limit: usize) -> Result<(), FfiError> {
    let actual = value.chars().count();
    if actual > limit {
        return Err(FfiError::InputTooLong {
            kind: kind.to_owned(),
            limit: limit as u64,
            actual: actual as u64,
        });
    }
    Ok(())
}

/// 解析 `otpauth://` URI。
///
/// 完整实现 Google Authenticator Key URI Format 的解析与校验，包含
/// issuer/account 前缀一致性检查、重复参数拒绝、百分号解码等。
///
/// # 错误
///
/// 输入超长返回 [`FfiError::InputTooLong`]；其余返回核心错误
/// （[`FfiError::Core`]），含义见核心 `Error` 的文档。
#[uniffi::export]
pub fn parse_otpauth_uri(uri: String) -> Result<FfiOtpAuth, FfiError> {
    check_len("uri", &uri, MAX_URI_CHARS)?;
    let parsed = uri::parse(&uri)?;
    Ok(FfiOtpAuth {
        uri_type: parsed.uri_type.into(),
        secret_base32: parsed.secret.to_base32(),
        issuer: parsed.issuer,
        account: parsed.account,
        algorithm: match parsed.algorithm {
            Algorithm::Sha1 => FfiAlgorithm::Sha1,
            Algorithm::Sha256 => FfiAlgorithm::Sha256,
            Algorithm::Sha512 => FfiAlgorithm::Sha512,
        },
        digits: match parsed.digits {
            Digits::Six => FfiDigits::Six,
            Digits::Seven => FfiDigits::Seven,
            Digits::Eight => FfiDigits::Eight,
        },
        period: parsed.period,
        counter: parsed.counter,
    })
}

/// 把 [`FfiOtpAuth`] 序列化回 `otpauth://` URI。
///
/// # 错误
///
/// 账号名含 `:` 时核心会拒绝——该字符与 `issuer:account` 的分隔符不可区分，
/// 强行编码会导致「写出去再读回来，issuer/account 归属变了」。这是**有意的**
/// 拒绝，不是缺陷。
#[uniffi::export]
pub fn serialize_otpauth_uri(auth: FfiOtpAuth) -> Result<String, FfiError> {
    check_len("secret", &auth.secret_base32, MAX_SECRET_CHARS)?;
    // 先按引用读出需要移动的字段，再构造核心类型——直接写
    // `issuer: auth.issuer` 会在同一函数里既借又移，编译器会拒绝。
    let secret = OtpSecret::from_base32(&auth.secret_base32)?;
    let core_auth = uri::OtpAuth {
        uri_type: auth.uri_type.into(),
        secret,
        issuer: auth.issuer,
        account: auth.account,
        algorithm: auth.algorithm.into(),
        digits: auth.digits.into(),
        period: auth.period,
        counter: auth.counter,
    };
    Ok(uri::serialize(&core_auth)?)
}

/// 计算 TOTP 验证码。
///
/// `unix_time` 是 Unix 秒，**由端侧提供**——核心不读时钟，这是刻意的：只有时间
/// 作为参数传入，RFC 6238 的测试向量才能被确定性地验证。端侧应传系统时钟秒数。
///
/// 返回值是定宽十进制字符串（含前导零），长度由 `digits` 决定。
#[uniffi::export]
pub fn totp_code(
    secret_base32: String,
    unix_time: u64,
    period: u64,
    algorithm: FfiAlgorithm,
    digits: FfiDigits,
) -> Result<String, FfiError> {
    check_len("secret", &secret_base32, MAX_SECRET_CHARS)?;
    let secret = OtpSecret::from_base32(&secret_base32)?;
    Ok(otp::totp_code(
        &secret,
        unix_time,
        period,
        algorithm.into(),
        digits.into(),
    )?)
}

/// 计算 HOTP 验证码。
#[uniffi::export]
pub fn hotp_code(
    secret_base32: String,
    counter: u64,
    algorithm: FfiAlgorithm,
    digits: FfiDigits,
) -> Result<String, FfiError> {
    check_len("secret", &secret_base32, MAX_SECRET_CHARS)?;
    let secret = OtpSecret::from_base32(&secret_base32)?;
    Ok(otp::hotp_code(
        &secret,
        counter,
        algorithm.into(),
        digits.into(),
    ))
}

/// 计算 Steam Guard 验证码（5 位，自定义字母表）。
///
/// `period` 通常传 30——Steam 使用 30 秒步长。
#[uniffi::export]
pub fn steam_guard_code(
    secret_base32: String,
    unix_time: u64,
    period: u64,
    algorithm: FfiAlgorithm,
) -> Result<String, FfiError> {
    check_len("secret", &secret_base32, MAX_SECRET_CHARS)?;
    let secret = OtpSecret::from_base32(&secret_base32)?;
    Ok(otp::steam_guard_code(
        &secret,
        unix_time,
        period,
        algorithm.into(),
    )?)
}

/// 校验用户输入的验证码，允许时间漂移。
///
/// `expected_counter` 是当前时间对应的计数器（`unix_time / period`）。
/// `window` 是允许的漂移步数（RFC 6238 建议 1，即 ±1 步）。
///
/// 返回命中的偏移量：`0` 表示当前步命中，`-1` 表示落后一步，`1` 表示超前一步，
/// 依此类推。**返回偏移量而非布尔值**，是为了让端侧据此校准该条目的时钟偏差，
/// 而不是只得到「对/错」。
///
/// 比较使用常量时间实现，不会因「前几位对了」而提前返回。
/// 返回 `None` 表示校验失败（含输入格式不对的情况）。
#[uniffi::export]
pub fn verify_code_with_drift(
    secret_base32: String,
    expected_counter: u64,
    window: u64,
    algorithm: FfiAlgorithm,
    digits: FfiDigits,
    provided_code: String,
) -> Result<Option<i64>, FfiError> {
    check_len("secret", &secret_base32, MAX_SECRET_CHARS)?;
    let secret = OtpSecret::from_base32(&secret_base32)?;
    Ok(otp::verify_with_drift(
        &secret,
        expected_counter,
        window,
        algorithm.into(),
        digits.into(),
        &provided_code,
    ))
}

/// 常量时间地比较两个验证码字符串是否相同。
///
/// 用于端侧已自行算出验证码的场景。若需要容错时钟漂移，用
/// [`verify_code_with_drift`]。
#[uniffi::export]
#[must_use]
pub fn codes_match(expected: String, provided: String) -> bool {
    otp::verify_code(&expected, &provided)
}

/// 该算法建议的最小种子长度（字节）。
///
/// 用于端侧在导入条目时给出**告警**而非拒绝——核心刻意不强制最小长度，因为
/// 真实世界存在短种子，硬拒会让用户无法导入本可用的账号。
#[uniffi::export]
#[must_use]
pub fn recommended_min_secret_len(algorithm: FfiAlgorithm) -> u64 {
    otp::recommended_min_secret_len(algorithm.into()) as u64
}

/// 判断种子是否短于建议长度。
///
/// 比让端侧自行比较长度更好：端侧拿不到种子的**字节**长度（只有 Base32 字符串），
/// 而 Base32 长度与字节长度非线性相关（5 位/字符 vs 8 位/字节），端侧自己算易错。
#[uniffi::export]
pub fn is_secret_shorter_than_recommended(
    secret_base32: String,
    algorithm: FfiAlgorithm,
) -> Result<bool, FfiError> {
    check_len("secret", &secret_base32, MAX_SECRET_CHARS)?;
    let secret = OtpSecret::from_base32(&secret_base32)?;
    Ok(secret.is_shorter_than_recommended(algorithm.into()))
}

/// 种子的**字节**长度（不是 Base32 字符串长度）。
///
/// 供端侧显示「20 字节 / 建议 20 字节」这类提示。
#[uniffi::export]
pub fn secret_byte_len(secret_base32: String) -> Result<u64, FfiError> {
    check_len("secret", &secret_base32, MAX_SECRET_CHARS)?;
    let secret = OtpSecret::from_base32(&secret_base32)?;
    Ok(secret.len() as u64)
}

/// 生成一个随机的 256 位种子并返回其 Base32 表示。
///
/// 用于「新建条目时自动生成种子」。随机数来自 OS CSPRNG（`getrandom`），
/// **不是**用户态 PRNG。
///
/// 256 位是刻意的选择：它是 SHA-256 的输出长度，且远超所有受支持算法建议的
/// 最小长度（20/32/64 字节中最大者为 64 字节 = 512 位，故这里取 32 字节
/// 对 SHA-256 是等长、对 SHA-512 偏短但仍在建议区间之上）。
#[uniffi::export]
pub fn generate_secret_base32() -> Result<String, FfiError> {
    let mut bytes = [0_u8; 32];
    // `getrandom` 经核心传递引入，用同一份避免版本漂移（与核心对 `zeroize`
    // 的处理一致：需要用到传递依赖时从上游取，不另开直接依赖）。
    //
    // 映射到核心的 `RandomnessUnavailable` 而不是在这里自造错误：随机源
    // 属于核心的职责，错误分类也应由核心统一，FFI 层只做搬运。
    qualia2fa_core::getrandom::fill(&mut bytes).map_err(|_| FfiError::Core {
        detail: Error::RandomnessUnavailable.into(),
    })?;
    let secret = OtpSecret::from_bytes(bytes.to_vec())?;
    Ok(secret.to_base32())
}

/// 核心库版本，供端侧做兼容性检查与问题排查。
///
/// 注意这是 `qualia2fa-core` 的版本，不是本 FFI crate 的版本——端侧真正需要
/// 对齐的是核心的语义版本。
#[uniffi::export]
#[must_use]
pub fn core_version() -> String {
    qualia2fa_core::VERSION.to_owned()
}

// ═══════════════════════════════════════════════════════════════════════════
// M3：设备身份、注册与登录
// ═══════════════════════════════════════════════════════════════════════════
//
// # 本节的形状由「主密钥尽量不过边界」决定
//
// 主密钥是全部数据的钥匙，因此它在 FFI 边界上每出现一次都是一份可能残留的拷贝
// （托管语言的字符串/数组不受 Rust 的 `zeroize` 控制）。核心的 `flow` 模块因此
// 把平台依赖做成两个 trait 参数，让编排能在**主密钥不出 Rust** 的前提下完成。
//
// 本节沿用同一思路：
//
// - [`FfiVault`] 在 Rust 侧**持有**主密钥，条目操作与序列化都在 Rust 内完成。
//   端侧只拿到保险库文件字节与条目字段，拿不到主密钥。Open / AddEntry / Serialize
//   这一整条最常见的路径上，主密钥**一次都不过边界**。
// - 主密钥只在两处必须过边界，而这两处都是**不可避免**的：注册时交给平台密钥库
//   保管（[`FfiSecureStore`]），登录时从平台密钥库取出。它的永久归宿是端侧的
//   硬件密钥库，而那个存储只有端侧能访问——这不是设计选择，是平台的既成事实。
// - 因此[`FfiSecureStore`]的 trait 方法收发**字节**而不是某种句柄。把主密钥包成
//   不透明句柄看似更干净，但那只是把同一份字节从「显式参数」挪到「端侧自己存」，
//   边界上的拷贝一次都没少，反而让「密钥到底存在哪」变得不明确。
//
// 端侧的最小实现方式因此是：把这两个 trait 直接转发给平台的密钥库 API，
// **不要在其中加入判断**——任何判断都应当回到 Hassle 层，那里有测试。

/// 设备身份密钥对的来源：由端侧转发给平台硬件密钥库。
///
/// 对应核心的 [`qualia2fa_core::flow::DeviceKeys`]。端侧实现应当直接转发给
/// `qualia2fa-keystore` 等平台层，**不要在其中加入判断**。
///
/// # 实现方必须满足的契约
///
/// - **`getOrCreate` 对同一 `label` 必须是幂等的。** 每次调用都新建一对密钥，
///   会让用户在重启后打不开自己的数据——旧身份对应的条目再也解不开，而界面上
///   看不出任何异常。
/// - **密钥必须立即持久化**，不能攒到「会话结束」再写。签名调用可能来自另一次
///   进程启动。
/// - **`sign` 收到的是原始消息，不是摘要。** 端侧不得先做一次哈希——那会与
///   核心的验签路径（标准 ECDSA 哈希模式）叠加成「哈希两次」，症状是每次配对都
///   报 `DeviceSignatureInvalid`，而密钥与消息看上去都对。
#[uniffi::export(with_foreign)]
pub trait FfiDeviceKeys: Send + Sync {
    /// 取得该 `label` 的公钥（不存在则创建）。SEC1 未压缩编码，65 字节。
    fn get_or_create(&self, label: String) -> Result<Vec<u8>, FfiError>;

    /// 用该 `label` 的私钥对**原始消息**签名。返回 64 字节原始 `r‖s`（非 DER）。
    fn sign(&self, label: String, message: Vec<u8>) -> Result<Vec<u8>, FfiError>;
}

/// 主密钥的持久化位置：由端侧转发给平台硬件密钥库。
///
/// 对应核心的 [`qualia2fa_core::flow::SecureStore`]。
///
/// # `load` 返回 `None` 与返回 `Err` 是两件不同的事
///
/// - `Ok(None)`：这台设备**从未注册过**。界面应当引导用户去注册或登录。
/// - `Err(..)`：设备注册过，但密钥现在读不出来（硬件被重置、密钥被删除、
///   用户换了 Windows 账户）。界面应当**警告数据可能已丢失**，绝不能引导用户
///   重新注册——那会用一个新主密钥覆盖旧数据，让原有条目永久不可恢复。
///
/// 把这两种情况合并成一个 `None` 是本接口最容易犯的错，而上层界面无从分辨。
#[uniffi::export(with_foreign)]
pub trait FfiSecureStore: Send + Sync {
    /// 读取主密钥，32 字节。从未注册过时返回 `None`。
    fn load_master_key(&self) -> Result<Option<Vec<u8>>, FfiError>;

    /// 写入主密钥（32 字节），覆盖已有值。
    fn store_master_key(&self, key: Vec<u8>) -> Result<(), FfiError>;

    /// 删除主密钥。已取消注册的设备上调用不应报错。
    fn delete_master_key(&self) -> Result<(), FfiError>;

    /// 该存储是否受硬件保护（TPM / Secure Enclave / Android Keystore）。
    ///
    /// **必须如实上报。** 没有硬件时返回 `false`，由界面征得用户同意后再继续；
    /// 谎报会让用户以为自己受硬件保护，而私钥其实只是一个软件文件。
    fn is_hardware_backed(&self) -> bool;
}

/// 核心 `DeviceKeys` 的转发实现：把 trait 调用桥到端侧回调。
struct ForeignDeviceKeys(Arc<dyn FfiDeviceKeys>);

impl qualia2fa_core::flow::DeviceKeys for ForeignDeviceKeys {
    fn get_or_create(&mut self, label: &str) -> Result<DevicePublicKey, Error> {
        let bytes = self
            .0
            .get_or_create(label.to_owned())
            .map_err(ffi_to_core_error)?;
        DevicePublicKey::from_sec1_bytes(&bytes)
    }

    fn sign(&mut self, label: &str, message: &[u8]) -> Result<DeviceSignature, Error> {
        let bytes = self
            .0
            .sign(label.to_owned(), message.to_vec())
            .map_err(ffi_to_core_error)?;
        DeviceSignature::from_bytes(&bytes)
    }
}

/// 核心 `SecureStore` 的转发实现：把 trait 调用桥到端侧回调。
struct ForeignSecureStore(Arc<dyn FfiSecureStore>);

impl qualia2fa_core::flow::SecureStore for ForeignSecureStore {
    fn load_master_key(&self) -> Result<Option<MasterKey>, Error> {
        let bytes = self.0.load_master_key().map_err(ffi_to_core_error)?;
        bytes
            .map(|bytes| flow::master_key_from_bytes(bytes.into()))
            .transpose()
    }

    fn store_master_key(&mut self, key: &MasterKey) -> Result<(), Error> {
        self.0
            .store_master_key(flow::master_key_to_bytes(key).expose_secret().to_vec())
            .map_err(ffi_to_core_error)
    }

    fn delete_master_key(&mut self) -> Result<(), Error> {
        self.0.delete_master_key().map_err(ffi_to_core_error)
    }

    fn is_hardware_backed(&self) -> bool {
        self.0.is_hardware_backed()
    }
}

/// 把端侧回调返回的 [`FfiError`] 还原成核心错误。
///
/// # 为什么是「还原」而不是「翻译」
///
/// 回调里出现的错误绝大多数**本来就是核心错误**——端侧只是把它们原样传回来
/// （例如平台密钥库报「硬件不可用」，那对应核心的
/// [`Error::DeviceKeyMissing`]）。若在这里一律包成一个笼统的错误，核心拿到的
/// 失败原因就退化了，而 `flow` 的失败处理正是按原因分支的。
///
/// [`FfiError::Core`] 因此按 `kind` 反映射回核心变体。反映射做不到的（边界自身的
/// [`FfiError::InputTooLong`]、以及未来新增的 kind）退化为
/// [`Error::DeviceKeyMissing`]——那是一个「这台设备的密钥不可用」的诚实描述，
/// 而不会让调用方以为一切正常。
fn ffi_to_core_error(source: FfiError) -> Error {
    match source {
        FfiError::Core { detail } => kind_to_core_error(&detail.kind),
        FfiError::InputTooLong { .. } => Error::DeviceKeyMissing,
    }
}

/// 把稳定的错误标识反映射回核心错误变体。
///
/// **只覆盖设备身份相关的那些**：本函数只被跨回调的路径用到，而那几条路径上可能
/// 出现的核心错误是有限的（密钥不存在、身份不匹配、存储写入失败）。其余一律退化
/// 为 [`Error::DeviceKeyMissing`]，而不是硬凑一个语义不符的变体——错误分类错了比
/// 分类粗更糟。
fn kind_to_core_error(kind: &str) -> Error {
    match kind {
        "device_key_missing" => Error::DeviceKeyMissing,
        "device_signature_invalid" => Error::DeviceSignatureInvalid {
            reason: "端侧签名失败",
        },
        "secure_store_write_failed" => Error::SecureStoreWriteFailed {
            reason: "端侧密钥库拒绝写入",
        },
        _ => Error::DeviceKeyMissing,
    }
}

/// 一条 2FA 条目，跨 FFI 边界的表示。
///
/// 与 [`uri::OtpAuth`] 的关系：那个是 `otpauth://` URI 的解析结果，这个是保险库
/// 里存的东西。两者字段相近但**不等价**——保险库条目多了显示名、备注与时间戳，
/// 少了「URI 类型」（HOTP 由 `counter` 是否为 `None` 表达）。
///
/// # `id` 为什么是字符串
///
/// 核心的 [`EntryId`](qualia2fa_core::vault::EntryId) 是 16 字节，但端侧只会把
/// 它当成不透明的标识来传递与比较（列表项 key、删除时指认哪一条）。用十六进制
/// 字符串而不是 `Vec<u8>`：托管语言里字节数组的相等性/哈希语义常常是引用比较，
/// 而字符串是值语义，端侧不必为此写额外代码。
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiVaultEntry {
    /// 条目标识，32 位十六进制小写字符串。
    pub id: String,
    /// 显示名。
    pub name: String,
    /// 发行方（服务名）。
    pub issuer: Option<String>,
    /// 账号名。
    pub account: String,
    /// 种子，Base32 编码（大写）。见模块文档对种子表示的约定。
    pub secret_base32: String,
    /// 使用的哈希算法。
    pub algorithm: FfiAlgorithm,
    /// 验证码位数。
    pub digits: FfiDigits,
    /// 时间步长（秒）。HOTP 条目此值无意义。
    pub period: u64,
    /// HOTP 的计数器。TOTP 条目为 `None`。
    pub counter: Option<u64>,
    /// 用户备注。
    pub note: String,
    /// 创建时间（Unix 秒）。
    pub created_at: u64,
    /// 最后修改时间（Unix 秒）。
    pub updated_at: u64,
}

impl FfiVaultEntry {
    /// 把核心条目转成跨边界表示。
    fn from_core(id: &qualia2fa_core::vault::EntryId, entry: &Entry) -> Self {
        Self {
            id: id.to_string(),
            name: entry.name.clone(),
            issuer: entry.issuer.clone(),
            account: entry.account.clone(),
            secret_base32: entry.secret.to_base32(),
            algorithm: match entry.algorithm {
                Algorithm::Sha1 => FfiAlgorithm::Sha1,
                Algorithm::Sha256 => FfiAlgorithm::Sha256,
                Algorithm::Sha512 => FfiAlgorithm::Sha512,
            },
            digits: match entry.digits {
                Digits::Six => FfiDigits::Six,
                Digits::Seven => FfiDigits::Seven,
                Digits::Eight => FfiDigits::Eight,
            },
            period: entry.period,
            counter: entry.counter,
            note: entry.note.clone(),
            created_at: entry.created_at,
            updated_at: entry.updated_at,
        }
    }

    /// 构造核心条目。`now` 用于填充创建/修改时间。
    fn to_core(&self, now: u64) -> Result<Entry, FfiError> {
        check_len("secret", &self.secret_base32, MAX_SECRET_CHARS)?;
        check_len("name", &self.name, MAX_VAULT_FIELD_CHARS)?;
        check_len("account", &self.account, MAX_VAULT_FIELD_CHARS)?;
        check_len("note", &self.note, MAX_VAULT_FIELD_CHARS)?;
        if let Some(issuer) = &self.issuer {
            check_len("issuer", issuer, MAX_VAULT_FIELD_CHARS)?;
        }
        let secret = OtpSecret::from_base32(&self.secret_base32)?;
        Ok(Entry::new(
            self.name.clone(),
            self.issuer.clone(),
            self.account.clone(),
            secret,
            self.algorithm.into(),
            self.digits.into(),
            self.period,
            self.counter,
            self.note.clone(),
            now,
            now,
        )?)
    }

    /// 解析 16 字节的十六进制标识。
    fn parse_id(&self) -> Result<qualia2fa_core::vault::EntryId, FfiError> {
        parse_entry_id(&self.id)
    }
}

/// 解析 `EntryId` 的十六进制表示（32 个小写十六进制字符）。
fn parse_entry_id(text: &str) -> Result<qualia2fa_core::vault::EntryId, FfiError> {
    check_len("entry_id", text, 32)?;
    let bytes = text.as_bytes();
    // 长度先判：下面的按 2 分组假设了偶数长度，而奇数长度会让最后一组只有一个
    // 字符——那是「截断的 ID」在界面上的表现，必须报错而不是补零。
    if bytes.len() != 32 {
        return Err(FfiError::Core {
            detail: Error::UriInvalidParameter {
                name: "entry_id".to_owned(),
                reason: "必须是 32 个十六进制字符".to_owned(),
            }
            .into(),
        });
    }
    let mut id = [0_u8; 16];
    for (index, slot) in id.iter_mut().enumerate() {
        let hi = hex_digit(bytes[index * 2])?;
        let lo = hex_digit(bytes[index * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(qualia2fa_core::vault::EntryId::from_bytes(id))
}

/// 单个十六进制字符 → 数值。
fn hex_digit(byte: u8) -> Result<u8, FfiError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(FfiError::Core {
            detail: Error::UriInvalidParameter {
                name: "entry_id".to_owned(),
                reason: "含非十六进制字符".to_owned(),
            }
            .into(),
        }),
    }
}

/// 一个已解锁的保险库。
///
/// # 主密钥不过边界
///
/// 本对象在 Rust 侧**持有**主密钥，条目操作与序列化都在 Rust 内完成。因此
/// 「打开保险库 → 读条目 → 写条目 → 存回文件」这条最常见的路径上，主密钥一次都
/// 不会以字节形式出现在 Kotlin/Swift 里。这是本对象存在的主要理由——如果端侧
/// 自己拿着主密钥，每一次列表刷新都要把它传进来一次。
///
/// # 端侧的生命周期
///
/// 端侧应当在用户解锁应用时构造本对象，在应用进入后台或用户锁定应用时**丢弃**它
/// （`null` 掉引用）。对象被 GC 时 Rust 侧的 `Drop` 会擦除主密钥；但那取决于 GC
/// 时机，因此**不要**依赖 GC 来锁屏——「锁屏」必须是真的丢掉引用，并让界面重新
/// 要求解锁。
#[derive(uniffi::Object)]
pub struct FfiVault {
    /// 核心的保险库状态，含主密钥。
    ///
    /// # 为什么是 `Mutex` 而不是直接放 `VaultFile`
    ///
    /// UniFFI 导出 `&mut self` 方法时要求对象以 `Arc<Self>` 共享，而 `Arc` 不给
    /// 可变借用——所以内部状态需要一个提供内部可变性的容器。`Mutex` 而不是
    /// `RefCell`：`Mutex` 是 `Send + Sync`，而 `RefCell` 不是，UniFFI 的
    /// `#[Object]` 要求 `Send + Sync`。
    ///
    /// **锁的粒度是「一次方法调用」**，锁内只有内存操作（哈希表增删、条目字段
    /// 拷贝）。加密与 Argon2 都在锁外：一次导出的 Argon2 要跑几百毫秒，若在锁内，
    /// 并发的界面刷新会卡住。
    ///
    /// 中毒（poison）用 `unwrap_or_else` 吞掉：本锁保护的是数据结构，而方法内部
    /// 没有会 panic 的代码。真要有 panic，恢复数据比让整个应用后续每次调用都失败
    /// 更可取——后者会让用户彻底无法读写自己的条目。
    inner: std::sync::Mutex<VaultFile>,
}

impl FfiVault {
    /// 从核心保险库构造。
    fn wrap(inner: VaultFile) -> Arc<Self> {
        Arc::new(Self {
            inner: std::sync::Mutex::new(inner),
        })
    }
}

#[uniffi::export]
impl FfiVault {
    /// 用一份已有的主密钥建立一个空保险库。
    ///
    /// 供两条路径使用：
    ///
    /// - [`FfiJoiner::complete`] 之后：已经拿到主密钥、也已经写进平台存储，现在要
    ///   一个能操作的保险库对象。
    /// - [`import_recovery_key`] 之后：同上。
    ///
    /// # 「空」是正常的
    ///
    /// D5 之下主密钥与条目是**分开传**的：登录只带来钥匙，不带来内容。端侧拿到的
    /// 第一个保险库必然是空的，条目要靠同步（M4）或本地文件取回。不要因为它空就
    /// 以为登录失败。
    ///
    /// # 主密钥仍然不过边界（除了这一次）
    ///
    /// 参数是 32 字节明文——这是端侧手里已经有主密钥的场景，绕不开。但本函数之后，
    /// 端侧可以把那 32 字节丢掉，后续一切都通过本对象进行。
    ///
    /// # 错误
    ///
    /// 长度不是 32 字节时返回 [`Error::MasterKeyWrongLength`]。
    #[uniffi::constructor]
    pub fn from_master_key(master_key: Vec<u8>) -> Result<Arc<Self>, FfiError> {
        let master = flow::master_key_from_bytes(master_key.into())?;
        Ok(Self::wrap(flow::empty_vault(master)))
    }

    /// 注册一台新设备：生成主密钥、取得设备身份、并把主密钥交给平台密钥库。
    ///
    /// # 这一步会做什么、不会做什么
    ///
    /// **会**：生成主密钥 → 取得设备身份 → 把主密钥写入 [`FfiSecureStore`]。
    /// **不会**创建保险库文件，也不会写磁盘。返回的是一个空的 [`FfiVault`]，
    /// 端侧往里面加完第一批条目后调用 [`FfiVault::serialize`] 落盘。
    ///
    /// 之所以不让这一步自己写文件：「先写一个空保险库、写完条目再写一次」会让最终
    /// 内容取决于哪一次成功，而端侧无从判断。一次写完，内容就是确定的。
    ///
    /// # 错误
    ///
    /// 设备身份创建失败、主密钥写入失败时返回相应错误，**此时磁盘上不会留下任何
    /// 东西**（本函数不写文件）。平台密钥库可能不可用，端侧应当把它当作一个需要
    /// 告知用户的状态，而不是重试。
    #[uniffi::constructor]
    pub fn register(
        keys: Arc<dyn FfiDeviceKeys>,
        store: Arc<dyn FfiSecureStore>,
        label: String,
    ) -> Result<Arc<Self>, FfiError> {
        check_len("label", &label, MAX_LABEL_CHARS)?;
        let mut keys = ForeignDeviceKeys(keys);
        let mut store = ForeignSecureStore(store);
        let registered = flow::registration(&mut keys, &mut store, &label)?;
        Ok(Self::wrap(registered.into_vault()))
    }

    /// 用平台密钥库里的主密钥打开保险库文件。
    ///
    /// # 错误
    ///
    /// 设备从未注册过时返回 [`Error::DeviceNotRegistered`]（`kind` 为
    /// `device_not_registered`）；主密钥存在但文件解不开时返回
    /// [`Error::VaultDecryptionFailed`]（`kind` 为 `vault_decryption_failed`）。
    /// 端侧必须区分这两者——前者引导用户去注册/登录，后者要警告数据可能已损坏或
    /// 主密钥被换过。合并处理会让用户在被引导重新注册时永久失去原有条目。
    ///
    /// # 已知限制：空保险库判定不了主密钥对错
    ///
    /// 主密钥只参与每条记录的 AEAD，文件头里没有它的校验值。因此一个**条目为空**
    /// 的文件对任何 32 字节主密钥都能打开。端侧不要把「打开成功」当成「密钥正确」；
    /// 需要确认时用 [`FfiVerifier`] 的挑战-应答。
    #[uniffi::constructor]
    pub fn open(store: Arc<dyn FfiSecureStore>, data: Vec<u8>) -> Result<Arc<Self>, FfiError> {
        let store = ForeignSecureStore(store);
        let file = flow::open_vault(&store, &data)?;
        Ok(Self::wrap(file))
    }

    /// 条目数量。
    #[must_use]
    pub fn entry_count(&self) -> u64 {
        self.lock().vault().len() as u64
    }

    /// 是否没有任何条目。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().vault().is_empty()
    }

    /// 墓碑数量。
    ///
    /// 墓碑是「这条被删了」的记录，用于让删除在设备间同步。界面通常不需要显示它，
    /// 但排错时有用。
    #[must_use]
    pub fn tombstone_count(&self) -> u64 {
        self.lock().vault().tombstone_count() as u64
    }

    /// 当前的全部条目。
    ///
    /// # 顺序
    ///
    /// 返回顺序**不保证**，因为核心内部用哈希表索引。端侧要显示列表就必须自己
    /// 排序（按名称、按创建时间等），不要依赖这个顺序稳定——依赖它会让列表在
    /// 两次刷新之间跳来跳去。
    #[must_use]
    pub fn entries(&self) -> Vec<FfiVaultEntry> {
        self.lock()
            .vault()
            .iter()
            .map(|(id, entry)| FfiVaultEntry::from_core(id, entry))
            .collect()
    }

    /// 按标识取一条条目。不存在时返回 `None`。
    #[must_use]
    pub fn entry(&self, id: String) -> Option<FfiVaultEntry> {
        let id = parse_entry_id(&id).ok()?;
        self.lock()
            .vault()
            .get(&id)
            .map(|entry| FfiVaultEntry::from_core(&id, entry))
    }

    /// 新增一条条目，返回它的标识。
    ///
    /// `now` 是 Unix 秒，**由端侧提供**——核心不读时钟。
    pub fn add_entry(&self, entry: FfiVaultEntry, now: u64) -> Result<String, FfiError> {
        flow::check_now(now)?;
        let core = entry.to_core(now)?;
        let id = self.lock().vault_mut().insert(core)?;
        Ok(id.to_string())
    }

    /// 修改一条已有条目。
    ///
    /// 找不到该标识时返回 [`Error::VaultEntryNotFound`]（`kind` 为
    /// `vault_entry_not_found`）。
    ///
    /// # 为什么不用「先删后加」
    ///
    /// 先删后加会换掉条目标识，而标识是设备间谈论「同一条条目」的唯一依据：换标识
    /// 会被同步当成「删了一条、又加了一条」，另一台设备上该条目的历史与墓碑全部
    /// 错位。修改必须**保持标识**。
    ///
    /// 因此这里的做法是取出旧条目、替换内容、用**同一个**标识放回去。创建时间也
    /// 保留：它记录的是「用户什么时候加进来的」，改一次名字就变掉会让界面上的排序
    /// 跳位。
    pub fn update_entry(&self, entry: FfiVaultEntry, now: u64) -> Result<(), FfiError> {
        flow::check_now(now)?;
        let id = entry.parse_id()?;
        let mut core = entry.to_core(now)?;
        // `mut` 是必须的：`MutexGuard` 的可变访问来自它的 `DerefMut`，而那需要
        // guard 本身可变。
        let mut vault = self.lock();
        // 先取出旧条目：既为了确认它存在，也为了保住它的创建时间。
        let created_at = vault
            .vault()
            .get(&id)
            .ok_or(Error::VaultEntryNotFound)?
            .created_at;
        core.created_at = created_at;
        // `Vault::replace` 而不是「remove + insert_with_id」：后者会**留下墓碑**，
        // 而一次改名不是删除。墓碑会被同步出去，另一端可能据此把条目真的删掉。
        vault.vault_mut().replace(id, core)?;
        Ok(())
    }

    /// 删除一条条目，留下墓碑。
    ///
    /// 返回是否删掉了一条（`false` 表示该标识本来就不存在）。
    ///
    /// # 墓碑是删除的正确形式
    ///
    /// 直接抹掉记录会让另一台设备在下次同步时把这条**重新带回来**——它不知道这边
    /// 删过。墓碑就是「这条被删了」这件事本身，它要跟着条目一起同步。
    pub fn remove_entry(&self, id: String, now: u64) -> Result<bool, FfiError> {
        flow::check_now(now)?;
        let id = parse_entry_id(&id)?;
        Ok(self.lock().vault_mut().remove(&id, now).is_some())
    }

    /// 序列化成保险库文件字节，供端侧落盘。
    ///
    /// 端侧应当**原子地**写文件（先写临时文件再改名），不要就地覆盖：写到一半
    /// 断电会留下一个解不开的文件，而用户唯一的一份数据就在里面。核心提供了
    /// `vault::write_file_atomically`，但它做 I/O，不在本库的暴露范围内，端侧需
    /// 自行实现等价语义。
    pub fn serialize(&self) -> Result<Vec<u8>, FfiError> {
        Ok(self.lock().serialize()?)
    }

    /// 计算某条条目当前的验证码。
    ///
    /// `unix_time` 由端侧提供（核心不读时钟）。HOTP 条目用 [`FfiVault::hotp_for`]。
    pub fn totp_for(&self, id: String, unix_time: u64) -> Result<String, FfiError> {
        self.code_for(&id, |entry| {
            otp::totp_code(
                &entry.secret,
                unix_time,
                entry.period,
                entry.algorithm,
                entry.digits,
            )
        })
    }

    /// 计算某条 HOTP 条目在指定计数器上的验证码。
    pub fn hotp_for(&self, id: String, counter: u64) -> Result<String, FfiError> {
        self.code_for(&id, |entry| {
            Ok(otp::hotp_code(
                &entry.secret,
                counter,
                entry.algorithm,
                entry.digits,
            ))
        })
    }

    /// 计算某条条目的 Steam Guard 验证码（5 位，自定义字母表）。
    pub fn steam_guard_for(&self, id: String, unix_time: u64) -> Result<String, FfiError> {
        self.code_for(&id, |entry| {
            otp::steam_guard_code(&entry.secret, unix_time, entry.period, entry.algorithm)
        })
    }

    /// 用口令导出一份恢复密钥文件。
    ///
    /// # KDF 参数
    ///
    /// `memory_kib` / `iterations` / `parallelism` 传 `None` 则用核心的推荐值
    /// （64 MiB / 3 次 / 1 路）。**端侧不要为了「快」而调低它们**：导出时的耗时是
    /// 一次性的，而攻击者拿到文件后是离线暴力破解，参数调低直接削弱用户的最后一道
    /// 防线。
    ///
    /// # 错误
    ///
    /// 参数超出核心允许的范围（内存上限 1 GiB、迭代上限 1000）时返回
    /// [`Error::RecoveryParametersInvalid`]（`kind` 为 `recovery_parameters_invalid`）。
    /// **上下界都要校验**，因为参数既可能来自端侧的滑块，也可能来自**别人的**文件。
    ///
    /// # 返回值的处置
    ///
    /// 调用方拿到的是**加了密的**文件字节，不是主密钥。端侧应当只把它写到用户选的
    /// 位置或显示成二维码让用户抄下来，不要留在剪贴板历史里。口令本身不过本函数的
    /// 返回值，端侧也不得持久化它。
    pub fn export_recovery_key(
        &self,
        passphrase: String,
        memory_kib: Option<u64>,
        iterations: Option<u64>,
        parallelism: Option<u64>,
    ) -> Result<Vec<u8>, FfiError> {
        check_len("passphrase", &passphrase, MAX_PASSPHRASE_CHARS)?;
        let params = kdf_params(memory_kib, iterations, parallelism)?;
        // 主密钥**不经过 `Vec<u8>`**：这里直接从锁内借出密钥引用，交给核心完成
        // 派生与加密。把它先拷成字节再传，等于在 FFI 边界上凭空多一份明文拷贝。
        let vault = self.lock();
        Ok(flow::export_recovery_key(
            vault.master_key(),
            &SecretString::from(passphrase),
            Some(params),
        )?)
    }
}

impl FfiVault {
    /// 取得锁，忽略中毒。
    ///
    /// 中毒意味着某个持有锁的线程 panic 过。此时数据结构的**不变量**仍然成立
    /// （本锁保护的是哈希表增删，没有「改了前半段就 panic」的中间状态），因此恢复
    /// 使用比让后续每次调用都失败更好——后者会让用户彻底无法读写自己的条目。
    fn lock(&self) -> std::sync::MutexGuard<'_, VaultFile> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// 取出条目的三个计算字段。
    ///
    /// 不返回 `&Entry`：条目住在 `MutexGuard` 后面，而 guard 在函数返回时就释放了，
    /// 借用无法逃出去。核心的 `OtpSecret` 刻意不实现 `Clone`（那会让「秘密被静默
    /// 复制」变成随手可做），因此这里**把验证码算完再返回字符串**，而不是把条目
    /// 或种子拷贝出来——拷贝路径越短，明文在内存里停留的地方越少。
    fn code_for(
        &self,
        id: &str,
        compute: impl FnOnce(&Entry) -> Result<String, Error>,
    ) -> Result<String, FfiError> {
        let id = parse_entry_id(id)?;
        let vault = self.lock();
        let entry = vault.vault().get(&id).ok_or(Error::VaultEntryNotFound)?;
        Ok(compute(entry)?)
    }
}

/// 用 [`FfiVault`] 手里的主密钥打开保险库。
///
/// # 返回的是一条字节串，而不是一个可打印的短码
///
/// 恢复密钥文件被设计成「用户可以抄在纸上、也可以放进二维码」。它**不是**主密钥：
/// 里面的主密钥由用户口令经 Argon2id 派生的密钥加密（见核心 `recovery` 模块）。
/// 因此这里返回 `Vec<u8>` 是安全的，但端侧仍然不该把它写进日志或剪贴板历史。
///
/// # 与 [`FfiVault::export_recovery_key`] 的关系
///
/// 两者做同一件事，区别只在主密钥从哪来：
///
/// - [`FfiVault::export_recovery_key`]：设备**已经解锁**，主密钥在 Rust 侧。
///   首选这条——主密钥一次都不过边界。
/// - 本函数：调用方手里只有主密钥字节（例如刚刚通过 [`FfiJoiner::complete`] 拿到，
///   还没来得及建保险库）。主密钥在这里过一次边界，是这条路径的固有代价。
#[uniffi::export]
pub fn export_recovery_key_from_master(
    master_key: Vec<u8>,
    passphrase: String,
    memory_kib: Option<u64>,
    iterations: Option<u64>,
    parallelism: Option<u64>,
) -> Result<Vec<u8>, FfiError> {
    check_len("passphrase", &passphrase, MAX_PASSPHRASE_CHARS)?;
    let params = kdf_params(memory_kib, iterations, parallelism)?;
    let master = flow::master_key_from_bytes(master_key.into())?;
    Ok(flow::export_recovery_key(
        &master,
        &SecretString::from(passphrase),
        Some(params),
    )?)
}

/// 用口令从恢复密钥文件里取回主密钥，并**写入平台密钥库**。
///
/// 返回主密钥的 32 字节。端侧把它交给 [`FfiSecureStore::store_master_key`]，或者
/// 直接丢掉——本函数已经在内部写过一次存储了。
///
/// # 为什么返回值与内部写入都有
///
/// 内部写入是为了让「恢复」与「登录」在存储这一步上行为一致（都走核心的
/// `SecureStore` 抽象，因此顺序保证相同）。返回值是为了让端侧能立刻构造一个
/// [`FfiVault`] 而不必再从密钥库读一次——读一次就多一次硬件访问，而有的平台每次
/// 访问都会弹生物识别提示。
///
/// # 错误
///
/// 口令错误返回 [`Error::RecoveryAuthenticationFailed`]（`kind` 为
/// `recovery_authentication_failed`）；文件结构不对返回
/// [`Error::RecoveryFileMalformed`]；参数超出范围返回
/// [`Error::RecoveryParametersInvalid`]。
///
/// **口令错误与文件损坏必须区分**：前者提示用户重新输入，后者要提示文件不可用。
/// 合并成一条「恢复失败」会让用户反复试口令，而问题根本不在口令上。
#[uniffi::export]
pub fn import_recovery_key(
    file: Vec<u8>,
    passphrase: String,
    store: Arc<dyn FfiSecureStore>,
) -> Result<Vec<u8>, FfiError> {
    check_len("passphrase", &passphrase, MAX_PASSPHRASE_CHARS)?;
    let mut store = ForeignSecureStore(store);
    let master = flow::import_recovery_key(&file, &SecretString::from(passphrase), &mut store)?;
    Ok(flow::master_key_to_bytes(&master).expose_secret().to_vec())
}

/// 把一份主密钥写入平台密钥库。
///
/// 供端侧在 [`FfiJoiner::complete`] 之后使用：那条路径返回主密钥字节，由端侧决定
/// 何时落库。单独提供这一步而不是让 `complete` 自己写，是因为「登录完成」与
/// 「保存密钥」在界面上是两个动作——用户可能在保存前就被要求确认设备名称。
///
/// # 错误
///
/// 密钥长度不是 32 字节时返回 [`Error::MasterKeyWrongLength`]。
#[uniffi::export]
pub fn store_master_key(
    master_key: Vec<u8>,
    store: Arc<dyn FfiSecureStore>,
) -> Result<(), FfiError> {
    let master = flow::master_key_from_bytes(master_key.into())?;
    let mut store = ForeignSecureStore(store);
    store.store_master_key(&master)?;
    Ok(())
}

// ── 登录：发起方与加入方 ─────────────────────────────────────────────────

/// 登录的发起方：一台**已经登录**、持有主密钥的设备。
///
/// 它负责显示二维码、接收请求、把主密钥加密交给对方。
///
/// # 一次登录只服务一个请求
///
/// 核心把这个性质做成了**类型强制的**（`authorize` 消费掉待处理的会话），因此
/// 重复调用第二次必然失败，不需要端侧维护标志位。端侧要做的只是：一个二维码对应
/// 一个 [`FfiLogin`] 实例，授权成功后把它丢掉。
///
/// # 跨重启的重放防护
///
/// 核心的 `Login` 能做的是「同一进程内一次」。要让重放防护跨应用重启存活，需要把
/// 用过的会话标识持久化、并在下次登录时恢复。**本层没有暴露这条路径**：核心的
/// `NonceLog` 没有序列化入口，因此跨重启这一层暂时不可达（详见 TODO.md）。
///
/// 就当前协议而言这不构成缺口——待处理的会话本身也不跨重启存活（它含一次性的临时
/// 私钥，端侧不可能把它写到磁盘上），因此没有东西可以被重放。真正需要它的是 M4 的
/// 局域网同步：那时才会有跨会话、跨重启都要拒绝的重放。
#[derive(uniffi::Object)]
pub struct FfiLogin {
    /// 核心的发起方状态。
    inner: std::sync::Mutex<Login>,
}

#[uniffi::export]
impl FfiLogin {
    /// 发起一次登录，返回要显示成二维码的文本。
    #[uniffi::constructor]
    pub fn begin() -> Result<Arc<Self>, FfiError> {
        Ok(Arc::new(Self {
            inner: std::sync::Mutex::new(Login::new()?),
        }))
    }

    /// 要显示成二维码的文本。
    ///
    /// 这是**唯一**需要展示给对方的信道。它不含主密钥（见核心 `pairing` 的模块
    /// 文档），但它是这次会话的凭据，因此不要把它发到聊天记录或截图分享——那等于
    /// 把登录机会交给看到它的人。
    pub fn payload(&self) -> String {
        self.lock().payload().to_base32()
    }

    /// 接受对方扫到二维码后发来的请求，返回要发回去的应答字节。
    ///
    /// # 授权就是「用户确认」
    ///
    /// 本函数一被调用，主密钥就被加密交给对方了。因此端侧**必须**在调用前让用户
    /// 确认（例如显示「有一台新设备请求登录，是你本人操作吗？」）。核心无法替端侧
    /// 做这个决定，也不该做。
    ///
    /// # 错误
    ///
    /// 请求不是本次会话发出的、密文被改过、或本次登录已经授权过，一律返回
    /// [`Error::PairingAuthenticationFailed`]。**原因刻意不细分**，免得给攻击者一个
    /// 区分「差一点就成功」的预言机；端侧的文案也应当保持笼统（「配对失败，请重新
    /// 扫码」而不是「密钥错误」）。
    pub fn authorize(&self, vault: Arc<FfiVault>, msg1: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        // 主密钥从 `FfiVault` 里借出来，**不经过端侧**。这是 `authorize` 收一个
        // vault 而不是一串字节的原因。
        let vault = vault.lock();
        let mut login = self.lock();
        Ok(login.authorize(&msg1, vault.master_key())?)
    }

    /// 请求方声明的设备标识（授权成功后才有值）。
    pub fn joiner_device_id(&self) -> Option<String> {
        self.lock().joiner_device().map(|id| id.to_hex())
    }
}

impl FfiLogin {
    /// 取得锁，忽略中毒（理由见 [`FfiVault::lock`]）。
    fn lock(&self) -> std::sync::MutexGuard<'_, Login> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// 登录的加入方：一台还没有主密钥的新设备。
///
/// # 生命周期是「扫码 → 发请求 → 收应答 → 完成」
///
/// 请求必须由**同一个**对象发出与完成：会话标识由这次的临时密钥决定，换一个对象
/// 就等于换一次会话，应答必然解不开。核心用类型表达了这一点（`request` 借 `&self`
/// 而不是消费它，`complete` 才消费），因此端侧只要不重建对象就自然正确。
#[derive(uniffi::Object)]
pub struct FfiJoiner {
    /// 核心的加入方状态。
    inner: std::sync::Mutex<Joiner>,
}

#[uniffi::export]
impl FfiJoiner {
    /// 用扫到的二维码文本建立会话。`label` 是本机设备身份在平台密钥库里的标签。
    ///
    /// # 错误
    ///
    /// 文本不是合法的二维码载荷时返回 [`Error::PairingPayloadMalformed`]。
    /// 注意「不是合法载荷」与「载荷合法但会话对不上」是两回事，后者要到
    /// [`FfiJoiner::complete`] 才会暴露。
    ///
    /// # 为什么这里不顺手发请求
    ///
    /// 核心的 `new` 与 `request` 是分开的两步，本层保持同样的粒度：发出请求需要
    /// 设备身份，而取得身份在有的平台上会弹生物识别提示。端侧可能希望先向用户说明
    /// 「接下来要创建本机密钥」再触发它。合并成一步会让那个提示来得毫无预兆。
    #[uniffi::constructor]
    pub fn from_qr(text: String, label: String) -> Result<Arc<Self>, FfiError> {
        check_len("qr", &text, MAX_QR_TEXT_CHARS)?;
        check_len("label", &label, MAX_LABEL_CHARS)?;
        Ok(Arc::new(Self {
            inner: std::sync::Mutex::new(Joiner::from_base32(&text, &label)?),
        }))
    }

    /// 要发给发起方的请求字节。**幂等**：重复调用返回同一条消息，不会重新签名。
    ///
    /// 重新签名会生成新的会话标识，让发起方认不出这是同一次登录——因此幂等不是
    /// 优化，是正确性要求。
    pub fn request(&self, keys: Arc<dyn FfiDeviceKeys>) -> Result<Vec<u8>, FfiError> {
        let mut keys = ForeignDeviceKeys(keys);
        let mut joiner = self.lock();
        Ok(joiner.request(&mut keys)?)
    }

    /// 本机在这次会话里声明的设备身份（SEC1 未压缩编码，65 字节）。
    ///
    /// 发起方应当拿它与 [`FfiLogin::joiner_device_id`] 一起显示给用户确认——用户
    /// 要能看出「请求登录的是不是我想的那台设备」。完成之后返回 `None`。
    #[must_use]
    pub fn identity(&self) -> Option<Vec<u8>> {
        self.lock().identity().map(|bytes| bytes.to_vec())
    }

    /// 用发起方的应答完成登录：验证应答、取出主密钥、**并写入平台密钥库**。
    ///
    /// 返回主密钥的 32 字节，供端侧立刻构造 [`FfiVault`]（用
    /// [`FfiVault::from_master_key`]）而不必再从密钥库读一次——多读一次就是多一次
    /// 硬件访问，而有的平台每次访问都会弹生物识别提示。
    ///
    /// # 这一步才真正验证应答
    ///
    /// 应答的解密与认证发生在这里，而不是在 [`FfiJoiner::from_qr`]。因此「登录
    /// 失败」的唯一可信位置是本函数——端侧不要因为在扫码阶段没报错就认为一切正常。
    ///
    /// # 只能用一次
    ///
    /// 核心的会话是一次性的（`complete` 内部 `take` 掉），因此第二次调用返回
    /// [`Error::PairingAuthenticationFailed`]，而**不是**与伪造应答不同的错误。
    /// 这是刻意的：单独报「已经用过了」等于告诉攻击者他的重放被认出来了。
    ///
    /// # 错误
    ///
    /// 应答来自另一次会话、密文被改过、发起方用了别的主密钥、或本次登录已经完成过，
    /// 都返回 [`Error::PairingAuthenticationFailed`]。主密钥写入平台存储失败时返回
    /// [`Error::SecureStoreWriteFailed`]——此时**主密钥不会留在任何地方**，端侧应当
    /// 让用户重新走一次登录。
    pub fn complete(
        &self,
        msg2: Vec<u8>,
        keys: Arc<dyn FfiDeviceKeys>,
        store: Arc<dyn FfiSecureStore>,
    ) -> Result<Vec<u8>, FfiError> {
        let mut keys = ForeignDeviceKeys(keys);
        let mut store = ForeignSecureStore(store);
        let master = self.lock().complete(&msg2, &mut keys, &mut store)?;
        Ok(flow::master_key_to_bytes(&master).expose_secret().to_vec())
    }
}

impl FfiJoiner {
    /// 取得锁，忽略中毒（理由见 [`FfiVault::lock`]）。
    fn lock(&self) -> std::sync::MutexGuard<'_, Joiner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

// ── 挑战-应答：证明持有主密钥（D3） ──────────────────────────────────────
//
// 这一节有**两条消息**，方向与我们平时说的「请求/应答」相反：
//
// 1. 验证方 → 应答方：挑战（`FfiVerifier::challenge` → `FfiResponder::accept`）
// 2. 应答方 → 验证方：应答（`FfiResponder::respond` → `FfiVerifier::verify`）
// 3. 验证方 → 应答方：确认标签（`FfiVerifier::session_id`/`confirmation` →
//    `FfiResponder::confirm`）
//
// 第三步容易被漏掉，而它是**反过来**的证明：应答方据此确认「回话的确实是刚才那个
// 验证方」。只做前两步时，任何人都可以先发一个挑战再假装自己验证通过了。

/// 验证方：要确认对方手里确实有主密钥。
///
/// # 它用在什么场景
///
/// 1. **确认解锁成功**。空保险库判定不了主密钥对错（见 [`FfiVault::open`] 的说明），
///    而挑战-应答直接证明「对方算得出用主密钥派生的标签」。
/// 2. **跨设备的身份确认**（后续里程碑）。
///
/// # 与配对的区别
///
/// 配对是「把主密钥交给对方」；挑战-应答是「证明我手里有主密钥，但不交出去」。
/// 前者只在登录时发生一次，后者可以随时发生。**不要把挑战-应答当成登录**：它不
/// 传输任何密钥。
#[derive(uniffi::Object)]
pub struct FfiVerifier {
    /// 核心的验证方状态。`verify` 消费它，因此是 `Option`。
    inner: std::sync::Mutex<Option<auth::Verifier>>,
    /// 第一步要发出去的挑战字节。
    challenge: Vec<u8>,
    /// 第二步之后算出来的会话标识，第三步要回传给对方。
    session_id: std::sync::Mutex<Option<[u8; AUTH_SESSION_ID_LEN]>>,
    /// 第二步之后算出来的确认标签，第三步要回传给对方。
    confirmation: std::sync::Mutex<Option<[u8; AUTH_CONFIRM_LEN]>>,
}

#[uniffi::export]
impl FfiVerifier {
    /// 发起一次挑战。
    #[uniffi::constructor]
    pub fn begin() -> Result<Arc<Self>, FfiError> {
        let (challenge, verifier) = auth::begin()?;
        Ok(Arc::new(Self {
            inner: std::sync::Mutex::new(Some(verifier)),
            challenge,
            session_id: std::sync::Mutex::new(None),
            confirmation: std::sync::Mutex::new(None),
        }))
    }

    /// 要发给对方的挑战字节。
    #[must_use]
    pub fn challenge(&self) -> Vec<u8> {
        self.challenge.clone()
    }

    /// 校验对方的应答，成功返回 `true`。
    ///
    /// 失败返回 [`Error::AuthProofFailed`]（`kind` 为 `auth_proof_failed`），**不要**
    /// 把它当成「主密钥错了」以外的意思：这个错误只在标签对不上时产生。
    ///
    /// # 只能用一次
    ///
    /// 挑战是一次性的（核心的 `verify` 消费 `self`）。重复校验返回
    /// [`Error::AuthProofFailed`]——与「应答是伪造的」同一个错误，理由同
    /// [`FfiJoiner::complete`]：不给重放者一个区分信号。
    ///
    /// # 成功之后还要做第三步
    ///
    /// 拿到 `true` 之后，端侧必须把 [`FfiVerifier::session_id`] 与
    /// [`FfiVerifier::confirmation`] 回传给对方，由对方调 [`FfiResponder::confirm`]
    /// 校验。**漏掉第三步等于只做了一半认证**：应答方无从确认回话的是不是真的验证方。
    pub fn verify(&self, response: Vec<u8>, vault: Arc<FfiVault>) -> Result<bool, FfiError> {
        let verifier = {
            let mut guard = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.take().ok_or(Error::AuthProofFailed)?
        };
        let vault = vault.lock();
        let verified = verifier.verify(&response, vault.master_key())?;
        *self
            .session_id
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(*verified.session_id());
        *self
            .confirmation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(verified.confirmation());
        Ok(true)
    }

    /// 第三步要回传给对方的会话标识。校验成功之前为 `None`。
    #[must_use]
    pub fn session_id(&self) -> Option<Vec<u8>> {
        self.session_id
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .map(|id| id.to_vec())
    }

    /// 第三步要回传给对方的确认标签。校验成功之前为 `None`。
    #[must_use]
    pub fn confirmation(&self) -> Option<Vec<u8>> {
        self.confirmation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .map(|tag| tag.to_vec())
    }
}

/// 应答方：手里有主密钥，要向验证方证明这一点。
#[derive(uniffi::Object)]
pub struct FfiResponder {
    /// 核心的应答方状态。
    inner: std::sync::Mutex<auth::Responder>,
}

#[uniffi::export]
impl FfiResponder {
    /// 接受对方发来的挑战。
    ///
    /// # 错误
    ///
    /// 挑战格式不对（长度、版本、临时公钥不在曲线上）时返回
    /// [`Error::AuthMessageMalformed`]。
    #[uniffi::constructor]
    pub fn accept(challenge: Vec<u8>) -> Result<Arc<Self>, FfiError> {
        Ok(Arc::new(Self {
            inner: std::sync::Mutex::new(auth::accept(&challenge)?),
        }))
    }

    /// 本机在这次会话里的设备身份（SEC1 未压缩编码，65 字节）。
    #[must_use]
    pub fn identity(&self) -> Vec<u8> {
        self.lock().public_key().to_vec()
    }

    /// 生成应答，交给验证方。
    ///
    /// 签名走 [`FfiDeviceKeys::sign`]，**传进去的是原始消息**；端侧实现不得先做
    /// 哈希（那样会与核心的验签路径叠加成「哈希两次」，每次校验都失败）。
    pub fn respond(
        &self,
        vault: Arc<FfiVault>,
        label: String,
        keys: Arc<dyn FfiDeviceKeys>,
    ) -> Result<Vec<u8>, FfiError> {
        check_len("label", &label, MAX_LABEL_CHARS)?;
        let vault = vault.lock();
        let responder = self.lock();
        let mut keys = ForeignDeviceKeys(keys);
        let device = keys.get_or_create(&label)?;
        // 注意签名回调收的是**原始消息**：核心的验签路径用标准 ECDSA 哈希模式，
        // 若这里先哈希再签，验签方会再哈希一次，结果是每次都报
        // `DeviceSignatureInvalid`，而密钥与消息看上去全对。
        let response =
            responder.respond(vault.master_key(), device.as_sec1_bytes(), |message| {
                keys.sign(&label, message)
            })?;
        Ok(response)
    }

    /// 校验验证方回传的确认标签（第三步）。
    ///
    /// 成功返回 `true`。**这一步不能省**：它证明对方确实算得出会话密钥，而不只是
    /// 转发了一条挑战。
    ///
    /// # 错误
    ///
    /// 标签不匹配或会话标识对不上时返回 [`Error::AuthProofFailed`]；标签长度不对
    /// 返回 [`Error::AuthMessageMalformed`]。
    pub fn confirm(
        &self,
        vault: Arc<FfiVault>,
        session_id: Vec<u8>,
        confirmation: Vec<u8>,
    ) -> Result<bool, FfiError> {
        let session_id: [u8; AUTH_SESSION_ID_LEN] =
            session_id
                .as_slice()
                .try_into()
                .map_err(|_| Error::AuthMessageMalformed {
                    reason: "会话标识长度不对",
                })?;
        let vault = vault.lock();
        let responder = self.lock();
        auth::confirm(vault.master_key(), &responder, &session_id, &confirmation)?;
        Ok(true)
    }
}

impl FfiResponder {
    /// 取得锁，忽略中毒。
    fn lock(&self) -> std::sync::MutexGuard<'_, auth::Responder> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

///
/// # 为什么参数从端侧来、却又必须在这里校验范围
///
/// 参数确实来自端侧（用户可以在界面上调），但**也来自别人的文件**：导入时
/// 参数是从文件里读出来的，而文件是攻击者可控的。核心的 `KdfParams::new`
/// 两头都设了上下界，这里直接把它的错误透传出去，不自己判断——判断只有一份实现，
/// 才不会出现「FFI 放过了、核心又拒绝」这类不一致。
///
/// 端侧传 `u64` 而不是核心的 `u32`：UniFFI 对 `u32` 的映射在 Kotlin 侧是无符号
/// 类型，而 Kotlin 没有原生无符号整数，端侧要额外绕。`u64` 在两侧都是自然的。
/// 超出 `u32` 的值会在核心的范围检查里被拒绝，不会静默截断。
fn kdf_params(
    memory_kib: Option<u64>,
    iterations: Option<u64>,
    parallelism: Option<u64>,
) -> Result<KdfParams, FfiError> {
    if memory_kib.is_none() && iterations.is_none() && parallelism.is_none() {
        return Ok(KdfParams::recommended());
    }
    let recommended = KdfParams::recommended();
    let narrow = |value: u64, what: &'static str| -> Result<u32, FfiError> {
        u32::try_from(value).map_err(|_| Error::RecoveryParametersInvalid { reason: what }.into())
    };
    Ok(KdfParams::new(
        narrow(
            memory_kib.unwrap_or(u64::from(recommended.memory_kib())),
            "内存上限超出可表示范围",
        )?,
        narrow(
            iterations.unwrap_or(u64::from(recommended.iterations())),
            "迭代次数超出可表示范围",
        )?,
        narrow(
            parallelism.unwrap_or(u64::from(recommended.parallelism())),
            "并行度超出可表示范围",
        )?,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc6238_vector_survives_the_ffi_boundary() {
        // RFC 6238 附录 B：SHA-1 / 20 字节种子 "12345678901234567890"
        // 在 59 秒处应为 94287082。
        let code = totp_code(
            RFC_SECRET.to_owned(),
            59,
            30,
            FfiAlgorithm::Sha1,
            FfiDigits::Eight,
        )
        .expect("应能计算");
        assert_eq!(code, "94287082");
    }

    #[test]
    fn uri_roundtrips_through_ffi_types() {
        let original = "otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA256&digits=7&period=45";
        let parsed = parse_otpauth_uri(original.to_owned()).expect("应能解析");
        assert_eq!(parsed.account, "alice");
        assert_eq!(parsed.issuer.as_deref(), Some("ACME"));
        assert_eq!(parsed.algorithm, FfiAlgorithm::Sha256);
        assert_eq!(parsed.digits, FfiDigits::Seven);
        assert_eq!(parsed.period, 45);

        let back = serialize_otpauth_uri(parsed.clone()).expect("应能序列化");
        let reparsed = parse_otpauth_uri(back).expect("应能再次解析");
        assert_eq!(reparsed, parsed, "FFI 往返后条目应等价");
    }

    #[test]
    fn oversized_input_is_rejected_at_the_boundary() {
        let huge = "A".repeat(MAX_SECRET_CHARS + 1);
        match secret_byte_len(huge) {
            Err(FfiError::InputTooLong {
                kind,
                limit,
                actual,
            }) => {
                assert_eq!(kind, "secret");
                assert_eq!(limit, MAX_SECRET_CHARS as u64);
                assert_eq!(actual, (MAX_SECRET_CHARS + 1) as u64);
            }
            other => panic!("应返回 InputTooLong，实际 {other:?}"),
        }
    }

    #[test]
    fn length_limit_counts_characters_not_bytes() {
        // 2048 个中文字符 = 6144 字节，但按字符计未超限，不应被边界拒绝。
        let chinese = "中".repeat(MAX_SECRET_CHARS);
        // 它不是合法 Base32，所以会走到核心解析并失败——关键是**不是** InputTooLong。
        match secret_byte_len(chinese) {
            Err(FfiError::InputTooLong { .. }) => panic!("按字符计不该触发上限"),
            Err(FfiError::Core { .. }) => {}
            Ok(_) => panic!("非 Base32 输入不该解析成功"),
        }
    }

    #[test]
    fn hotp_matches_rfc4226_through_ffi() {
        // RFC 4226 附录 D 前四组。
        let expected = ["755224", "287082", "359152", "969429"];
        for (counter, want) in expected.iter().enumerate() {
            let got = hotp_code(
                RFC_SECRET.to_owned(),
                counter as u64,
                FfiAlgorithm::Sha1,
                FfiDigits::Six,
            )
            .expect("应能计算");
            assert_eq!(&got, want, "counter={counter}");
        }
    }

    #[test]
    fn drift_verification_returns_the_offset() {
        let code = totp_code(
            RFC_SECRET.to_owned(),
            59,
            30,
            FfiAlgorithm::Sha1,
            FfiDigits::Eight,
        )
        .expect("应能计算");
        // 当前步应命中并返回 0。59/30 = 1。
        let hit = verify_code_with_drift(
            RFC_SECRET.to_owned(),
            1,
            1,
            FfiAlgorithm::Sha1,
            FfiDigits::Eight,
            code.clone(),
        )
        .expect("应能校验");
        assert_eq!(hit, Some(0));

        // 落后一步（用 89 秒即 counter=2 的码去对 counter=1）应返回 1。
        let next = totp_code(
            RFC_SECRET.to_owned(),
            89,
            30,
            FfiAlgorithm::Sha1,
            FfiDigits::Eight,
        )
        .expect("应能计算");
        let offset = verify_code_with_drift(
            RFC_SECRET.to_owned(),
            1,
            1,
            FfiAlgorithm::Sha1,
            FfiDigits::Eight,
            next,
        )
        .expect("应能校验");
        assert_eq!(offset, Some(1));
    }

    #[test]
    fn generated_secrets_are_32_bytes_and_unique() {
        let a = generate_secret_base32().expect("应能生成");
        let b = generate_secret_base32().expect("应能生成");
        assert_ne!(a, b, "两次生成不该相同");
        assert_eq!(secret_byte_len(a).expect("应能解析"), 32);
    }

    #[test]
    fn colon_in_account_is_rejected_at_serialize() {
        let auth = FfiOtpAuth {
            uri_type: FfiUriType::Totp,
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            issuer: None,
            account: "a:b".to_owned(),
            algorithm: FfiAlgorithm::Sha1,
            digits: FfiDigits::Six,
            period: 30,
            counter: None,
        };
        assert!(
            serialize_otpauth_uri(auth).is_err(),
            "含冒号的账号名应被拒绝"
        );
    }

    // ── M3：注册、登录、恢复、挑战-应答 ──────────────────────────────

    /// 测试用的设备身份：密钥由标签确定性地导出。
    ///
    /// 确定性的用意是让「同一台设备」在多次调用间保持一致——真实平台密钥库也是
    /// 这样的（同一个标签取回同一把密钥）。用真随机数会让「用同一个 label 重新
    /// 取一次应当拿到同一把」这条性质无法验证。
    #[derive(Default)]
    struct TestKeys {
        keys: std::sync::Mutex<std::collections::HashMap<String, p256::ecdsa::SigningKey>>,
    }

    impl TestKeys {
        /// 取回或创建标签对应的签名密钥。
        fn key_for(&self, label: &str) -> p256::ecdsa::SigningKey {
            let mut keys = self.keys.lock().expect("测试中无并发中毒");
            keys.entry(label.to_owned())
                .or_insert_with(|| {
                    // 由标签导出确定性的标量。这里**只是为了让测试可复现**，不是
                    // 密钥派生方案——真实实现必须用平台密钥库。
                    let scalar = sha2::Digest::finalize({
                        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
                        sha2::Digest::update(&mut hasher, label.as_bytes());
                        hasher
                    });
                    p256::ecdsa::SigningKey::from_slice(&scalar).expect("标量应当合法")
                })
                .clone()
        }
    }

    impl FfiDeviceKeys for TestKeys {
        fn get_or_create(&self, label: String) -> Result<Vec<u8>, FfiError> {
            let key = self.key_for(&label);
            Ok(key.verifying_key().to_sec1_point(false).as_bytes().to_vec())
        }

        fn sign(&self, label: String, message: Vec<u8>) -> Result<Vec<u8>, FfiError> {
            use p256::ecdsa::signature::Signer as _;
            let key = self.key_for(&label);
            let signature: p256::ecdsa::Signature = key.sign(&message);
            Ok(signature.to_bytes().to_vec())
        }
    }

    /// 测试用的平台密钥库：把主密钥放在内存里。
    #[derive(Default)]
    struct TestStore {
        master: std::sync::Mutex<Option<Vec<u8>>>,
    }

    impl FfiSecureStore for TestStore {
        fn load_master_key(&self) -> Result<Option<Vec<u8>>, FfiError> {
            Ok(self.master.lock().expect("测试中无并发中毒").clone())
        }

        fn store_master_key(&self, key: Vec<u8>) -> Result<(), FfiError> {
            *self.master.lock().expect("测试中无并发中毒") = Some(key);
            Ok(())
        }

        fn delete_master_key(&self) -> Result<(), FfiError> {
            *self.master.lock().expect("测试中无并发中毒") = None;
            Ok(())
        }

        fn is_hardware_backed(&self) -> bool {
            // 如实上报。谎报成 `true` 会让依赖它的分支走进与生产不同的路径，
            // 而测试就再也不会覆盖到软件密钥那条。
            false
        }
    }

    /// 一个最小可用的条目。
    fn sample_entry(name: &str) -> FfiVaultEntry {
        FfiVaultEntry {
            id: String::new(),
            name: name.to_owned(),
            issuer: Some("ACME".to_owned()),
            account: "alice".to_owned(),
            secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
            algorithm: FfiAlgorithm::Sha1,
            digits: FfiDigits::Six,
            period: 30,
            counter: None,
            note: String::new(),
            created_at: 0,
            updated_at: 0,
        }
    }

    const NOW: u64 = 1_700_000_000;

    /// 注册之后能加条目、能算验证码、能序列化再打开。
    ///
    /// 这条走的是端侧最常走的那条路：注册 → 加条目 → 落盘 → 重新打开 → 读验证码。
    #[test]
    fn a_registered_vault_roundtrips_through_the_boundary() {
        let keys = Arc::new(TestKeys::default());
        let store = Arc::new(TestStore::default());
        let vault = FfiVault::register(keys.clone(), store.clone(), "device-a".to_owned())
            .expect("注册应当成功");
        assert!(vault.is_empty(), "注册不带条目");

        let id = vault
            .add_entry(sample_entry("GitHub"), NOW)
            .expect("应当能添加条目");
        assert_eq!(vault.entry_count(), 1);

        let code = vault.totp_for(id.clone(), NOW).expect("应当能算验证码");
        assert_eq!(code.len(), 6, "六位验证码");

        let data = vault.serialize().expect("应当能序列化");
        let reopened = FfiVault::open(store, data).expect("应当能用存储里的主密钥打开");
        assert_eq!(reopened.entry_count(), 1);
        assert_eq!(
            reopened.totp_for(id, NOW).expect("应当能算验证码"),
            code,
            "同一条条目在重新打开后必须算出同一个验证码"
        );
    }

    /// 修改条目不能换掉标识，也不能留下墓碑。
    ///
    /// 换标识会被同步读成「删了一条、又加了一条」；留墓碑会被读成「这条被删了」。
    /// 两种都会在另一台设备上造成可见的错误，而本机看起来一切正常。
    #[test]
    fn updating_an_entry_keeps_its_id_and_leaves_no_tombstone() {
        let keys = Arc::new(TestKeys::default());
        let store = Arc::new(TestStore::default());
        let vault = FfiVault::register(keys, store, "device-a".to_owned()).expect("注册应当成功");
        let id = vault
            .add_entry(sample_entry("GitHub"), NOW)
            .expect("应当能添加条目");

        let mut edited = sample_entry("GitHub (work)");
        edited.id = id.clone();
        vault
            .update_entry(edited, NOW + 60)
            .expect("应当能修改条目");

        assert_eq!(vault.entry_count(), 1, "修改不该多出一条");
        assert_eq!(vault.tombstone_count(), 0, "修改不是删除");
        let entry = vault.entry(id).expect("标识必须仍然指向该条目");
        assert_eq!(entry.name, "GitHub (work)");
        assert_eq!(entry.created_at, NOW, "创建时间应当被保留");
    }

    /// 指定一个不存在的标识时，修改与删除必须**分别**报告。
    ///
    /// 合并处理会让界面在「这条已经不在了」时显示一个空列表，而用户刚才明明还在
    /// 看条目。
    #[test]
    fn a_missing_entry_id_is_reported_as_not_found() {
        let keys = Arc::new(TestKeys::default());
        let store = Arc::new(TestStore::default());
        let vault = FfiVault::register(keys, store, "device-a".to_owned()).expect("注册应当成功");

        let mut ghost = sample_entry("ghost");
        ghost.id = "0".repeat(32);
        let error = vault
            .update_entry(ghost, NOW)
            .expect_err("不存在的标识应当报错");
        assert_eq!(error.kind(), "vault_entry_not_found");

        // 删除一条不存在的条目返回 `false`，不是错误：删除是幂等的，重复删除
        // （例如界面上点了两次）不该弹出错误。
        assert!(
            !vault.remove_entry("0".repeat(32), NOW).expect("应当能调用"),
            "删除不存在的条目应当返回 false"
        );
        assert_eq!(vault.entry_count(), 0);
    }

    /// 登录把主密钥原样交给新设备，新设备因此能打开老设备的保险库。
    ///
    /// 只断言「没有报错」是不够的：一个把主密钥换成新随机值的实现同样不报错，
    /// 而用户要到同步时才发现条目一条都对不上。
    #[test]
    fn login_transfers_the_master_key_across_the_boundary() {
        let old_keys = Arc::new(TestKeys::default());
        let old_store = Arc::new(TestStore::default());
        let old_vault =
            FfiVault::register(old_keys.clone(), old_store.clone(), "device-a".to_owned())
                .expect("注册应当成功");
        old_vault
            .add_entry(sample_entry("GitHub"), NOW)
            .expect("应当能添加条目");
        let data = old_vault.serialize().expect("应当能序列化");

        // 老设备出示二维码。
        let login = FfiLogin::begin().expect("应当能开始登录");
        // 新设备扫码、发请求。
        let joiner_keys = Arc::new(TestKeys::default());
        let joiner =
            FfiJoiner::from_qr(login.payload(), "device-b".to_owned()).expect("应当能建立会话");
        let request = joiner.request(joiner_keys.clone()).expect("应当能发出请求");
        // 老设备授权（真实界面在这里要用户确认）。
        let reply = login
            .authorize(old_vault.clone(), request)
            .expect("应当能授权");
        // 新设备完成。
        let joiner_store = Arc::new(TestStore::default());
        let master = joiner
            .complete(reply, joiner_keys, joiner_store.clone())
            .expect("应当能完成登录");

        assert_eq!(master.len(), 32, "主密钥是 32 字节");
        assert!(
            joiner_store.master.lock().expect("无中毒").is_some(),
            "主密钥必须已经写入新设备的平台存储"
        );

        // 关键断言：新设备用自己拿到的密钥能打开老设备的文件。
        let new_vault = FfiVault::open(joiner_store, data).expect("新设备应当能打开老设备的保险库");
        assert_eq!(new_vault.entry_count(), 1, "老设备的那一条应当可见");
    }

    /// 一次登录只能完成一次，且第二次与「伪造应答」报同一个错。
    #[test]
    fn a_login_cannot_be_completed_twice_across_the_boundary() {
        let old_keys = Arc::new(TestKeys::default());
        let old_store = Arc::new(TestStore::default());
        let old_vault =
            FfiVault::register(old_keys, old_store, "device-a".to_owned()).expect("注册应当成功");
        let login = FfiLogin::begin().expect("应当能开始登录");
        let joiner_keys = Arc::new(TestKeys::default());
        let joiner =
            FfiJoiner::from_qr(login.payload(), "device-b".to_owned()).expect("应当能建立会话");
        let request = joiner.request(joiner_keys.clone()).expect("应当能发出请求");
        let reply = login.authorize(old_vault, request).expect("应当能授权");
        let joiner_store = Arc::new(TestStore::default());

        joiner
            .complete(reply.clone(), joiner_keys.clone(), joiner_store.clone())
            .expect("第一次应当成功");
        let error = joiner
            .complete(reply, joiner_keys, joiner_store)
            .expect_err("第二次必须失败");
        assert_eq!(
            error.kind(),
            "pairing_authentication_failed",
            "必须与伪造应答同一个错误，不给重放者一个区分信号"
        );
    }

    /// 恢复密钥文件能取回同一把主密钥。
    #[test]
    fn a_recovery_file_restores_the_same_master_key() {
        let keys = Arc::new(TestKeys::default());
        let store = Arc::new(TestStore::default());
        let vault = FfiVault::register(keys, store, "device-a".to_owned()).expect("注册应当成功");
        vault
            .add_entry(sample_entry("GitHub"), NOW)
            .expect("应当能添加条目");
        let data = vault.serialize().expect("应当能序列化");

        // 用偏小的参数：这条测试关心的是往返正确性，不是抗暴力破解强度。
        // 推荐参数（64 MiB）会让每次 `cargo test` 多花几百毫秒。
        let file = vault
            .export_recovery_key("correct horse".to_owned(), Some(8), Some(1), Some(1))
            .expect("应当能导出");

        let new_store = Arc::new(TestStore::default());
        let restored =
            import_recovery_key(file.clone(), "correct horse".to_owned(), new_store.clone())
                .expect("应当能导入");
        assert_eq!(restored.len(), 32);

        // 恢复出来的密钥必须真的能打开原文件。
        let reopened = FfiVault::open(new_store, data).expect("应当能打开");
        assert_eq!(reopened.entry_count(), 1);

        // 口令错误必须与文件损坏区分：前者提示重新输入，后者要提示文件不可用。
        let wrong = import_recovery_key(
            file,
            "wrong passphrase".to_owned(),
            Arc::new(TestStore::default()),
        )
        .expect_err("口令错误应当失败");
        assert_eq!(wrong.kind(), "recovery_authentication_failed");
    }

    /// 挑战-应答的三步都要能走通，且主密钥不出边界。
    #[test]
    fn challenge_response_confirms_both_sides_across_the_boundary() {
        let keys = Arc::new(TestKeys::default());
        let store = Arc::new(TestStore::default());
        let vault =
            FfiVault::register(keys.clone(), store, "device-a".to_owned()).expect("注册应当成功");

        let verifier = FfiVerifier::begin().expect("应当能发起挑战");
        let responder = FfiResponder::accept(verifier.challenge()).expect("应当能接受挑战");
        let response = responder
            .respond(vault.clone(), "device-a".to_owned(), keys)
            .expect("应当能生成应答");

        assert!(
            verifier
                .verify(response, vault.clone())
                .expect("应当能校验应答"),
            "第二步应当通过"
        );

        // 第三步：确认标签回传，应答方据此确认对方算得出会话密钥。
        let session_id = verifier.session_id().expect("校验之后应当有会话标识");
        let confirmation = verifier.confirmation().expect("校验之后应当有确认标签");
        assert!(
            responder
                .confirm(vault, session_id, confirmation)
                .expect("应当能确认"),
            "第三步应当通过"
        );
    }

    /// 挑战-应答与配对一样是一次性的。
    #[test]
    fn a_challenge_cannot_be_verified_twice() {
        let keys = Arc::new(TestKeys::default());
        let store = Arc::new(TestStore::default());
        let vault =
            FfiVault::register(keys.clone(), store, "device-a".to_owned()).expect("注册应当成功");
        let verifier = FfiVerifier::begin().expect("应当能发起挑战");
        let responder = FfiResponder::accept(verifier.challenge()).expect("应当能接受挑战");
        let response = responder
            .respond(vault.clone(), "device-a".to_owned(), keys)
            .expect("应当能生成应答");

        verifier
            .verify(response.clone(), vault.clone())
            .expect("第一次应当通过");
        let error = verifier
            .verify(response, vault)
            .expect_err("第二次必须失败");
        assert_eq!(error.kind(), "auth_proof_failed");
    }

    /// 每一类错误都有独一无二的 kind，且没有一类落进 `"unknown"`。
    ///
    /// `core_error_kind` 末尾有一个 `_ => "unknown"` 兜底（核心的 `Error` 标了
    /// `non_exhaustive`，必须有这一支）。因此**新增核心变体时编译器不会提醒**——
    /// 这条测试就是那个提醒：漏掉映射的变体会在这里显示成 `"unknown"`。
    #[test]
    fn every_mapped_error_kind_is_distinct_and_known() {
        let kinds = [
            core_error_kind(&Error::SecretEmpty),
            core_error_kind(&Error::VaultTruncated),
            core_error_kind(&Error::VaultCorrupt),
            core_error_kind(&Error::VaultDecryptionFailed),
            core_error_kind(&Error::VaultEntryNotFound),
            core_error_kind(&Error::MasterKeyWrongLength {
                expected: 32,
                actual: 1,
            }),
            core_error_kind(&Error::DeviceKeyMissing),
            core_error_kind(&Error::DeviceNotRegistered),
            core_error_kind(&Error::DeviceIdentityMismatch),
            core_error_kind(&Error::PairingAuthenticationFailed),
            core_error_kind(&Error::RecoveryAuthenticationFailed),
            core_error_kind(&Error::AuthProofFailed),
            core_error_kind(&Error::TimestampZero),
        ];
        for kind in kinds {
            assert_ne!(kind, "unknown", "有变体没有被映射到稳定的 kind");
        }
        let unique: std::collections::HashSet<_> = kinds.iter().collect();
        assert_eq!(
            unique.len(),
            kinds.len(),
            "两个变体映到了同一个 kind，端侧就无法区分它们"
        );
    }
}
