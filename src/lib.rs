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

use qualia2fa_core::Error;
use qualia2fa_core::otp::{self, Algorithm, Digits, OtpSecret};
use qualia2fa_core::uri;

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
        // 核心是 #[non_exhaustive]：新增变体时这里会编译失败，从而强制我们
        // 为它选一个 kind，而不是让它悄悄落到兜底分支。
        _ => "unknown",
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
}
