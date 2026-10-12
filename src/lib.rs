//! FFI layer of Qualia2FA: exposes `qualia2fa-core` as UniFFI bindings.
//!
//! # Responsibility of this crate
//!
//! This crate **only moves data**: it converts the primitive types passed in from
//! Kotlin/Swift into core types, calls the core, and converts the results back.
//! **Any cryptography, parsing or validation logic in this file is a design
//! regression** — such logic must stay inside `qualia2fa-core`, the only layer
//! that is free of unsafe code and can be audited on its own.
//!
//! A review of this crate has a single checklist item: **has any core logic been
//! moved in here?**
//!
//! `uniffi::setup_scaffolding!()` expands the unsafe code the FFI boundary needs
//! inside this crate (raw pointer dereferences, `catch_unwind`, transfer of string
//! ownership), so this crate is not `forbid(unsafe_code)`. The safety boundary runs
//! **between crates**: the core is `forbid(unsafe_code)`, and this crate is the
//! only place allowed to contain unsafe code, which must stay thin. `Cargo.toml`
//! sets `unsafe_code` to `warn` rather than `allow`, so new unsafe code is reported
//! at build time.
//!
//! # Handling of secret material
//!
//! The core's [`OtpSecret`] **deliberately implements neither `Clone` nor a raw
//! byte accessor**, and its `Debug` does not even print the length. Across the FFI
//! boundary a seed is always represented as a **Base32 string**:
//!
//! - inbound: `&str` -> [`OtpSecret::from_base32`]
//! - outbound: [`OtpSecret::to_base32`]
//!
//! Seed bytes therefore never cross the FFI boundary as a `Vec<u8>`, which would
//! leave one copy on each side outside the control of any erasure. Base32 is the
//! single narrow exit already chosen by the core, and this layer reuses it.
//!
//! **Known residual risk**: on the Kotlin/Swift side a Base32 string is an
//! ordinary `String`, not protected by `secrecy`'s erasure, and it may be copied
//! by the garbage collector or stored in a string pool. That is an inherent
//! limitation of managed languages, so **the client side must adopt its own
//! discipline**: a seed's Base32 exists only in the scope that needs it, is
//! dropped immediately afterwards, and is never logged or persisted.

uniffi::setup_scaffolding!();

use std::sync::Arc;

use qualia_dik::{DevicePublicKey, DeviceSignature};
use qualia2fa_core::auth;
use qualia2fa_core::flow::{self, DeviceKeys as _, Joiner, Login, SecureStore as _};
use qualia2fa_core::otp::{self, Algorithm, Digits, OtpSecret};
use qualia2fa_core::recovery::KdfParams;
use qualia2fa_core::uri;
use qualia2fa_core::vault::{Entry, MasterKey, VaultFile};
use qualia2fa_core::{Error, ExposeSecret as _, SecretString};

/// Length of a challenge-response session identifier.
///
/// The core's `auth::SESSION_ID_LEN` is a **private** constant (it belongs to the
/// protocol internals and is not meant to be depended on from above), so the
/// value is written out here. It is not arbitrary: the core's
/// `pairing::SESSION_ID_LEN` is 32 as well, and the two are equal on purpose —
/// session identifiers on one channel must have the same length, otherwise a
/// length comparison would report a difference where there is none.
const AUTH_SESSION_ID_LEN: usize = 32;

/// Length of a challenge-response confirmation tag (core `auth::CONFIRM_LEN`, also private).
const AUTH_CONFIRM_LEN: usize = 32;

/// Maximum length in characters of a seed string crossing the FFI boundary.
///
/// Real seeds are 16-64 bytes (about 26-104 Base32 characters). The limit is 2048,
/// which leaves room for non-standard cases while rejecting meaningless input such
/// as a huge string a client was tricked into passing in.
///
/// **This is a defensive limit, not a specification requirement**: the core
/// deliberately sets no lower bound on seed length (short seeds exist in the
/// wild), and judging whether a length is adequate is a UI-layer warning, see
/// [`is_secret_shorter_than_recommended`].
const MAX_SECRET_CHARS: usize = 2048;

/// Maximum length in characters of an `otpauth://` URI crossing the FFI boundary.
///
/// Real URIs are usually shorter than 200 characters. A QR code holds at most
/// about 2953 bytes, so 4096 covers any URI that can arrive from a QR code while
/// rejecting oversized input.
const MAX_URI_CHARS: usize = 4096;

/// Maximum length in characters of a vault field crossing the FFI boundary.
///
/// The core enforces its own limit on decrypted fields (`Entry::MAX_FIELD_LEN`,
/// 64 KiB bytes), but that is the **post-decryption** defence. This constant
/// guards the side coming in from the client: a UI text box has no reason to hold
/// more than this, and rejecting at the boundary is cheaper than running a whole
/// encryption pass only to fail inside the core.
///
/// The limit counts characters (8 Ki characters) rather than the core's 64 KiB
/// bytes because what the client sends is a string; counting bytes would make a
/// note containing non-ASCII text hit the limit much earlier. 8 Ki characters is
/// far beyond any real service name, account name or note.
const MAX_VAULT_FIELD_CHARS: usize = 8 * 1024;

/// Maximum length in characters of a device label crossing the FFI boundary.
///
/// The label ends up in the platform key store, and platforms differ in how long a
/// key name may be (Windows CNG, Android Keystore and the iOS keychain all impose
/// limits, and not all of them are documented). Real labels are short strings such
/// as `qualia2fa-device`, so 256 characters is ample while still rejecting an
/// oversized label passed in by a client.
const MAX_LABEL_CHARS: usize = 256;

/// Maximum length in characters of a passphrase crossing the FFI boundary.
///
/// The passphrase is fed to Argon2, whose running time grows linearly with the
/// input length. Without a limit, a multi-megabyte "passphrase" could occupy the
/// thread for a long time during export or import. **The limit is not a security
/// measure** (passphrase strength comes from entropy, not length); it only
/// rejects meaningless input.
const MAX_PASSPHRASE_CHARS: usize = 1024;

/// Maximum length in characters of QR code text crossing the FFI boundary.
///
/// The QR payload is 99 bytes, 159 characters in Base32. The limit is 512, which
/// leaves room for text the client may carry around the payload (for example a
/// user copying the code together with quotes from a chat log) while rejecting
/// oversized input.
const MAX_QR_TEXT_CHARS: usize = 512;

/// Summary of a core error, carried across the FFI boundary.
///
/// The core's [`Error`] is a `#[non_exhaustive]` rich error enum (carrying
/// `String`, `usize` and other payloads) and is not a UniFFI type: UniFFI requires
/// every field of an error enum to implement `Lift`/`Lower`/`TypeId`, and with
/// `#[uniffi(flat_error)]` the variants would cross the boundary as `Display` text
/// only, leaving the client one opaque string and **no way to dispatch the UI by
/// failure reason**. This type carries two fields:
///
/// - `kind`: a stable machine-readable identifier the client branches on
/// - `message`: user-facing text, for display and logs only
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiCoreError {
    /// Stable error identifier; see the contract in [`core_error_kind`].
    pub kind: String,
    /// Human-readable error text (identical to the core's `Display`).
    pub message: String,
}

/// Maps a core error to a **stable** machine-readable identifier.
///
/// # Stability contract
///
/// These strings are what the client `switch`es on, so they are **part of the
/// public interface**: new values may be added, but existing values must not be
/// renamed or change meaning (a rename breaks client behaviour).
///
/// The client must have a fallback branch for unknown `kind` values: the core is
/// `#[non_exhaustive]`, so variants will be added and older clients will meet
/// values they have never seen.
///
/// `format!("{source:?}")` and automatic derivation from the variant name are
/// deliberately not used: `Debug` output is an implementation detail, renaming a
/// variant would silently change client behaviour, and it may contain payload
/// contents. Every string is written out in an explicit `match` arm so that a
/// rename is visible during review.
///
/// # Notes on individual kinds
///
/// - `vault_entry_not_found` is distinct from an empty vault: the entry the caller
///   is acting on no longer exists.
/// - `vault_bad_key_check` reports a structural problem (the key check value has
///   the wrong length, or the file is truncated or malformed), whereas
///   `vault_decryption_failed` reports a wrong key or a file that was modified.
/// - `device_not_registered` means this device has never been registered;
///   `vault_decryption_failed` means it was registered but the data cannot be
///   decrypted.
/// - `pairing_authentication_failed` deliberately does not distinguish a modified
///   ciphertext, a wrong session and a wrong joiner public key, so that an attacker
///   gets no oracle for "almost succeeded".
/// - Failures reported by the device identity library are split into
///   `device_public_key_invalid`, `device_signature_invalid` and `device_error`
///   rather than one generic kind.
/// - The final `_ => "unknown"` arm is **required**: the core's `Error` is
///   `#[non_exhaustive]`, so a wildcard arm is mandatory outside its own crate
///   (removing it is `E0004`). The price is that the compiler does not flag a newly
///   added core variant — `"unknown"` silently absorbs it and the client receives a
///   kind it cannot dispatch. The `every_mapped_error_kind_is_distinct_and_known`
///   test guards against that instead of the compiler: add one mapping arm per new
///   variant and add the value to that test's list.
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
        // ── Vault ──────────────────────────────────────────────────────────
        Error::VaultTruncated => "vault_truncated",
        Error::VaultBadMagic => "vault_bad_magic",
        Error::VaultUnsupportedVersion { .. } => "vault_unsupported_version",
        Error::VaultReservedByteNotZero { .. } => "vault_reserved_byte_not_zero",
        Error::VaultUnknownRecordKind { .. } => "vault_unknown_record_kind",
        Error::VaultRecordTooLong { .. } => "vault_record_too_long",
        Error::VaultTooManyRecords => "vault_too_many_records",
        Error::VaultTrailingBytes { .. } => "vault_trailing_bytes",
        Error::VaultDuplicateEntryId => "vault_duplicate_entry_id",
        Error::VaultEntryNotFound => "vault_entry_not_found",
        Error::VaultDuplicateField { .. } => "vault_duplicate_field",
        Error::VaultCorrupt => "vault_corrupt",
        Error::VaultBadKeyCheck => "vault_bad_key_check",
        Error::VaultInvalidUtf8 => "vault_invalid_utf8",
        Error::VaultDecryptionFailed => "vault_decryption_failed",
        Error::MasterKeyWrongLength { .. } => "master_key_wrong_length",
        Error::FieldTooLong { .. } => "field_too_long",
        Error::VaultIo { .. } => "vault_io",
        // ── Device identity, pairing, recovery, challenge-response ─────────
        Error::DevicePublicKeyInvalid { .. } => "device_public_key_invalid",
        Error::DeviceSignatureInvalid { .. } => "device_signature_invalid",
        Error::Device(qualia_dik::Error::DevicePublicKeyInvalid { .. }) => {
            "device_public_key_invalid"
        }
        Error::Device(qualia_dik::Error::DeviceSignatureInvalid { .. }) => {
            "device_signature_invalid"
        }
        Error::Device(_) => "device_error",
        Error::PairingPayloadMalformed { .. } => "pairing_payload_malformed",
        Error::PairingUnsupportedVersion { .. } => "pairing_unsupported_version",
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
        Error::DeviceNotRegistered => "device_not_registered",
        Error::DeviceIdentityMismatch => "device_identity_mismatch",
        Error::SecureStoreWriteFailed { .. } => "secure_store_write_failed",
        Error::TimestampZero => "timestamp_zero",
        _ => "unknown",
    }
}

impl FfiError {
    /// Stable error identifier, for the client to dispatch UI text on.
    ///
    /// The client could read `FfiError.Core.detail.kind` directly, but that would
    /// require every call site to match on the variant first. This method folds the
    /// boundary's own errors into the same set of identifiers (`input_too_long`),
    /// so the client needs a single `when`.
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

/// Lets [`FfiCoreError`] take part in an outer error's text through `Display`.
///
/// Written by hand rather than derived: `Display` outputs `message` and does not
/// repeat `kind` — `kind` is meant for programs, and putting it into user-facing
/// text only adds noise.
///
/// It is needed because `#[error("{source}")]` requires `source` to implement
/// `Display`; otherwise thiserror treats it as `Error::source()` instead and
/// reports an unsatisfied `as_dyn_error` trait bound.
impl core::fmt::Display for FfiCoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Errors originating in the FFI boundary itself.
///
/// Kept separate from the core's [`Error`] because "input too long" is a
/// **boundary** concern, not a core semantic. Core errors are passed through in
/// structured form as [`FfiCoreError`], which is not the same as discarding their
/// classification.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// The input exceeds the limit set by this layer.
    #[error("输入过长：{kind} 上限为 {limit} 字符，实际 {actual} 字符")]
    InputTooLong {
        /// The restricted input category (`secret` / `uri`).
        kind: String,
        /// Maximum number of characters allowed.
        limit: u64,
        /// Actual number of characters.
        actual: u64,
    },

    /// An error returned by the core.
    ///
    /// **No `#[from]`**: `#[from]` would make thiserror generate
    /// `impl From<Error> for FfiError`, but UniFFI requires every field to be a
    /// type that can cross the boundary, and the core `Error` is not. The
    /// conversion is a hand-written `From` that first reduces the error to the
    /// plain data of [`FfiCoreError`].
    ///
    /// The field is named `detail` rather than `source` on purpose: thiserror
    /// always treats a field named `source` as `Error::source()` (requiring
    /// `std::error::Error`), even when the text only writes `{source}`, and then
    /// reports an unsatisfied `as_dyn_error` bound.
    #[error("{detail}")]
    Core {
        /// Structured summary of the core error.
        detail: FfiCoreError,
    },
}

/// Conversion from a core error to an FFI error.
///
/// Hand-written rather than `#[from]`; see [`FfiError::Core`].
impl From<Error> for FfiError {
    fn from(source: Error) -> Self {
        FfiError::Core {
            detail: source.into(),
        }
    }
}

/// Hash algorithm selection passed in over FFI.
///
/// The core's [`Algorithm`] is not exposed directly, for two reasons:
///
/// 1. The extra layer keeps the Rust API unaffected by renames of the client-side enum.
/// 2. If the core ever turns it into an enum carrying data, the FFI contract stays unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiAlgorithm {
    /// HMAC-SHA-1 (the RFC 6238 default; almost every real server supports only this).
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
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

/// Number of digits in a generated code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiDigits {
    /// 6 digits (the default).
    Six,
    /// 7 digits (used by some banks).
    Seven,
    /// 8 digits.
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

/// Type of an `otpauth://` URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiUriType {
    /// Time-based.
    Totp,
    /// Counter-based.
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

/// A parsed `otpauth://` entry.
///
/// The fields correspond one-to-one to the core [`uri::OtpAuth`]; the only
/// difference is that `secret` appears as a Base32 string rather than as an
/// `OtpSecret` (see the module documentation).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiOtpAuth {
    /// TOTP or HOTP.
    pub uri_type: FfiUriType,
    /// The secret, Base32 encoded (upper case).
    pub secret_base32: String,
    /// Issuer (service name), such as `GitHub`.
    pub issuer: Option<String>,
    /// Account name, such as `alice@example.com`.
    pub account: String,
    /// Hash algorithm in use.
    pub algorithm: FfiAlgorithm,
    /// Number of digits in a code.
    pub digits: FfiDigits,
    /// Time step in seconds.
    ///
    /// **Invariant**: for HOTP entries this value is always the core default and
    /// has no meaning (HOTP advances by counter). It follows the convention of
    /// the core [`uri::OtpAuth::period`].
    pub period: u64,
    /// The HOTP counter. `None` for TOTP.
    pub counter: Option<u64>,
}

/// Checks a string length limit and returns [`FfiError::InputTooLong`] when it is
/// exceeded.
///
/// The limit counts **characters**, not bytes: strings arriving from the host
/// side may contain multi-byte characters, and counting bytes would make such
/// input hit the limit sooner than the reported character count suggests.
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

/// Parses an `otpauth://` URI.
///
/// Parses and validates the Google Authenticator Key URI Format, including the
/// issuer/account prefix consistency check, rejection of repeated parameters and
/// percent decoding.
///
/// # Errors
///
/// Returns [`FfiError::InputTooLong`] when the input is too long; otherwise
/// returns a core error ([`FfiError::Core`]) whose meaning is documented on the
/// core `Error`.
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

/// Serializes an [`FfiOtpAuth`] back into an `otpauth://` URI.
///
/// # Errors
///
/// The core rejects an account name containing `:` — that character is
/// indistinguishable from the `issuer:account` separator, so encoding it would
/// change which part of a round-tripped URI belongs to the issuer and which to
/// the account. The rejection is intentional.
#[uniffi::export]
pub fn serialize_otpauth_uri(auth: FfiOtpAuth) -> Result<String, FfiError> {
    check_len("secret", &auth.secret_base32, MAX_SECRET_CHARS)?;
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

/// Computes a TOTP code.
///
/// `unix_time` is Unix seconds and is **supplied by the host side**: the core
/// does not read a clock, so time always enters as a parameter, which is what
/// makes the RFC 6238 test vectors verifiable. The host side should pass the
/// system clock in seconds.
///
/// The return value is a fixed-width decimal string (leading zeros included)
/// whose length is given by `digits`.
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

/// Computes an HOTP code.
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

/// Computes a Steam Guard code (5 characters, custom alphabet).
///
/// `period` is normally 30, the time step Steam uses.
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

/// Verifies a user-supplied code, allowing for clock drift.
///
/// `expected_counter` is the counter for the current time (`unix_time / period`).
/// `window` is the number of steps of drift allowed (RFC 6238 suggests 1, that
/// is ±1 step).
///
/// The return value is the offset that matched: `0` for the current step, `-1`
/// for one step behind, `1` for one step ahead, and so on. The offset is
/// **returned instead of a boolean** so that the host side can calibrate that
/// entry's clock deviation rather than only learn right or wrong.
///
/// The comparison is constant time and does not return early on a matching
/// prefix. `None` means verification failed, including a malformed input code.
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

/// Compares two code strings for equality in constant time.
///
/// For host-side code that has already computed the expected code itself. Use
/// [`verify_code_with_drift`] when clock drift must be tolerated.
#[uniffi::export]
#[must_use]
pub fn codes_match(expected: String, provided: String) -> bool {
    otp::verify_code(&expected, &provided)
}

/// Recommended minimum secret length in bytes for the given algorithm.
///
/// Intended for a **warning** on import rather than a rejection: the core does
/// not enforce a minimum length, since short secrets exist in practice.
#[uniffi::export]
#[must_use]
pub fn recommended_min_secret_len(algorithm: FfiAlgorithm) -> u64 {
    otp::recommended_min_secret_len(algorithm.into()) as u64
}

/// Reports whether the secret is shorter than the recommended length.
///
/// The host side cannot compare lengths itself: it only has the Base32 string,
/// and the Base32 length is not linearly related to the byte length (5 bits per
/// character versus 8 bits per byte).
#[uniffi::export]
pub fn is_secret_shorter_than_recommended(
    secret_base32: String,
    algorithm: FfiAlgorithm,
) -> Result<bool, FfiError> {
    check_len("secret", &secret_base32, MAX_SECRET_CHARS)?;
    let secret = OtpSecret::from_base32(&secret_base32)?;
    Ok(secret.is_shorter_than_recommended(algorithm.into()))
}

/// The **byte** length of the secret (not the Base32 string length).
///
/// Intended for host-side messages such as "20 bytes / 20 recommended".
#[uniffi::export]
pub fn secret_byte_len(secret_base32: String) -> Result<u64, FfiError> {
    check_len("secret", &secret_base32, MAX_SECRET_CHARS)?;
    let secret = OtpSecret::from_base32(&secret_base32)?;
    Ok(secret.len() as u64)
}

/// Generates a random 256-bit secret and returns its Base32 representation.
///
/// Intended for generating a secret when a new entry is created. Randomness
/// comes from the OS CSPRNG (`getrandom`), not from a user-space PRNG.
///
/// 256 bits is the output length of SHA-256 and is above the recommended
/// minimum of every supported algorithm: the largest of the recommended minima
/// is 64 bytes (512 bits), so 32 bytes is equal in length to SHA-256's output,
/// shorter than SHA-512's block but still above its recommended minimum.
#[uniffi::export]
pub fn generate_secret_base32() -> Result<String, FfiError> {
    let mut bytes = [0_u8; 32];
    qualia2fa_core::getrandom::fill(&mut bytes).map_err(|_| FfiError::Core {
        detail: Error::RandomnessUnavailable.into(),
    })?;
    let secret = OtpSecret::from_bytes(bytes.to_vec())?;
    Ok(secret.to_base32())
}

/// The core library version, for compatibility checks and diagnostics.
///
/// This is the version of `qualia2fa-core`, not of this FFI crate: the semantic
/// version the host side needs to align with is the core's.
#[uniffi::export]
#[must_use]
pub fn core_version() -> String {
    qualia2fa_core::VERSION.to_owned()
}

// ═══════════════════════════════════════════════════════════════════════════
// Device identity, registration and login
// ═══════════════════════════════════════════════════════════════════════════
//
// The master key stays inside Rust wherever possible. The core `flow` module
// takes its platform dependencies as two trait parameters, so orchestration
// completes without the master key leaving Rust. This section has the same
// shape:
//
// - [`FfiVault`] **holds** the master key on the Rust side, and both entry
//   operations and serialization happen inside Rust. The host side only
//   receives vault file bytes and entry fields, never the master key: on the
//   open / add entry / serialize path the master key does not cross the
//   boundary at all.
// - The master key crosses the boundary in exactly two places, both
//   unavoidable: registration hands it to the platform key store
//   ([`FfiSecureStore`]), and login reads it back out of the platform key
//   store. Its permanent home is the host side's hardware key store, which only
//   the host side can reach.
// - [`FfiSecureStore`] therefore exchanges **bytes** rather than some key
//   handle: the master key arrives and leaves the host side as a 32-byte array.
//
// The minimal host-side implementation is to forward these two traits straight
// to the platform key store API, **with no decisions of its own**: any decision
// belongs in the core layer.

/// Source of the device identity key pair: forwarded by the host side to the
/// platform hardware key store.
///
/// Corresponds to the core [`qualia2fa_core::flow::DeviceKeys`]. An
/// implementation should forward directly to the platform layer, **with no
/// decisions of its own**.
///
/// # Contract the implementation must satisfy
///
/// - **`get_or_create` must be idempotent for the same `label`.** A label names
///   one key pair for the lifetime of the device.
/// - **A key must be persisted immediately**, not buffered until the end of a
///   session: a signing call may arrive in a later process start.
/// - **`sign` receives the raw message, not a digest.** The host side must not
///   hash it first: the core verifies with the standard ECDSA hash mode, so
///   hashing twice makes verification report `DeviceSignatureInvalid` while the
///   key and the message are both correct.
#[uniffi::export(with_foreign)]
pub trait FfiDeviceKeys: Send + Sync {
    /// Returns the public key for `label`, creating it when it does not exist.
    /// SEC1 uncompressed encoding, 65 bytes.
    fn get_or_create(&self, label: String) -> Result<Vec<u8>, FfiError>;

    /// Signs the **raw message** with the private key for `label`. Returns the
    /// 64-byte raw `r‖s`, not DER.
    fn sign(&self, label: String, message: Vec<u8>) -> Result<Vec<u8>, FfiError>;
}

/// Where the master key is persisted: forwarded by the host side to the
/// platform hardware key store.
///
/// Corresponds to the core [`qualia2fa_core::flow::SecureStore`].
///
/// # `load` returning `None` and returning `Err` are two different things
///
/// - `Ok(None)`: this device was **never registered**. The user interface
///   should guide the user to register or log in.
/// - `Err(..)`: the device was registered, but the key cannot be read now
///   (hardware reset, key deleted, different user account). The user interface
///   must **warn that data may be lost** and must never guide the user to
///   register again, since that would overwrite the old data with a new master
///   key and make the existing entries permanently unrecoverable.
///
/// Collapsing these two cases into one `None` is the easiest mistake at this
/// interface, and the user interface above cannot tell them apart.
#[uniffi::export(with_foreign)]
pub trait FfiSecureStore: Send + Sync {
    /// Reads the master key, 32 bytes. Returns `None` when the device was never
    /// registered.
    fn load_master_key(&self) -> Result<Option<Vec<u8>>, FfiError>;

    /// Writes the master key (32 bytes), overwriting any existing value.
    fn store_master_key(&self, key: Vec<u8>) -> Result<(), FfiError>;

    /// Deletes the master key. Calling it on a device that was never registered
    /// must not report an error.
    fn delete_master_key(&self) -> Result<(), FfiError>;

    /// Whether this store is hardware backed (TPM / Secure Enclave / Android
    /// Keystore).
    ///
    /// **Must be reported truthfully.** With no hardware available it returns
    /// `false` and the user interface asks for consent before continuing;
    /// claiming otherwise would tell the user that a software file is hardware
    /// protected.
    fn is_hardware_backed(&self) -> bool;
}

/// Forwarding implementation of the core `DeviceKeys`: bridges trait calls to
/// host-side callbacks.
struct ForeignDeviceKeys(Arc<dyn FfiDeviceKeys>);

impl qualia2fa_core::flow::DeviceKeys for ForeignDeviceKeys {
    fn get_or_create(&mut self, label: &str) -> Result<DevicePublicKey, Error> {
        let bytes = self
            .0
            .get_or_create(label.to_owned())
            .map_err(ffi_to_core_error)?;
        Ok(DevicePublicKey::from_sec1_bytes(&bytes)?)
    }

    fn sign(&mut self, label: &str, message: &[u8]) -> Result<DeviceSignature, Error> {
        let bytes = self
            .0
            .sign(label.to_owned(), message.to_vec())
            .map_err(ffi_to_core_error)?;
        Ok(DeviceSignature::from_bytes(&bytes)?)
    }
}

/// Forwarding implementation of the core `SecureStore`: bridges trait calls to
/// host-side callbacks.
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

/// Converts an [`FfiError`] returned by a host-side callback back into a core
/// error.
///
/// The errors appearing in these callbacks **are core errors already**: the host
/// side passes them back (for example, a platform key store reporting unavailable
/// hardware, which corresponds to the core [`Error::DeviceKeyMissing`]), and the
/// error handling in `flow` branches on that reason. [`FfiError::Core`] is mapped
/// back to a core variant through `kind`; what cannot be mapped back — the
/// boundary's own [`FfiError::InputTooLong`] and any kind added later — degrades to
/// [`Error::DeviceKeyMissing`].
fn ffi_to_core_error(source: FfiError) -> Error {
    match source {
        FfiError::Core { detail } => kind_to_core_error(&detail.kind),
        FfiError::InputTooLong { .. } => Error::DeviceKeyMissing,
    }
}

/// Maps a stable error kind back to a core error variant.
///
/// **Only the device-identity-related ones**: this function is used on the
/// callback-crossing paths, where the set of possible core errors is limited
/// (missing key, mismatched identity, failed store write). Everything else
/// degrades to [`Error::DeviceKeyMissing`] rather than being forced into a
/// variant whose meaning does not fit: a wrong classification is worse than a
/// coarse one.
fn kind_to_core_error(kind: &str) -> Error {
    match kind {
        "device_key_missing" => Error::DeviceKeyMissing,
        "device_signature_invalid" => Error::Device(qualia_dik::Error::DeviceSignatureInvalid {
            reason: "端侧签名失败",
        }),
        "secure_store_write_failed" => Error::SecureStoreWriteFailed {
            reason: "端侧密钥库拒绝写入",
        },
        _ => Error::DeviceKeyMissing,
    }
}

/// A 2FA entry, as represented across the FFI boundary.
///
/// Relation to [`uri::OtpAuth`]: that type is the parse result of an `otpauth://`
/// URI, while this one is what a vault stores. The fields are similar but **not
/// equivalent** — a vault entry adds a display name, a note and timestamps, and
/// has no "URI type" field (HOTP is expressed by `counter` being `None`).
///
/// The core's [`EntryId`](qualia2fa_core::vault::EntryId) is 16 bytes; it crosses
/// the boundary as a 32-character lower-case hexadecimal string, the form the host
/// side uses as an opaque identifier (list item key, naming an entry to delete).
/// Strings have value semantics, whereas byte-array equality and hashing in
/// managed languages are often by reference.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiVaultEntry {
    /// Entry identifier, a 32-character lower-case hexadecimal string.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Issuer (service name).
    pub issuer: Option<String>,
    /// Account name.
    pub account: String,
    /// The secret, Base32 encoded (upper case). See the module documentation for
    /// the secret representation.
    pub secret_base32: String,
    /// Hash algorithm in use.
    pub algorithm: FfiAlgorithm,
    /// Number of digits in a code.
    pub digits: FfiDigits,
    /// Time step in seconds. Meaningless for HOTP entries.
    pub period: u64,
    /// The HOTP counter. `None` for TOTP entries.
    pub counter: Option<u64>,
    /// User note.
    pub note: String,
    /// Creation time in Unix seconds.
    pub created_at: u64,
    /// Last modification time in Unix seconds.
    pub updated_at: u64,
}

impl FfiVaultEntry {
    /// Converts a core entry into its cross-boundary representation.
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

    /// Builds a core entry. `now` fills in the creation and modification times.
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

    /// Parses the 16-byte hexadecimal identifier.
    fn parse_id(&self) -> Result<qualia2fa_core::vault::EntryId, FfiError> {
        parse_entry_id(&self.id)
    }
}

/// Parses the hexadecimal representation of an `EntryId` (32 lower-case
/// hexadecimal characters).
fn parse_entry_id(text: &str) -> Result<qualia2fa_core::vault::EntryId, FfiError> {
    check_len("entry_id", text, 32)?;
    let bytes = text.as_bytes();
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

/// One hexadecimal character → its value.
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

/// An unlocked vault.
///
/// # The master key does not cross the boundary
///
/// This object **holds** the master key on the Rust side, and entry operations
/// and serialization happen inside Rust. On the open vault → read entries →
/// write entries → serialize path, the master key never appears as bytes in
/// Kotlin or Swift.
///
/// # Host-side lifetime
///
/// The host side constructs this object when the user unlocks the application
/// and **discards** it (drops the reference) when the application goes to the
/// background or the user locks it. The Rust-side `Drop` wipes the master key
/// when the object is collected, but that depends on collection timing, so
/// locking **must not** rely on the collector: locking means actually dropping
/// the reference and letting the user interface ask for an unlock again.
#[derive(uniffi::Object)]
pub struct FfiVault {
    /// The core vault state, including the master key.
    ///
    /// UniFFI shares exported objects as `Arc<Self>`, and `Arc` grants no mutable
    /// borrow, so the state sits behind a container with interior mutability.
    /// `Mutex` and not `RefCell`: UniFFI's `#[Object]` requires `Send + Sync`, which
    /// `RefCell` does not provide.
    ///
    /// **The lock granularity is one method call**, and only in-memory work
    /// happens under the lock (hash-table insert and remove, copying entry
    /// fields). Encryption and Argon2 run outside the lock: one export
    /// derivation takes hundreds of milliseconds, and holding the lock across it
    /// would stall concurrent user-interface refreshes.
    ///
    /// Poisoning is absorbed with `unwrap_or_else`: this lock guards a data
    /// structure, and the methods inside it contain no panicking code. Should a
    /// panic happen anyway, recovering the data is preferable to failing every
    /// later call, which would leave the user unable to read or write entries.
    inner: std::sync::Mutex<VaultFile>,
}

impl FfiVault {
    /// Builds from a core vault.
    fn wrap(inner: VaultFile) -> Arc<Self> {
        Arc::new(Self {
            inner: std::sync::Mutex::new(inner),
        })
    }
}

#[uniffi::export]
impl FfiVault {
    /// Creates an empty vault from an existing master key.
    ///
    /// Used by two paths:
    ///
    /// - after [`FfiJoiner::complete`]: the master key has been obtained and
    ///   written to the platform store, and a vault object to operate on is now
    ///   needed;
    /// - after [`import_recovery_key`]: the same.
    ///
    /// # An empty vault is expected
    ///
    /// The master key and the entries are **transferred separately**: logging in
    /// brings the key, not the content. The first vault the host side obtains is
    /// necessarily empty, and the entries come back through sync or from a local
    /// file.
    ///
    /// # The master key crosses the boundary here, and only here
    ///
    /// The parameter is a 32-byte plaintext key — the case where the host side
    /// already holds the master key, which cannot be avoided. After this call
    /// the host side can drop those 32 bytes; everything later goes through this
    /// object.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MasterKeyWrongLength`] when the length is not 32 bytes.
    #[uniffi::constructor]
    pub fn from_master_key(master_key: Vec<u8>) -> Result<Arc<Self>, FfiError> {
        let master = flow::master_key_from_bytes(master_key.into())?;
        Ok(Self::wrap(flow::empty_vault(master)))
    }

    /// Registers a new device: generates a master key, obtains a device
    /// identity, and hands the master key to the platform key store.
    ///
    /// # What this step does and does not do
    ///
    /// **Does**: generate the master key → obtain the device identity → write
    /// the master key into [`FfiSecureStore`].
    /// **Does not** create a vault file or write to disk. It returns an empty
    /// [`FfiVault`]; the host side adds the first entries and then calls
    /// [`FfiVault::serialize`] to persist them.
    ///
    /// # Errors
    ///
    /// Returns the corresponding error when creating the device identity or
    /// writing the master key fails, and in that case **leaves nothing on disk**
    /// (this function writes no file). The platform key store may be
    /// unavailable; the host side should treat that as a state to report to the
    /// user rather than retry.
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

    /// Opens a vault file with the master key from the platform key store.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DeviceNotRegistered`] (`kind` is
    /// `device_not_registered`) when the device was never registered, and
    /// [`Error::VaultDecryptionFailed`] (`kind` is `vault_decryption_failed`)
    /// when a master key exists but the file cannot be opened. The host side
    /// must distinguish the two: the first guides the user to register or log
    /// in, the second warns that the data may be damaged or that the master key
    /// was replaced.
    ///
    /// # An empty vault also tells whether the master key is right
    ///
    /// Format version 2 places a master key check value at the end of the file,
    /// so **a file with no entries is judged as well**: a wrong master key
    /// returns [`Error::VaultDecryptionFailed`] immediately instead of only
    /// after the user adds a first entry. The host side may therefore present
    /// "unlocked" as soon as the open succeeds.
    ///
    /// **Old version 1 files still cannot be judged** — such a file carries no
    /// information to judge with. Use the challenge-response of [`FfiVerifier`]
    /// for authoritative confirmation, since it does not depend on file
    /// content.
    #[uniffi::constructor]
    pub fn open(store: Arc<dyn FfiSecureStore>, data: Vec<u8>) -> Result<Arc<Self>, FfiError> {
        let store = ForeignSecureStore(store);
        let file = flow::open_vault(&store, &data)?;
        Ok(Self::wrap(file))
    }

    /// Number of entries.
    #[must_use]
    pub fn entry_count(&self) -> u64 {
        self.lock().vault().len() as u64
    }

    /// Whether there are no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().vault().is_empty()
    }

    /// Number of tombstones.
    ///
    /// A tombstone is the record that an entry was deleted, which lets the
    /// deletion propagate between devices. User interfaces normally need not
    /// show it, but it is useful when diagnosing.
    #[must_use]
    pub fn tombstone_count(&self) -> u64 {
        self.lock().vault().tombstone_count() as u64
    }

    /// All current entries.
    ///
    /// # Order
    ///
    /// The order is **not guaranteed**, because the core indexes entries with a
    /// hash table. The host side must sort the list itself (by name, by creation
    /// time, and so on) and must not rely on this order being stable.
    #[must_use]
    pub fn entries(&self) -> Vec<FfiVaultEntry> {
        self.lock()
            .vault()
            .iter()
            .map(|(id, entry)| FfiVaultEntry::from_core(id, entry))
            .collect()
    }

    /// Returns one entry by identifier. `None` when it does not exist.
    #[must_use]
    pub fn entry(&self, id: String) -> Option<FfiVaultEntry> {
        let id = parse_entry_id(&id).ok()?;
        self.lock()
            .vault()
            .get(&id)
            .map(|entry| FfiVaultEntry::from_core(&id, entry))
    }

    /// Adds an entry and returns its identifier.
    ///
    /// `now` is Unix seconds, **supplied by the host side** — the core does not
    /// read a clock.
    pub fn add_entry(&self, entry: FfiVaultEntry, now: u64) -> Result<String, FfiError> {
        flow::check_now(now)?;
        let core = entry.to_core(now)?;
        let id = self.lock().vault_mut().insert(core)?;
        Ok(id.to_string())
    }

    /// Modifies an existing entry.
    ///
    /// Returns [`Error::VaultEntryNotFound`] (`kind` is `vault_entry_not_found`)
    /// when the identifier is not found.
    ///
    /// # The identifier is preserved
    ///
    /// The identifier is the only thing by which devices refer to "the same
    /// entry": changing it reads as one deletion plus one insertion during sync,
    /// which misplaces that entry's history and tombstone on other devices.
    /// Modification must therefore **keep the identifier**.
    ///
    /// So this takes out the old entry, replaces its content and puts it back
    /// under the **same** identifier. The creation time is preserved as well: it
    /// records when the user added the entry, and letting it change would make
    /// the user interface reorder rows.
    pub fn update_entry(&self, entry: FfiVaultEntry, now: u64) -> Result<(), FfiError> {
        flow::check_now(now)?;
        let id = entry.parse_id()?;
        let mut core = entry.to_core(now)?;
        let mut vault = self.lock();
        let created_at = vault
            .vault()
            .get(&id)
            .ok_or(Error::VaultEntryNotFound)?
            .created_at;
        core.created_at = created_at;
        vault.vault_mut().replace(id, core)?;
        Ok(())
    }

    /// Deletes an entry, leaving a tombstone.
    ///
    /// Returns whether an entry was deleted (`false` means the identifier did
    /// not exist).
    ///
    /// # A tombstone is how deletion is recorded
    ///
    /// Erasing the record outright would make another device bring the entry
    /// **back** at the next sync, since it does not know about the deletion
    /// here. The tombstone is the fact "this entry was deleted" and travels with
    /// the entries.
    pub fn remove_entry(&self, id: String, now: u64) -> Result<bool, FfiError> {
        flow::check_now(now)?;
        let id = parse_entry_id(&id)?;
        Ok(self.lock().vault_mut().remove(&id, now).is_some())
    }

    /// Serializes into vault file bytes for the host side to persist.
    ///
    /// The host side should write the file **atomically** (write a temporary
    /// file, then rename) rather than overwrite in place: losing power halfway
    /// leaves a file that cannot be opened, and the user's only copy of the data
    /// is inside it. The core provides `vault::write_file_atomically`, but it
    /// performs I/O and is not part of this library's exported surface.
    pub fn serialize(&self) -> Result<Vec<u8>, FfiError> {
        Ok(self.lock().serialize()?)
    }

    /// Computes the current code for one entry.
    ///
    /// `unix_time` is supplied by the host side (the core does not read a
    /// clock). Use [`FfiVault::hotp_for`] for HOTP entries.
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

    /// Computes the code for one HOTP entry at the given counter.
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

    /// Computes the Steam Guard code for one entry (5 characters, custom
    /// alphabet).
    pub fn steam_guard_for(&self, id: String, unix_time: u64) -> Result<String, FfiError> {
        self.code_for(&id, |entry| {
            otp::steam_guard_code(&entry.secret, unix_time, entry.period, entry.algorithm)
        })
    }

    /// Exports a recovery key file protected by a passphrase.
    ///
    /// # KDF parameters
    ///
    /// Passing `None` for `memory_kib` / `iterations` / `parallelism` uses the
    /// core defaults (64 MiB / 3 iterations / 1 lane). The host side **must
    /// not** lower them for speed: the export cost is paid once, whereas an
    /// attacker who obtains the file attacks it offline, so lower parameters
    /// weaken the last line of defence directly.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RecoveryParametersInvalid`] (`kind` is
    /// `recovery_parameters_invalid`) when the parameters fall outside the range
    /// the core allows (memory at most 1 GiB, at most 1000 iterations). **Both
    /// bounds are checked**, because the parameters can come from the host
    /// side's sliders and from **someone else's** file.
    ///
    /// # Handling the return value
    ///
    /// The caller receives **encrypted** file bytes, not the master key. The
    /// host side should only write them to a location the user chose or show
    /// them as a QR code for the user to copy down, and should keep them out of
    /// the clipboard history. The passphrase itself is not part of the return
    /// value and must not be persisted by the host side.
    pub fn export_recovery_key(
        &self,
        passphrase: String,
        memory_kib: Option<u64>,
        iterations: Option<u64>,
        parallelism: Option<u64>,
    ) -> Result<Vec<u8>, FfiError> {
        check_len("passphrase", &passphrase, MAX_PASSPHRASE_CHARS)?;
        let params = kdf_params(memory_kib, iterations, parallelism)?;
        let vault = self.lock();
        Ok(flow::export_recovery_key(
            vault.master_key(),
            &SecretString::from(passphrase),
            Some(params),
        )?)
    }
}

impl FfiVault {
    /// Takes the lock, ignoring poisoning.
    ///
    /// Poisoning means a thread panicked while holding the lock. The data
    /// structure's **invariants** still hold at that point (this lock guards
    /// hash-table insert and remove, which have no half-modified intermediate
    /// state), so recovering is preferable to failing every later call, which
    /// would leave the user unable to read or write entries at all.
    fn lock(&self) -> std::sync::MutexGuard<'_, VaultFile> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Computes the three derived fields of an entry.
    ///
    /// It does not return `&Entry`: entries live behind the `MutexGuard`, which
    /// is released when the function returns, so a borrow cannot escape. The
    /// core's `OtpSecret` deliberately does not implement `Clone`, so this
    /// **computes the code and returns the string** rather than copying the
    /// entry or the secret out.
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

/// Opens a vault with the master key held by an [`FfiVault`].
///
/// # The return value is a byte string, not a printable short code
///
/// The recovery key file is designed so that a user can copy it onto paper or
/// into a QR code. It is **not** the master key: the master key inside it is
/// encrypted under a key derived from the user passphrase with Argon2id (see the
/// core `recovery` module). Returning `Vec<u8>` is therefore safe, but the host
/// side should still keep it out of logs and the clipboard history.
///
/// # Relation to [`FfiVault::export_recovery_key`]
///
/// Both do the same thing; only the source of the master key differs:
///
/// - [`FfiVault::export_recovery_key`]: the device is **already unlocked** and the
///   master key is on the Rust side. Prefer that path — the master key does not
///   cross the boundary at all.
/// - this function: the caller only holds master key bytes (for example just
///   obtained from [`FfiJoiner::complete`], before a vault exists). The master
///   key crosses the boundary once here.
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

/// Recovers the master key from a recovery key file with a passphrase and
/// **writes it into the platform key store**.
///
/// The write goes through the core `SecureStore` abstraction, so this path and
/// login share the same ordering guarantees at the storage step.
///
/// Returns the 32 bytes of the master key. The host side either passes them to
/// [`FfiSecureStore::store_master_key`] or drops them, since this function has
/// already written the store once; building an [`FfiVault`] from the returned bytes
/// avoids a second key-store read, which is a hardware access that prompts for
/// biometrics on some platforms.
///
/// # Errors
///
/// A wrong passphrase returns [`Error::RecoveryAuthenticationFailed`] (`kind` is
/// `recovery_authentication_failed`); a malformed file returns
/// [`Error::RecoveryFileMalformed`]; out-of-range parameters return
/// [`Error::RecoveryParametersInvalid`].
///
/// **A wrong passphrase and a damaged file must be distinguished**: the first
/// asks the user to type it again, the second reports that the file is unusable.
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

/// Writes a master key into the platform key store.
///
/// For use by the host side after [`FfiJoiner::complete`], which returns master
/// key bytes and leaves the timing of the store write to the host side. This is
/// a separate step rather than something `complete` does itself, because
/// "login finished" and "key saved" are two actions in a user interface.
///
/// # Errors
///
/// Returns [`Error::MasterKeyWrongLength`] when the key length is not 32 bytes.
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

// ── Login: initiator and joiner ──────────────────────────────────────────

/// The initiator of a login: a device that is **already logged in** and holds
/// the master key.
///
/// It displays the QR code, receives the request and hands the master key to the
/// other device in encrypted form.
///
/// # One login serves exactly one request
///
/// The core enforces this with the **type system** (`authorize` consumes the
/// pending session), so a second call necessarily fails and the host side needs
/// no flag of its own. All the host side does is keep one QR code per
/// [`FfiLogin`] instance and drop it after a successful authorization.
///
/// # Replay protection across restarts
///
/// The core's `Login` guarantees single use within one process. Keeping replay
/// protection across application restarts would require persisting used session
/// identifiers and restoring them at the next login. **This layer does not expose
/// that path**: the core's `NonceLog` has no serialization entry point, so
/// cross-restart protection is presently unreachable.
///
/// That is not a gap for the current protocol: a pending session itself does not
/// survive a restart (it contains an ephemeral private key that the host side
/// cannot write to disk), so there is nothing to replay.
#[derive(uniffi::Object)]
pub struct FfiLogin {
    /// The core initiator state.
    inner: std::sync::Mutex<Login>,
}

#[uniffi::export]
impl FfiLogin {
    /// Starts a login and returns the text to display as a QR code.
    #[uniffi::constructor]
    pub fn begin() -> Result<Arc<Self>, FfiError> {
        Ok(Arc::new(Self {
            inner: std::sync::Mutex::new(Login::new()?),
        }))
    }

    /// The text to display as a QR code.
    ///
    /// This is the **only** channel that has to be shown to the other device. It
    /// contains no master key (see the module documentation of the core
    /// `pairing`), but it is the credential for this session, so it must not be
    /// sent to a chat log or shared as a screenshot.
    pub fn payload(&self) -> String {
        self.lock().payload().to_base32()
    }

    /// Accepts the request the other device sends after scanning the QR code and
    /// returns the reply bytes to send back.
    ///
    /// # Authorization is user confirmation
    ///
    /// The moment this function is called, the master key is encrypted and handed
    /// to the other device. The host side **must** therefore obtain user
    /// confirmation before calling it (for example by asking whether the user
    /// really started a login on a new device). The core cannot make that
    /// decision for the host side, and should not.
    ///
    /// # Errors
    ///
    /// A request that did not come from this session, tampered ciphertext, and a
    /// login that has already been authorized all return
    /// [`Error::PairingAuthenticationFailed`]. **The reason is deliberately not
    /// split further**, so that an attacker gains no oracle distinguishing "almost
    /// succeeded"; host-side text should stay generic as well.
    pub fn authorize(&self, vault: Arc<FfiVault>, msg1: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        let vault = vault.lock();
        let mut login = self.lock();
        Ok(login.authorize(&msg1, vault.master_key())?)
    }

    /// The device identifier declared by the requester (a value exists only after
    /// a successful authorization).
    pub fn joiner_device_id(&self) -> Option<String> {
        self.lock().joiner_device().map(|id| id.to_hex())
    }
}

impl FfiLogin {
    /// Takes the lock, ignoring poisoning (see [`FfiVault::lock`]).
    fn lock(&self) -> std::sync::MutexGuard<'_, Login> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The joiner of a login: a new device that does not have the master key yet.
///
/// # The lifecycle is scan → request → reply → complete
///
/// The request must be issued and completed by the **same** object: the session
/// identifier is determined by this session's ephemeral key, so a different
/// object means a different session and the reply cannot be opened. The core
/// expresses this in the type system (`request` borrows `&self` instead of
/// consuming it, and only `complete` consumes), so as long as the host side does
/// not rebuild the object the behavior is right.
#[derive(uniffi::Object)]
pub struct FfiJoiner {
    /// The core joiner state.
    inner: std::sync::Mutex<Joiner>,
}

#[uniffi::export]
impl FfiJoiner {
    /// Establishes a session from the scanned QR code text. `label` is the label
    /// of this device's identity in the platform key store.
    ///
    /// This step does not send the request; the core keeps `new` and `request` as
    /// two steps and this layer keeps the same granularity. Sending the request
    /// needs the device identity, and obtaining it prompts for biometrics on some
    /// platforms, so the host side can tell the user that a local key is about to
    /// be created first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PairingPayloadMalformed`] when the text is not a valid QR
    /// payload. Note that "not a valid payload" and "valid payload but a
    /// mismatched session" are two different things; the latter only surfaces at
    /// [`FfiJoiner::complete`].
    #[uniffi::constructor]
    pub fn from_qr(text: String, label: String) -> Result<Arc<Self>, FfiError> {
        check_len("qr", &text, MAX_QR_TEXT_CHARS)?;
        check_len("label", &label, MAX_LABEL_CHARS)?;
        Ok(Arc::new(Self {
            inner: std::sync::Mutex::new(Joiner::from_base32(&text, &label)?),
        }))
    }

    /// The request bytes to send to the initiator. **Idempotent**: repeated calls
    /// return the same message and do not sign again.
    ///
    /// Signing again would produce a new session identifier and the initiator
    /// would no longer recognize it as the same login, so idempotence is a
    /// correctness requirement rather than an optimization.
    pub fn request(&self, keys: Arc<dyn FfiDeviceKeys>) -> Result<Vec<u8>, FfiError> {
        let mut keys = ForeignDeviceKeys(keys);
        let mut joiner = self.lock();
        Ok(joiner.request(&mut keys)?)
    }

    /// The device identity this device declares in this session (SEC1
    /// uncompressed encoding, 65 bytes).
    ///
    /// The initiator should display it together with
    /// [`FfiLogin::joiner_device_id`] for the user to confirm, so that the user
    /// can tell whether the requesting device is the expected one. Returns `None`
    /// after completion.
    #[must_use]
    pub fn identity(&self) -> Option<Vec<u8>> {
        self.lock().identity().map(|bytes| bytes.to_vec())
    }

    /// Completes the login with the initiator's reply: verifies the reply, takes
    /// out the master key and **writes it into the platform key store**.
    ///
    /// Returns the 32 bytes of the master key so that the host side can build an
    /// [`FfiVault`] right away with [`FfiVault::from_master_key`] instead of
    /// reading the key store again; every read is another hardware access that
    /// prompts for biometrics on some platforms.
    ///
    /// # This is where the reply is actually verified
    ///
    /// Decryption and authentication of the reply happen here, not in
    /// [`FfiJoiner::from_qr`]. A login failure is therefore only trustworthy from
    /// this function.
    ///
    /// # Single use
    ///
    /// The core's session is single use (`complete` takes it internally), so a
    /// second call returns [`Error::PairingAuthenticationFailed`] and **not** a
    /// different error from a forged reply. Reporting "already used" separately
    /// would tell an attacker that the replay was detected.
    ///
    /// # Errors
    ///
    /// A reply from another session, tampered ciphertext, an initiator using a
    /// different master key, and a completed login all return
    /// [`Error::PairingAuthenticationFailed`]. A failure to write the master key
    /// into the platform store returns [`Error::SecureStoreWriteFailed`]; in that
    /// case **the master key is left nowhere** and the host side should have the
    /// user log in again.
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
    /// Takes the lock, ignoring poisoning (see [`FfiVault::lock`]).
    fn lock(&self) -> std::sync::MutexGuard<'_, Joiner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

// ── Challenge-response: proving possession of the master key ─────────────
//
// This section has **three messages**, and their direction is the opposite of
// the usual "request/response":
//
// 1. verifier → responder: the challenge (`FfiVerifier::challenge` →
//    `FfiResponder::accept`)
// 2. responder → verifier: the response (`FfiResponder::respond` →
//    `FfiVerifier::verify`)
// 3. verifier → responder: the confirmation tag (`FfiVerifier::session_id` and
//    `FfiVerifier::confirmation` → `FfiResponder::confirm`)
//
// The third step is easy to omit, and it is the proof in the **opposite**
// direction: the responder uses it to confirm that the party answering really
// is the verifier that sent the challenge. With only the first two steps,
// anyone can send a challenge and then pretend to have verified it.

/// The verifier: confirms that the other side actually holds the master key.
///
/// # Where it is used
///
/// 1. **Confirming a successful unlock.** A version 2 vault file already tells
///    whether the master key is right (see [`FfiVault::open`]), so this path
///    mainly serves **old version 1 files** and the case of having only a master
///    key and no file yet.
/// 2. **Cross-device identity confirmation.** It does not depend on file
///    content, so it is the only proof available when the file is missing or
///    damaged.
///
/// # Difference from pairing
///
/// Pairing hands the master key to the other side; challenge-response proves
/// possession of the master key without handing it over. The former happens once
/// at login, the latter at any time. **Challenge-response is not login**: it
/// transfers no key.
#[derive(uniffi::Object)]
pub struct FfiVerifier {
    /// The core verifier state. `verify` consumes it, hence the `Option`.
    inner: std::sync::Mutex<Option<auth::Verifier>>,
    /// The challenge bytes to send in the first step.
    challenge: Vec<u8>,
    /// The session identifier computed after the second step, sent back to the
    /// other side in the third step.
    session_id: std::sync::Mutex<Option<[u8; AUTH_SESSION_ID_LEN]>>,
    /// The confirmation tag computed after the second step, sent back to the
    /// other side in the third step.
    confirmation: std::sync::Mutex<Option<[u8; AUTH_CONFIRM_LEN]>>,
}

#[uniffi::export]
impl FfiVerifier {
    /// Starts a challenge.
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

    /// The challenge bytes to send to the other side.
    #[must_use]
    pub fn challenge(&self) -> Vec<u8> {
        self.challenge.clone()
    }

    /// Verifies the other side's response and returns `true` on success.
    ///
    /// Failure returns [`Error::AuthProofFailed`] (`kind` is `auth_proof_failed`);
    /// **do not** read anything else into it: this error is produced only when a
    /// tag does not match.
    ///
    /// # Single use
    ///
    /// The challenge is single use (the core's `verify` consumes `self`). A
    /// repeated verification returns [`Error::AuthProofFailed`] — the same error
    /// as a forged response, for the reason given at [`FfiJoiner::complete`]: no
    /// distinguishing signal for a replayer.
    ///
    /// # The third step follows a success
    ///
    /// After receiving `true`, the host side must send
    /// [`FfiVerifier::session_id`] and [`FfiVerifier::confirmation`] back to the
    /// other side, which verifies them with [`FfiResponder::confirm`]. **Omitting
    /// the third step leaves the authentication half done**: the responder has no
    /// way to confirm that the party answering really is the verifier.
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

    /// The session identifier to send back in the third step. `None` before a
    /// successful verification.
    #[must_use]
    pub fn session_id(&self) -> Option<Vec<u8>> {
        self.session_id
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .map(|id| id.to_vec())
    }

    /// The confirmation tag to send back in the third step. `None` before a
    /// successful verification.
    #[must_use]
    pub fn confirmation(&self) -> Option<Vec<u8>> {
        self.confirmation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .map(|tag| tag.to_vec())
    }
}

/// The responder: holds the master key and proves it to the verifier.
#[derive(uniffi::Object)]
pub struct FfiResponder {
    /// The core responder state.
    inner: std::sync::Mutex<auth::Responder>,
}

#[uniffi::export]
impl FfiResponder {
    /// Accepts a challenge sent by the other side.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AuthMessageMalformed`] when the challenge is malformed
    /// (length, version, or an ephemeral public key that is not on the curve).
    #[uniffi::constructor]
    pub fn accept(challenge: Vec<u8>) -> Result<Arc<Self>, FfiError> {
        Ok(Arc::new(Self {
            inner: std::sync::Mutex::new(auth::accept(&challenge)?),
        }))
    }

    /// The device identity this device uses in this session (SEC1 uncompressed
    /// encoding, 65 bytes).
    #[must_use]
    pub fn identity(&self) -> Vec<u8> {
        self.lock().public_key().to_vec()
    }

    /// Produces the response to hand to the verifier.
    ///
    /// Signing goes through [`FfiDeviceKeys::sign`] and **receives the raw
    /// message**; the host-side implementation must not hash it first, since the
    /// core verifies with the standard ECDSA hash mode and hashing twice makes
    /// every verification fail.
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
        let response =
            responder.respond(vault.master_key(), device.as_sec1_bytes(), |message| {
                keys.sign(&label, message)
            })?;
        Ok(response)
    }

    /// Verifies the confirmation tag sent back by the verifier (the third step).
    ///
    /// Returns `true` on success. **This step must not be skipped**: it proves
    /// that the other side can actually compute the session key rather than only
    /// forwarding a challenge.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AuthProofFailed`] when the tag does not match or the
    /// session identifier does not match, and [`Error::AuthMessageMalformed`]
    /// when the tag length is wrong.
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
    /// Takes the lock, ignoring poisoning.
    fn lock(&self) -> std::sync::MutexGuard<'_, auth::Responder> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Builds [`KdfParams`] from the optional host-side values.
///
/// The values come from the host side (the user can adjust them in the user
/// interface) and, on import, from a file that is attacker controlled. The range
/// check lives in the core's `KdfParams::new`, which bounds both ends; this
/// function passes its error through rather than judging on its own, so there is a
/// single implementation of the check.
///
/// The host side passes `u64` rather than the core's `u32`: UniFFI maps `u32` to
/// an unsigned type on the Kotlin side, which Kotlin does not have natively. A
/// value above `u32` is rejected by the core's range check and is never silently
/// truncated.
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
        let chinese = "中".repeat(MAX_SECRET_CHARS);
        match secret_byte_len(chinese) {
            Err(FfiError::InputTooLong { .. }) => panic!("按字符计不该触发上限"),
            Err(FfiError::Core { .. }) => {}
            Ok(_) => panic!("非 Base32 输入不该解析成功"),
        }
    }

    #[test]
    fn hotp_matches_rfc4226_through_ffi() {
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

    // ── Registration, login, recovery, challenge-response ────────────

    /// A device identity for tests: keys are derived deterministically from the
    /// label.
    ///
    /// Determinism keeps "the same device" consistent between calls, as a real
    /// platform key store does (the same label returns the same key). With true
    /// randomness, the property "getting the same label again returns the same
    /// key" could not be verified.
    #[derive(Default)]
    struct TestKeys {
        keys: std::sync::Mutex<std::collections::HashMap<String, p256::ecdsa::SigningKey>>,
    }

    impl TestKeys {
        /// Returns or creates the signing key for a label.
        fn key_for(&self, label: &str) -> p256::ecdsa::SigningKey {
            let mut keys = self.keys.lock().expect("测试中无并发中毒");
            keys.entry(label.to_owned())
                .or_insert_with(|| {
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

    /// A platform key store for tests: keeps the master key in memory.
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
            false
        }
    }

    /// A minimal usable entry.
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

    /// An **empty** vault must also tell whether the master key is right.
    ///
    /// This covers the gap that format version 2 closes: in version 1 the master
    /// key only took part in the AEAD of each record, and an empty file has no
    /// records, so any 32-byte key opened it and the user interface showed
    /// "unlocked" for a wrong key.
    ///
    /// The observable behavior for the host side is that `FfiVault.open` rejects a
    /// wrong master key even for a file with **no entries at all**, so "the open
    /// succeeded" can be taken as "unlocked" directly.
    #[test]
    fn an_empty_vault_rejects_a_wrong_master_key() {
        let store_a = Arc::new(TestStore::default());
        let vault_a = FfiVault::register(
            Arc::new(TestKeys::default()),
            store_a,
            "device-a".to_owned(),
        )
        .expect("注册应当成功");
        assert!(vault_a.is_empty(), "前提：这个保险库确实是空的");
        let data = vault_a.serialize().expect("应当能序列化");

        let store_b = Arc::new(TestStore::default());
        FfiVault::register(
            Arc::new(TestKeys::default()),
            store_b.clone(),
            "device-b".to_owned(),
        )
        .expect("注册应当成功");

        let error = FfiVault::open(store_b, data)
            .err()
            .expect("空保险库用错误密钥必须被拒");
        assert_eq!(
            error.kind(),
            "vault_decryption_failed",
            "必须是「解不开」，而不是「没注册」——两者的界面动作完全不同"
        );
    }

    /// A registered vault accepts entries, computes codes, and can be serialized
    /// and opened again.
    ///
    /// This follows the most common host-side path: register → add entry →
    /// persist → reopen → read a code.
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

    /// Updating an entry must not change its identifier and must not leave a
    /// tombstone.
    ///
    /// A changed identifier reads as one deletion plus one insertion during sync,
    /// and a tombstone reads as "this entry was deleted"; both cause a visible
    /// error on another device.
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

    /// A **nonexistent** identifier must be reported separately by update and by
    /// removal.
    ///
    /// Collapsing the two would show an empty list where the user was just
    /// looking at an entry.
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

        assert!(
            !vault.remove_entry("0".repeat(32), NOW).expect("应当能调用"),
            "删除不存在的条目应当返回 false"
        );
        assert_eq!(vault.entry_count(), 0);
    }

    /// Logging in hands the master key to the new device unchanged, so the new
    /// device can open the old device's vault.
    ///
    /// Asserting only "no error" is not enough: an implementation that replaced
    /// the master key with a fresh random value reports no error either.
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

        let login = FfiLogin::begin().expect("应当能开始登录");
        let joiner_keys = Arc::new(TestKeys::default());
        let joiner =
            FfiJoiner::from_qr(login.payload(), "device-b".to_owned()).expect("应当能建立会话");
        let request = joiner.request(joiner_keys.clone()).expect("应当能发出请求");
        let reply = login
            .authorize(old_vault.clone(), request)
            .expect("应当能授权");
        let joiner_store = Arc::new(TestStore::default());
        let master = joiner
            .complete(reply, joiner_keys, joiner_store.clone())
            .expect("应当能完成登录");

        assert_eq!(master.len(), 32, "主密钥是 32 字节");
        assert!(
            joiner_store.master.lock().expect("无中毒").is_some(),
            "主密钥必须已经写入新设备的平台存储"
        );

        let new_vault = FfiVault::open(joiner_store, data).expect("新设备应当能打开老设备的保险库");
        assert_eq!(new_vault.entry_count(), 1, "老设备的那一条应当可见");
    }

    /// A login can be completed only once, and the second attempt reports the
    /// same error as a forged reply.
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

    /// A recovery key file restores the same master key.
    #[test]
    fn a_recovery_file_restores_the_same_master_key() {
        let keys = Arc::new(TestKeys::default());
        let store = Arc::new(TestStore::default());
        let vault = FfiVault::register(keys, store, "device-a".to_owned()).expect("注册应当成功");
        vault
            .add_entry(sample_entry("GitHub"), NOW)
            .expect("应当能添加条目");
        let data = vault.serialize().expect("应当能序列化");

        let file = vault
            .export_recovery_key("correct horse".to_owned(), Some(8), Some(1), Some(1))
            .expect("应当能导出");

        let new_store = Arc::new(TestStore::default());
        let restored =
            import_recovery_key(file.clone(), "correct horse".to_owned(), new_store.clone())
                .expect("应当能导入");
        assert_eq!(restored.len(), 32);

        let reopened = FfiVault::open(new_store, data).expect("应当能打开");
        assert_eq!(reopened.entry_count(), 1);

        let wrong = import_recovery_key(
            file,
            "wrong passphrase".to_owned(),
            Arc::new(TestStore::default()),
        )
        .expect_err("口令错误应当失败");
        assert_eq!(wrong.kind(), "recovery_authentication_failed");
    }

    /// All three steps of the challenge-response must work, with the master key
    /// staying inside the boundary.
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

        let session_id = verifier.session_id().expect("校验之后应当有会话标识");
        let confirmation = verifier.confirmation().expect("校验之后应当有确认标签");
        assert!(
            responder
                .confirm(vault, session_id, confirmation)
                .expect("应当能确认"),
            "第三步应当通过"
        );
    }

    /// Challenge-response is single use, like pairing.
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

    /// Every kind is unique, and none of them falls into `"unknown"`.
    ///
    /// `core_error_kind` ends with a `_ => "unknown"` fallback (the core `Error` is
    /// marked `non_exhaustive`, so that arm is required). The compiler therefore
    /// **does not warn about a newly added core variant**; this test is the
    /// reminder: a variant missing from the mapping shows up here as `"unknown"`.
    #[test]
    fn every_mapped_error_kind_is_distinct_and_known() {
        let kinds = [
            core_error_kind(&Error::SecretEmpty),
            core_error_kind(&Error::VaultTruncated),
            core_error_kind(&Error::VaultCorrupt),
            core_error_kind(&Error::VaultDecryptionFailed),
            core_error_kind(&Error::VaultEntryNotFound),
            core_error_kind(&Error::VaultBadKeyCheck),
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
