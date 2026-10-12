// Copyright (C) 2026 Qualia2FA contributors
//
// This library is free software; you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation; either version 3 of the License, or (at your option) any
// later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
// details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library; if not, see <https://www.gnu.org/licenses/>.

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

use qualia_dik::keystore::PlatformKeyStore;
use qualia_dik::{DeviceKeyStore, DevicePublicKey, DeviceSignature, DeviceSigner};
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
            FfiError::Qr { kind, .. } => kind,
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
    #[error("input too long: {kind} limit is {limit} characters, got {actual} characters")]
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

    /// An error from the transport layer behind the code channel.
    ///
    /// Kept separate from [`FfiError::Core`] because it is a different layer with a
    /// different set of failure modes: a payload that will not fit, an image with no code
    /// in it, an image whose buffer does not match its dimensions. The message never
    /// carries a payload.
    #[error("{message}")]
    Qr {
        /// Stable kind for the host to branch on, in `snake_case`.
        kind: String,
        /// Human-readable message. Never contains a payload or a secret.
        message: String,
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
// The code channel: turning text into a QR code and back
// ═══════════════════════════════════════════════════════════════════════════

/// A rendered QR code, as pixels the host can draw.
///
/// The pixels are **grayscale**, one byte per pixel, `0` for black and `255` for white.
#[derive(Clone, uniffi::Record)]
pub struct FfiQrImage {
    /// Image width in pixels.
    pub width: u32,
    /// Image height in pixels.
    pub height: u32,
    /// Grayscale pixels, row major, `width * height` bytes.
    pub pixels: Vec<u8>,
}

impl core::fmt::Debug for FfiQrImage {
    /// Prints the dimensions only: the pixels are the code, and during pairing the code
    /// carries session material that must not reach a log or a panic message.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FfiQrImage")
            .field("width", &self.width)
            .field("height", &self.height)
            .finish_non_exhaustive()
    }
}

/// The error correction level of a code, named by what it survives.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum FfiEcLevel {
    /// About 7% of the code may be damaged.
    Low,
    /// About 15%.
    Medium,
    /// About 25%.
    Quartile,
    /// About 30%.
    High,
}

impl From<FfiEcLevel> for qualia_transport::qr::EcLevel {
    fn from(value: FfiEcLevel) -> Self {
        match value {
            FfiEcLevel::Low => Self::Low,
            FfiEcLevel::Medium => Self::Medium,
            FfiEcLevel::Quartile => Self::Quartile,
            FfiEcLevel::High => Self::High,
        }
    }
}

/// Encodes `text` into a single QR code and renders it as grayscale pixels.
///
/// `scale` is how many pixels one module becomes, `quiet_zone` how many modules of
/// margin surround the code. Text that does not fit in `max_version` is an error: the
/// code is never truncated, and the error correction level is not silently lowered.
///
/// # Errors
///
/// Returns [`FfiError::Qr`] with kind `payload_too_large` when the text does not fit, and
/// `bad_render_geometry` when `scale` or `quiet_zone` is zero.
#[uniffi::export]
pub fn qr_encode(
    text: String,
    ec_level: FfiEcLevel,
    max_version: u8,
    scale: u16,
    quiet_zone: u16,
) -> Result<FfiQrImage, FfiError> {
    let profile =
        qualia_transport::qr::QrProfile::new(ec_level.into(), max_version).map_err(qr_error)?;
    let symbol = profile.encode_payload(text.as_bytes()).map_err(qr_error)?;
    let image = symbol.render(scale, quiet_zone).map_err(qr_error)?;
    Ok(FfiQrImage {
        width: image.width(),
        height: image.height(),
        pixels: image.pixels().to_vec(),
    })
}

/// Reads the text back out of a grayscale image.
///
/// The text is carried inside the transport's own envelope (`Q2FA1:<index>/<count>:<BASE32>`),
/// which is what a code drawn by [`qr_encode`] contains and what any scanner sees; this
/// function unwraps it so the caller gets back the text it encoded.
///
/// The input is **pixels, not an image file**: decoding the file format belongs to the
/// platform (`ImageIO` on the JVM, `BitmapFactory` on Android, `UIImage` on iOS), because
/// format decoders are where the historical vulnerabilities live. The host converts an
/// imported image to grayscale and hands the result here.
///
/// # Errors
///
/// Returns [`FfiError::Qr`] with kind `bad_image_geometry` when the buffer does not match
/// the dimensions, `not_our_qr_text` when the code is not this application's, `no_qr_found`
/// when there is no code in the image, and `qr_decoder_panicked` when the decoder hit the
/// assertion that degenerate images trigger. That last one is contained rather than fixed:
/// the panic is caught here, and the fix belongs upstream.
#[uniffi::export]
pub fn qr_decode(pixels: Vec<u8>, width: u32, height: u32) -> Result<String, FfiError> {
    let image =
        qualia_transport::image::GrayImage::from_luma8(width, height, pixels).map_err(qr_error)?;
    let payload = qualia_transport::qr::scan::decode_payload(&image).map_err(qr_error)?;
    String::from_utf8(payload).map_err(|_| FfiError::Qr {
        kind: "payload_not_utf8".to_owned(),
        message: "the code carried bytes that are not UTF-8 text".to_owned(),
    })
}

/// Reduces a transport error to a kind and a message, without the payload.
///
/// The transport error is `#[non_exhaustive]`, so the wildcard arm is required by the
/// compiler rather than optional; a new variant therefore lands in `qr_error` until it is
/// mapped, which is what the host sees as an unnamed failure. Its own test pins the kinds
/// that matter.
fn qr_error(source: qualia_transport::Error) -> FfiError {
    use qualia_transport::Error as QrError;

    let kind = match &source {
        QrError::PayloadTooLarge { .. } => "payload_too_large",
        QrError::TooManyFrames { .. } => "too_many_frames",
        QrError::NotOurQrText => "not_our_qr_text",
        QrError::MalformedFrameHeader => "malformed_frame_header",
        QrError::MultiFrameUnsupported { .. } => "multi_frame_unsupported",
        QrError::UnknownEcLevel { .. } => "unknown_ec_level",
        QrError::VersionOutOfRange { .. } => "version_out_of_range",
        QrError::BadRenderGeometry { .. } => "bad_render_geometry",
        QrError::BadImageGeometry { .. } => "bad_image_geometry",
        QrError::NoQrFound => "no_qr_found",
        QrError::QrDecoderPanicked => "qr_decoder_panicked",
        QrError::QrNotText => "qr_not_text",
        _ => "qr_error",
    };

    FfiError::Qr {
        kind: kind.to_owned(),
        message: source.to_string(),
    }
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
        // Neither of the boundary's own errors can arrive from a host callback: the code
        // channel is called from the host, not into it. They degrade the same way as any
        // other error that has no core equivalent.
        FfiError::InputTooLong { .. } | FfiError::Qr { .. } => Error::DeviceKeyMissing,
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
            reason: "signing failed on the client side",
        }),
        "secure_store_write_failed" => Error::SecureStoreWriteFailed {
            reason: "the client key store refused the write",
        },
        _ => Error::DeviceKeyMissing,
    }
}

/// The device identity key store of the current platform, exported to the host
/// side.
///
/// # What this object is for
///
/// [`FfiDeviceKeys`] is a **foreign** trait: the host side implements it. The
/// implementation that really exists — create a P-256 key inside the platform
/// key store, read its public key, sign with it — lives in `qualia-dik`, so a
/// host-side implementation of that trait would only forward. This object is
/// that forwarding, written once in Rust: the host side calls the methods below
/// and writes no key-store code of its own.
///
/// # Contract: the byte formats of [`FfiDeviceKeys`]
///
/// - [`FfiPlatformKeys::device_public_key`] returns the 65-byte SEC1
///   uncompressed point `0x04 || X(32) || Y(32)`, the encoding
///   [`FfiDeviceKeys::get_or_create`] has to return.
/// - [`FfiPlatformKeys::sign`] takes the **raw message** and returns the 64-byte
///   raw `r‖s`, the convention [`FfiDeviceKeys::sign`] has to follow.
///
/// # The backend is reported as it is
///
/// [`FfiPlatformKeys::backend`] and [`FfiPlatformKeys::is_hardware_backed`]
/// report the backend **actually in use**. Opening prefers the TPM and falls back
/// to the operating system software key store only when there is no TPM, and the
/// fallback stays visible: such a machine reports `"software"` and `false`.
/// Reporting a software key as hardware-protected would tell the user that a
/// private key which can be copied off the disk is held by hardware.
///
/// # No signer is kept between calls
///
/// `qualia-dik` hands out a signer as `Box<dyn DeviceSigner>`, and that trait is
/// neither `Send` nor `Sync`: a platform key handle is not thread safe, and the
/// library's Windows backend documents the intended pattern as one handle per
/// thread rather than one handle shared between threads. A UniFFI object must be
/// `Send + Sync`, so no handle is stored here. Every method opens the identity
/// under this object's label again, which is the pattern the platform backend
/// asks for; the label itself is created once, by [`FfiPlatformKeys::open`].
///
/// # This type does not implement `Debug`
///
/// Deriving it would delegate to the key store's own `Debug`, whose output is an
/// implementation detail rather than part of this interface, and the object sits
/// next to platform key material. Nothing in this crate needs it.
///
/// # Current state
///
/// Windows is the only platform with a backend implementation. On every other
/// platform [`FfiPlatformKeys::open`] fails with an error naming that platform;
/// there is **no** fallback to a software key.
#[derive(uniffi::Object)]
pub struct FfiPlatformKeys {
    /// Key store of the current platform, opened on the best available backend.
    store: PlatformKeyStore,
    /// Label of the device identity this object manages.
    label: String,
}

#[uniffi::export]
impl FfiPlatformKeys {
    /// Opens the best available platform backend and the identity stored under
    /// `label`, creating that identity when it does not exist yet.
    ///
    /// "Best available" is the platform's choice, not this layer's: on Windows
    /// the TPM 2.0 provider is preferred and the software key store is used only
    /// when no TPM is available. Which one was chosen is reported by
    /// [`FfiPlatformKeys::backend`], so the host side can tell the user before
    /// relying on the identity.
    ///
    /// # One label is one identity for the lifetime of the device
    ///
    /// The label is the only handle the platform key store has, so opening the
    /// same label again returns the same identity and never creates a second key.
    ///
    /// # The signer handle returned by the key store is dropped
    ///
    /// Creating the identity is what this call is for; see [`FfiPlatformKeys`]
    /// for why the platform handle is not kept between calls.
    ///
    /// # Errors
    ///
    /// [`FfiError::InputTooLong`] when the label is longer than the boundary
    /// limit; otherwise a [`FfiError::Core`] error: this machine has no usable
    /// platform key store, this platform has no backend yet, the platform rejects
    /// the label, or the platform refuses the operation. The key store failures
    /// carry the kind `device_error`.
    #[uniffi::constructor]
    pub fn open(label: String) -> Result<Arc<Self>, FfiError> {
        check_len("label", &label, MAX_LABEL_CHARS)?;
        let store = open_platform_key_store()?;
        store.open_or_create(&label).map_err(platform_error)?;
        Ok(Arc::new(Self { store, label }))
    }

    /// The SEC1 uncompressed public key of the identity under this object's
    /// label: 65 bytes, `0x04 || X(32) || Y(32)`.
    ///
    /// The same key [`FfiDeviceKeys::get_or_create`] has to return for that
    /// label, because both name one platform identity. A public key is not a
    /// secret: it is propagated to peer devices and shown in QR codes.
    ///
    /// # Errors
    ///
    /// A [`FfiError::Core`] error when the identity cannot be opened: it was
    /// deleted, this is a different user account, or no key store is available.
    pub fn device_public_key(&self) -> Result<Vec<u8>, FfiError> {
        let signer = self.signer()?;
        Ok(signer.public_key().as_sec1_bytes().to_vec())
    }

    /// Signs the **raw message** with the identity under this object's label and
    /// returns the 64-byte raw `r‖s`.
    ///
    /// # Do not hash the message first
    ///
    /// The platform hashes with SHA-256 internally and the core verifies with the
    /// standard ECDSA hash mode, so a digest passed in here would be hashed a
    /// second time and every verification would report `device_signature_invalid`
    /// while both the key and the message are correct.
    ///
    /// # The return value is not DER
    ///
    /// It is the fixed 64-byte `r‖s` layout the protocol uses. DER is variable
    /// length (68 to 72 bytes, depending on leading zero padding), which would
    /// reveal the high bytes of `r` and `s` and give one mathematical signature
    /// several valid encodings.
    ///
    /// # Errors
    ///
    /// A [`FfiError::Core`] error (`device_error`) when the platform refuses to
    /// sign — a cancelled authentication prompt, for example — or the identity
    /// cannot be opened.
    pub fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, FfiError> {
        let signer = self.signer()?;
        let signature = signer.sign(&message).map_err(platform_error)?;
        Ok(signature.as_bytes().to_vec())
    }

    /// The backend that holds this identity, as a stable short name: `"tpm"`,
    /// `"secure-enclave"`, `"android-keystore"`, `"software"` or
    /// `"unavailable"`.
    ///
    /// The value comes from the key store rather than from a signer, so asking
    /// for it opens no key handle. It is reported **truthfully** and may be
    /// weaker than what the platform could provide: a Windows machine without a
    /// TPM reports `"software"`, which means the private key is an ordinary
    /// operating system key store entry. An identity that opened successfully
    /// reports `"tpm"` or `"software"` today, since Windows is the only platform
    /// with a backend.
    #[must_use]
    pub fn backend(&self) -> String {
        self.store.backend().as_str().to_owned()
    }

    /// Whether the private key of this identity cannot leave hardware.
    ///
    /// Consistent with [`FfiPlatformKeys::backend`] by construction: `true`
    /// exactly when that backend is a hardware one. With `"software"` the key can
    /// be taken by an attacker who has administrator rights or disk access, so
    /// the host side has to tell the user before a critical operation.
    #[must_use]
    pub fn is_hardware_backed(&self) -> bool {
        self.store.backend().is_hardware_backed()
    }
}

/// Helpers of [`FfiPlatformKeys`] that are **not** exported.
///
/// A separate `impl` block on purpose: `#[uniffi::export]` processes every method
/// of the block it is attached to, including private ones, and it cannot generate
/// cross-boundary code for a Rust-only type such as `Box<dyn DeviceSigner>`.
impl FfiPlatformKeys {
    /// Opens the identity stored under this object's label.
    ///
    /// Written in fully qualified form rather than as a method call: the Windows
    /// backend has an **inherent** `open(preferred: WindowsProvider)`
    /// constructor, and an inherent method of that name wins method resolution
    /// and then fails on the argument type. Fully qualified syntax names the
    /// trait method on every platform.
    fn signer(&self) -> Result<Box<dyn DeviceSigner>, FfiError> {
        DeviceKeyStore::open(&self.store, &self.label).map_err(platform_error)
    }
}

/// Opens the platform key store on the best backend this machine has.
///
/// # Why one `cfg` appears here
///
/// The two constructors differ **on purpose**: opening a provider on Windows can
/// fail — no TPM, disabled by group policy, key store held by another process —
/// and returns a `Result`, while the placeholder compiled on every other platform
/// cannot fail and returns the value directly. `qualia-dik` documents that callers
/// write the call once per platform instead of hiding the difference, so this
/// function is the only place in this crate where a platform `cfg` appears; no
/// method carries one.
///
/// On a platform whose backend is not implemented, the store returned here fails
/// every operation with an error naming that platform, and **nothing falls back
/// to a software key**.
fn open_platform_key_store() -> Result<PlatformKeyStore, FfiError> {
    #[cfg(target_os = "windows")]
    {
        PlatformKeyStore::open_best_available().map_err(platform_error)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(PlatformKeyStore::open_best_available())
    }
}

/// Converts an error of the device identity library into an [`FfiError`].
///
/// The core wraps that error in its own `Error::Device` variant (`#[from]`), so
/// it reaches the host side with the stable `kind` that [`core_error_kind`]
/// already assigns to it: `device_public_key_invalid` and
/// `device_signature_invalid` keep their specific kinds, every other key store
/// failure is `device_error`. The library's messages are safe to pass on: each
/// `reason` field is a fixed `&'static str` supplied by the library, never key
/// material.
fn platform_error(source: qualia_dik::Error) -> FfiError {
    Error::from(source).into()
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
                reason: "must be 32 hexadecimal characters".to_owned(),
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
                reason: "contains a non-hexadecimal character".to_owned(),
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
                    reason: "wrong session identifier length",
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
            "memory limit is outside the representable range",
        )?,
        narrow(
            iterations.unwrap_or(u64::from(recommended.iterations())),
            "iteration count is outside the representable range",
        )?,
        narrow(
            parallelism.unwrap_or(u64::from(recommended.parallelism())),
            "parallelism is outside the representable range",
        )?,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_qr_code_survives_encoding_and_decoding() {
        for text in [
            "hello",
            "otpauth://totp/Example:alice?secret=MZXW6YTBOI",
            "中文内容，含标点。",
        ] {
            let image = qr_encode(text.to_owned(), FfiEcLevel::Medium, 20, 4, 4)
                .expect("the text must fit in a version 20 code");
            assert_eq!(image.pixels.len(), (image.width * image.height) as usize);
            assert!(image.pixels.contains(&0), "the code must have dark modules");
            assert!(
                image.pixels.contains(&255),
                "the code must have light modules"
            );

            let decoded =
                qr_decode(image.pixels, image.width, image.height).expect("the code must decode");
            assert_eq!(decoded, text, "the text must come back unchanged");
        }
    }

    #[test]
    fn a_buffer_that_does_not_match_the_dimensions_is_an_error() {
        let error = qr_decode(vec![0; 10], 100, 100).expect_err("a short buffer must be rejected");
        assert_eq!(error.kind(), "bad_image_geometry");
    }

    #[test]
    fn an_image_without_a_code_reports_that_rather_than_panicking() {
        let error = qr_decode(vec![255; 64 * 64], 64, 64).expect_err("a blank image has no code");
        assert_eq!(error.kind(), "no_qr_found");
    }

    #[test]
    fn text_that_does_not_fit_is_rejected_rather_than_truncated() {
        let error = qr_encode("a".repeat(8_000), FfiEcLevel::Medium, 20, 4, 4)
            .expect_err("the text must not fit");
        assert_eq!(error.kind(), "payload_too_large");
    }

    #[test]
    fn zero_scale_is_rejected() {
        let error = qr_encode("x".to_owned(), FfiEcLevel::Medium, 20, 0, 4)
            .expect_err("zero scale cannot render");
        assert_eq!(error.kind(), "bad_render_geometry");
    }

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
        .expect("should compute");
        assert_eq!(code, "94287082");
    }

    #[test]
    fn uri_roundtrips_through_ffi_types() {
        let original = "otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA256&digits=7&period=45";
        let parsed = parse_otpauth_uri(original.to_owned()).expect("should parse");
        assert_eq!(parsed.account, "alice");
        assert_eq!(parsed.issuer.as_deref(), Some("ACME"));
        assert_eq!(parsed.algorithm, FfiAlgorithm::Sha256);
        assert_eq!(parsed.digits, FfiDigits::Seven);
        assert_eq!(parsed.period, 45);

        let back = serialize_otpauth_uri(parsed.clone()).expect("should serialize");
        let reparsed = parse_otpauth_uri(back).expect("should parse again");
        assert_eq!(
            reparsed, parsed,
            "the entry should be equivalent after an FFI round trip"
        );
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
            other => panic!("expected InputTooLong, got {other:?}"),
        }
    }

    #[test]
    fn length_limit_counts_characters_not_bytes() {
        let chinese = "中".repeat(MAX_SECRET_CHARS);
        match secret_byte_len(chinese) {
            Err(FfiError::InputTooLong { .. }) => {
                panic!("counting characters must not hit the limit")
            }
            Err(FfiError::Core { .. }) => {}
            Err(FfiError::Qr { .. }) => {
                panic!("the code channel is not involved in a length check")
            }
            Ok(_) => panic!("non-Base32 input must not parse"),
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
            .expect("should compute");
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
        .expect("should compute");
        let hit = verify_code_with_drift(
            RFC_SECRET.to_owned(),
            1,
            1,
            FfiAlgorithm::Sha1,
            FfiDigits::Eight,
            code.clone(),
        )
        .expect("should verify");
        assert_eq!(hit, Some(0));

        let next = totp_code(
            RFC_SECRET.to_owned(),
            89,
            30,
            FfiAlgorithm::Sha1,
            FfiDigits::Eight,
        )
        .expect("should compute");
        let offset = verify_code_with_drift(
            RFC_SECRET.to_owned(),
            1,
            1,
            FfiAlgorithm::Sha1,
            FfiDigits::Eight,
            next,
        )
        .expect("should verify");
        assert_eq!(offset, Some(1));
    }

    #[test]
    fn generated_secrets_are_32_bytes_and_unique() {
        let a = generate_secret_base32().expect("should generate");
        let b = generate_secret_base32().expect("should generate");
        assert_ne!(a, b, "two generated secrets must differ");
        assert_eq!(secret_byte_len(a).expect("should parse"), 32);
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
            "an account name containing a colon must be rejected"
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
            let mut keys = self.keys.lock().expect("no lock poisoning in tests");
            keys.entry(label.to_owned())
                .or_insert_with(|| {
                    let scalar = sha2::Digest::finalize({
                        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
                        sha2::Digest::update(&mut hasher, label.as_bytes());
                        hasher
                    });
                    p256::ecdsa::SigningKey::from_slice(&scalar).expect("the scalar must be valid")
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
            Ok(self
                .master
                .lock()
                .expect("no lock poisoning in tests")
                .clone())
        }

        fn store_master_key(&self, key: Vec<u8>) -> Result<(), FfiError> {
            *self.master.lock().expect("no lock poisoning in tests") = Some(key);
            Ok(())
        }

        fn delete_master_key(&self) -> Result<(), FfiError> {
            *self.master.lock().expect("no lock poisoning in tests") = None;
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
        .expect("registration should succeed");
        assert!(
            vault_a.is_empty(),
            "precondition: this vault really is empty"
        );
        let data = vault_a.serialize().expect("should serialize");

        let store_b = Arc::new(TestStore::default());
        FfiVault::register(
            Arc::new(TestKeys::default()),
            store_b.clone(),
            "device-b".to_owned(),
        )
        .expect("registration should succeed");

        let error = FfiVault::open(store_b, data)
            .err()
            .expect("an empty vault must be rejected with a wrong key");
        assert_eq!(
            error.kind(),
            "vault_decryption_failed",
            "it must be \"cannot decrypt\", not \"not registered\": the two lead to completely different user interface actions"
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
            .expect("registration should succeed");
        assert!(vault.is_empty(), "registration adds no entries");

        let id = vault
            .add_entry(sample_entry("GitHub"), NOW)
            .expect("should add the entry");
        assert_eq!(vault.entry_count(), 1);

        let code = vault
            .totp_for(id.clone(), NOW)
            .expect("should compute the code");
        assert_eq!(code.len(), 6, "six-digit code");

        let data = vault.serialize().expect("should serialize");
        let reopened =
            FfiVault::open(store, data).expect("should open with the master key from the store");
        assert_eq!(reopened.entry_count(), 1);
        assert_eq!(
            reopened.totp_for(id, NOW).expect("should compute the code"),
            code,
            "the same entry must produce the same code after reopening"
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
        let vault = FfiVault::register(keys, store, "device-a".to_owned())
            .expect("registration should succeed");
        let id = vault
            .add_entry(sample_entry("GitHub"), NOW)
            .expect("should add the entry");

        let mut edited = sample_entry("GitHub (work)");
        edited.id = id.clone();
        vault
            .update_entry(edited, NOW + 60)
            .expect("should update the entry");

        assert_eq!(vault.entry_count(), 1, "an update must not add an entry");
        assert_eq!(vault.tombstone_count(), 0, "an update is not a deletion");
        let entry = vault
            .entry(id)
            .expect("the identifier must still point at the entry");
        assert_eq!(entry.name, "GitHub (work)");
        assert_eq!(
            entry.created_at, NOW,
            "the creation time should be preserved"
        );
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
        let vault = FfiVault::register(keys, store, "device-a".to_owned())
            .expect("registration should succeed");

        let mut ghost = sample_entry("ghost");
        ghost.id = "0".repeat(32);
        let error = vault
            .update_entry(ghost, NOW)
            .expect_err("a nonexistent identifier should be reported");
        assert_eq!(error.kind(), "vault_entry_not_found");

        assert!(
            !vault
                .remove_entry("0".repeat(32), NOW)
                .expect("should be callable"),
            "removing a nonexistent entry should return false"
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
                .expect("registration should succeed");
        old_vault
            .add_entry(sample_entry("GitHub"), NOW)
            .expect("should add the entry");
        let data = old_vault.serialize().expect("should serialize");

        let login = FfiLogin::begin().expect("should start the login");
        let joiner_keys = Arc::new(TestKeys::default());
        let joiner = FfiJoiner::from_qr(login.payload(), "device-b".to_owned())
            .expect("should establish the session");
        let request = joiner
            .request(joiner_keys.clone())
            .expect("should send the request");
        let reply = login
            .authorize(old_vault.clone(), request)
            .expect("should authorize");
        let joiner_store = Arc::new(TestStore::default());
        let master = joiner
            .complete(reply, joiner_keys, joiner_store.clone())
            .expect("should complete the login");

        assert_eq!(master.len(), 32, "the master key is 32 bytes");
        assert!(
            joiner_store.master.lock().expect("not poisoned").is_some(),
            "the master key must already be in the new device's platform store"
        );

        let new_vault = FfiVault::open(joiner_store, data)
            .expect("the new device should open the old device's vault");
        assert_eq!(
            new_vault.entry_count(),
            1,
            "the old device's entry should be visible"
        );
    }

    /// A login can be completed only once, and the second attempt reports the
    /// same error as a forged reply.
    #[test]
    fn a_login_cannot_be_completed_twice_across_the_boundary() {
        let old_keys = Arc::new(TestKeys::default());
        let old_store = Arc::new(TestStore::default());
        let old_vault = FfiVault::register(old_keys, old_store, "device-a".to_owned())
            .expect("registration should succeed");
        let login = FfiLogin::begin().expect("should start the login");
        let joiner_keys = Arc::new(TestKeys::default());
        let joiner = FfiJoiner::from_qr(login.payload(), "device-b".to_owned())
            .expect("should establish the session");
        let request = joiner
            .request(joiner_keys.clone())
            .expect("should send the request");
        let reply = login
            .authorize(old_vault, request)
            .expect("should authorize");
        let joiner_store = Arc::new(TestStore::default());

        joiner
            .complete(reply.clone(), joiner_keys.clone(), joiner_store.clone())
            .expect("the first attempt should succeed");
        let error = joiner
            .complete(reply, joiner_keys, joiner_store)
            .expect_err("the second attempt must fail");
        assert_eq!(
            error.kind(),
            "pairing_authentication_failed",
            "it must be the same error as a forged reply, so a replayer gets no distinguishing signal"
        );
    }

    /// A recovery key file restores the same master key.
    #[test]
    fn a_recovery_file_restores_the_same_master_key() {
        let keys = Arc::new(TestKeys::default());
        let store = Arc::new(TestStore::default());
        let vault = FfiVault::register(keys, store, "device-a".to_owned())
            .expect("registration should succeed");
        vault
            .add_entry(sample_entry("GitHub"), NOW)
            .expect("should add the entry");
        let data = vault.serialize().expect("should serialize");

        let file = vault
            .export_recovery_key("correct horse".to_owned(), Some(8), Some(1), Some(1))
            .expect("should export");

        let new_store = Arc::new(TestStore::default());
        let restored =
            import_recovery_key(file.clone(), "correct horse".to_owned(), new_store.clone())
                .expect("should import");
        assert_eq!(restored.len(), 32);

        let reopened = FfiVault::open(new_store, data).expect("should open");
        assert_eq!(reopened.entry_count(), 1);

        let wrong = import_recovery_key(
            file,
            "wrong passphrase".to_owned(),
            Arc::new(TestStore::default()),
        )
        .expect_err("a wrong passphrase should fail");
        assert_eq!(wrong.kind(), "recovery_authentication_failed");
    }

    /// All three steps of the challenge-response must work, with the master key
    /// staying inside the boundary.
    #[test]
    fn challenge_response_confirms_both_sides_across_the_boundary() {
        let keys = Arc::new(TestKeys::default());
        let store = Arc::new(TestStore::default());
        let vault = FfiVault::register(keys.clone(), store, "device-a".to_owned())
            .expect("registration should succeed");

        let verifier = FfiVerifier::begin().expect("should start the challenge");
        let responder =
            FfiResponder::accept(verifier.challenge()).expect("should accept the challenge");
        let response = responder
            .respond(vault.clone(), "device-a".to_owned(), keys)
            .expect("should produce the response");

        assert!(
            verifier
                .verify(response, vault.clone())
                .expect("should verify the response"),
            "the second step should pass"
        );

        let session_id = verifier
            .session_id()
            .expect("a session identifier should exist after verification");
        let confirmation = verifier
            .confirmation()
            .expect("a confirmation tag should exist after verification");
        assert!(
            responder
                .confirm(vault, session_id, confirmation)
                .expect("should confirm"),
            "the third step should pass"
        );
    }

    /// Challenge-response is single use, like pairing.
    #[test]
    fn a_challenge_cannot_be_verified_twice() {
        let keys = Arc::new(TestKeys::default());
        let store = Arc::new(TestStore::default());
        let vault = FfiVault::register(keys.clone(), store, "device-a".to_owned())
            .expect("registration should succeed");
        let verifier = FfiVerifier::begin().expect("should start the challenge");
        let responder =
            FfiResponder::accept(verifier.challenge()).expect("should accept the challenge");
        let response = responder
            .respond(vault.clone(), "device-a".to_owned(), keys)
            .expect("should produce the response");

        verifier
            .verify(response.clone(), vault.clone())
            .expect("the first attempt should pass");
        let error = verifier
            .verify(response, vault)
            .expect_err("the second attempt must fail");
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
            assert_ne!(kind, "unknown", "a variant is not mapped to a stable kind");
        }
        let unique: std::collections::HashSet<_> = kinds.iter().collect();
        assert_eq!(
            unique.len(),
            kinds.len(),
            "two variants map to the same kind, so the client side cannot tell them apart"
        );
    }

    // ── Platform key store forwarding ────────────────────────────────

    /// Sequence that keeps the labels of one process distinct.
    ///
    /// `cargo test` runs tests in parallel and the platform key store is global
    /// shared state: two tests that use one label would delete each other's keys.
    static PLATFORM_LABEL_SEQUENCE: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);

    /// A device label for tests, unique across the machine.
    ///
    /// The label becomes an entry in the **system-wide** key namespace, so it
    /// carries the `Q2faTest-` prefix the device identity kit's own integration
    /// tests use. A label without that prefix could name a real user identity,
    /// and deleting one costs that user the device identity permanently.
    fn test_label(name: &str) -> String {
        let sequence = PLATFORM_LABEL_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pid = std::process::id();
        format!("Q2faTest-{name}-{pid}-{sequence}")
    }

    /// The label limit is enforced before the platform is touched.
    ///
    /// This holds on every machine, with or without a key store: an oversized
    /// label has to be rejected at the boundary and never reach the platform.
    #[test]
    fn an_oversized_label_is_rejected_before_the_platform_is_touched() {
        match FfiPlatformKeys::open("a".repeat(MAX_LABEL_CHARS + 1)) {
            Err(FfiError::InputTooLong { kind, limit, .. }) => {
                assert_eq!(kind, "label");
                assert_eq!(limit, MAX_LABEL_CHARS as u64);
            }
            Err(_) => panic!("expected an InputTooLong error, got another error kind"),
            Ok(_) => panic!("an oversized label must not reach the platform key store"),
        }
    }

    /// The exported key store forwards to the platform's own key store.
    ///
    /// Requires a usable platform key store: the TPM or the software KSP on
    /// Windows. Where there is none — a platform whose backend is not implemented
    /// yet, or a machine whose key store cannot be opened — the test **skips with
    /// a printed reason** instead of failing, because what it checks (forwarding)
    /// cannot be observed without a key store. Printing the reason keeps a skip
    /// distinguishable from a pass in the test output.
    #[test]
    fn platform_keys_forward_to_the_platform_key_store() {
        let label = test_label("platform-keys");
        let keys = match FfiPlatformKeys::open(label.clone()) {
            Ok(keys) => keys,
            Err(error) => {
                println!("skipping: no usable platform key store on this machine ({error})");
                return;
            }
        };

        let public_key = keys
            .device_public_key()
            .expect("the public key of the opened identity should be readable");
        assert_eq!(
            public_key.len(),
            65,
            "the public key must be a 65-byte SEC1 uncompressed point"
        );
        let public_key = qualia_dik::DevicePublicKey::from_sec1_bytes(&public_key)
            .expect("the platform must return a point on P-256");

        let message = b"\x01Qualia2FA platform keys";
        let signature = keys.sign(message.to_vec()).expect("signing should succeed");
        assert_eq!(
            signature.len(),
            64,
            "the signature must be the 64-byte raw r||s, not DER"
        );
        let signature = qualia_dik::DeviceSignature::from_bytes(&signature)
            .expect("a 64-byte raw signature should parse");

        qualia_dik::device::verify(&public_key, message, &signature)
            .expect("the signature must verify over the raw message, not over a digest");

        let backend = keys.backend();
        assert!(
            backend == "tpm" || backend == "software",
            "an identity that opened must report a real backend, got {backend}"
        );
        assert_eq!(
            keys.is_hardware_backed(),
            backend == "tpm",
            "is_hardware_backed must agree with the backend that is reported"
        );

        let reopened = FfiPlatformKeys::open(label.clone()).expect("reopening should succeed");
        assert_eq!(
            reopened
                .device_public_key()
                .expect("the public key should be readable again"),
            public_key.as_sec1_bytes().to_vec(),
            "the identity under one label changed: the key was not persisted"
        );

        DeviceKeyStore::delete(&keys.store, label.as_str())
            .expect("the test identity should be removable");
    }
}
