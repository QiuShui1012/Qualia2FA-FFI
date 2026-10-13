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
use qualia_dik::{
    DEVICE_ID_LEN, DeviceId, DeviceKeyStore, DevicePublicKey, DeviceSignature, DeviceSigner,
};
use qualia2fa_core::auth;
use qualia2fa_core::flow::{self, DeviceKeys as _, Joiner, Login, SecureStore as _};
use qualia2fa_core::otp::{self, Algorithm, Digits, OtpSecret};
use qualia2fa_core::recovery::KdfParams;
use qualia2fa_core::sync::{
    Conflict, ConflictKind, Decision, PayloadKind, SeenSyncIds, adjudicate,
};
use qualia2fa_core::transport::{
    Recipient, Roster, SharePlan, SyncSession, Transport, TransportCapabilities,
};
use qualia2fa_core::uri;
use qualia2fa_core::vault::{Entry, MasterKey, Vault, VaultFile};
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
        // ── Synchronization and the channel ────────────────────────────────
        //
        // The sync family is mapped as a whole rather than only the variants the current
        // screen branches on: a payload that fails to open, a log that is full and a
        // channel that was used twice all mean different things to the user, and letting
        // them collapse into `"unknown"` would leave the host side unable to tell them
        // apart once it wants to.
        Error::SyncBadMagic => "sync_bad_magic",
        Error::SyncUnsupportedVersion { .. } => "sync_unsupported_version",
        Error::SyncEmptyPayload => "sync_empty_payload",
        Error::SyncTruncated => "sync_truncated",
        Error::SyncRecordCountMismatch { .. } => "sync_record_count_mismatch",
        Error::SyncTooManyRecords { .. } => "sync_too_many_records",
        Error::SyncCompressionFailed => "sync_compression_failed",
        Error::SyncDecompressionFailed => "sync_decompression_failed",
        Error::SyncPayloadTooLarge { .. } => "sync_payload_too_large",
        Error::SyncUnknownRecordKind { .. } => "sync_unknown_record_kind",
        Error::SyncMalformed { .. } => "sync_malformed",
        Error::SyncAuthenticationFailed => "sync_authentication_failed",
        Error::SyncAlreadyApplied => "sync_already_applied",
        Error::SyncIdLogFull { .. } => "sync_id_log_full",
        Error::SyncSenderMismatch => "sync_sender_mismatch",
        Error::SyncUnknownPayloadKind { .. } => "sync_unknown_payload_kind",
        Error::SyncNoSessionFound => "sync_no_session_found",
        Error::TransportFailed { .. } => "transport_failed",
        Error::TransportUnsupported { .. } => "transport_unsupported",
        Error::TransportAlreadyUsed => "transport_already_used",
        Error::TransportMessageTooLarge { .. } => "transport_message_too_large",
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
            FfiError::InvalidDeviceId { .. } => "invalid_device_id",
            FfiError::UnknownConflict { .. } => "unknown_conflict",
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
    #[error("{detail}")]
    Qr {
        /// Stable kind for the host to branch on, in `snake_case`.
        kind: String,
        /// Human-readable detail. Never contains a payload or a secret.
        detail: String,
    },

    /// An identifier handed across the boundary is not in the form this layer documents.
    ///
    /// Device identifiers cross as 64 hexadecimal characters (see [`FfiTransport`]). A
    /// value of another shape is a **host-side** mistake — a truncated copy, or a
    /// fingerprint formatted with separators — and reading it as some other device would
    /// attribute a payload to the wrong sender, which is what the sender check exists to
    /// prevent.
    #[error("{kind} is not 64 hexadecimal characters")]
    InvalidDeviceId {
        /// Which identifier was wrong (`device_id`), so the host side can point at it.
        kind: String,
    },

    /// A decision was handed over for a conflict that is not waiting.
    ///
    /// The conflicts of a receive replace the ones before them, so a decision kept from an
    /// older merge names nothing. Refusing it is deliberate: applying a decision to
    /// whatever now sits under that identifier is how a user ends up with content they
    /// never chose.
    #[error("no conflict is waiting for entry {entry_id}")]
    UnknownConflict {
        /// The entry identifier the decision named, as it was passed in.
        entry_id: String,
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
        detail: "the code carried bytes that are not UTF-8 text".to_owned(),
    })
}

/// Reads **any** text out of a grayscale image, whichever application drew the code.
///
/// This is the entry point for a screen that receives text and decides what it means for
/// itself: an `otpauth://` link to import, a code handed over by someone else's server. Use
/// [`qr_decode`] instead when the caller wants *this* application's payload, because that one
/// skips foreign codes rather than handing back the first one it finds.
///
/// The input is pixels, not an image file, for the reason given on [`qr_decode`].
///
/// # Errors
///
/// The same kinds as [`qr_decode`] except `not_our_qr_text`, which this entry point cannot
/// report: a code of another application is exactly what it is here to read.
#[uniffi::export]
pub fn qr_decode_text(pixels: Vec<u8>, width: u32, height: u32) -> Result<String, FfiError> {
    let image =
        qualia_transport::image::GrayImage::from_luma8(width, height, pixels).map_err(qr_error)?;
    qualia_transport::qr::scan::decode_text(&image).map_err(qr_error)
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
        detail: source.to_string(),
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
        // None of the boundary's own errors can arrive from a host callback: the code
        // channel is called from the host, not into it, and an identifier or a conflict
        // named by the host is checked where it is used. They degrade the same way as any
        // other error that has no core equivalent.
        FfiError::InputTooLong { .. }
        | FfiError::Qr { .. }
        | FfiError::InvalidDeviceId { .. }
        | FfiError::UnknownConflict { .. } => Error::DeviceKeyMissing,
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

    /// The fingerprint of this device's identity: 64 hexadecimal characters.
    ///
    /// It is the identifier a sync payload carries as its sender, the value the channel
    /// reports for this device (see [`FfiTransport::local_device`]), and the string a
    /// pairing screen shows next to a requester. All three are the **same value by
    /// construction**: the fingerprint is derived from the public key, so two devices that
    /// show the same string really do hold the same identity, with no registry to keep in
    /// step and nothing to forge.
    ///
    /// # Errors
    ///
    /// A [`FfiError::Core`] error when the identity cannot be opened: it was deleted, this
    /// is a different user account, or no key store is available.
    pub fn device_id(&self) -> Result<String, FfiError> {
        Ok(self.signer()?.public_key().device_id().to_hex())
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
/// The constructors differ **on purpose**: opening a key store can fail where there is one
/// to open — Windows may have no TPM, a key store held by another process or a policy that
/// forbids it, and Android may be reached without the Java VM this library needs — and those
/// return a `Result`. The placeholder compiled on the remaining platforms cannot fail and
/// returns the value directly. `qualia-dik` documents that callers write the call once per
/// platform instead of hiding the difference, so this function is the only place in this
/// crate where a platform `cfg` appears; no method carries one.
///
/// On a platform whose backend is not implemented, the store returned here fails
/// every operation with an error naming that platform, and **nothing falls back
/// to a software key**.
fn open_platform_key_store() -> Result<PlatformKeyStore, FfiError> {
    #[cfg(any(target_os = "windows", target_os = "android"))]
    {
        PlatformKeyStore::open_best_available().map_err(platform_error)
    }
    #[cfg(not(any(target_os = "windows", target_os = "android")))]
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

// ── Synchronization: the channel contract and one session ────────────────
//
// The core owns the protocol: which payload goes first, what a merge does, what a conflict
// means. This half only moves data across the boundary:
//
//   - the host side implements a channel (`FfiTransport`), which is where a real
//     transport lives (today the text/QR code channel, later a LAN one);
//   - `FfiSyncSession` drives one exchange against such a channel.
//
// Nothing here decides anything. A review of this section has one question: **has any
// protocol rule been copied in from the core?**

/// How many parties take part in one sync.
///
/// Mirrors [`qualia2fa_core::transport::Roster`]. The distinction has to be declared by
/// the channel rather than guessed by the caller: the same code is two-party over QR codes
/// and may be multi-party for the same use over a LAN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiRoster {
    /// Exactly two parties. Transfer starts as soon as they connect.
    TwoParty,
    /// Three or more parties. The initiator decides when to start.
    MultiParty,
}

impl From<FfiRoster> for Roster {
    fn from(value: FfiRoster) -> Self {
        match value {
            FfiRoster::TwoParty => Self::TwoParty,
            FfiRoster::MultiParty => Self::MultiParty,
        }
    }
}

/// What a channel can do.
///
/// Mirrors [`qualia2fa_core::transport::TransportCapabilities`]; see it for the meaning of
/// each field. Two points matter at this boundary:
///
/// - **The values are a declaration, not a probe.** They must be available before the
///   exchange starts, so the caller can pick a mode before anything is displayed.
/// - **`max_message_len` is one message**, not one physical artifact: a channel that shows
///   several codes in sequence declares the sum over all of them, and how the bytes are cut
///   into frames is the channel's business.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct FfiTransportCapabilities {
    /// Roster of this channel.
    pub roster: FfiRoster,
    /// Per-message byte limit; `None` means a byte stream with no limit.
    pub max_message_len: Option<u64>,
    /// Largest QR version this channel may display, if it displays codes.
    pub max_qr_version: Option<u8>,
    /// Whether this channel may be used only once (QR codes are).
    pub single_use: bool,
    /// Whether this channel can carry a whole payload, or only link establishment.
    pub can_carry_payload: bool,
}

impl From<FfiTransportCapabilities> for TransportCapabilities {
    fn from(value: FfiTransportCapabilities) -> Self {
        Self {
            roster: value.roster.into(),
            // A limit wider than this platform can address is treated as the largest one
            // it can: the direction is safe (a channel never gets a limit larger than it
            // declared) and the value is far beyond any real message.
            max_message_len: value
                .max_message_len
                .map(|len| usize::try_from(len).unwrap_or(usize::MAX)),
            max_qr_version: value.max_qr_version,
            single_use: value.single_use,
            can_carry_payload: value.can_carry_payload,
        }
    }
}

/// The recipient of one message.
///
/// Mirrors [`qualia2fa_core::transport::Recipient`]. The recipient is an explicit parameter
/// rather than left implicit: on a channel with several peers, "forward this to one peer"
/// and "broadcast" are two different actions.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FfiRecipient {
    /// Send to this peer only: a 64-character hexadecimal device identifier.
    One {
        /// Device identifier, hexadecimal.
        device_id: String,
    },
    /// Send to every peer of the current session.
    All,
}

impl TryFrom<FfiRecipient> for Recipient {
    type Error = FfiError;

    fn try_from(value: FfiRecipient) -> Result<Self, FfiError> {
        Ok(match value {
            FfiRecipient::One { device_id } => Self::One(parse_device_id(&device_id)?),
            FfiRecipient::All => Self::All,
        })
    }
}

/// One message taken off a channel, together with the sender the channel claims.
///
/// Mirrors the return value of [`qualia2fa_core::transport::Transport::receive`]. The
/// `sender` is the **channel's claim**, and the core compares it with the sender inside the
/// payload: the payload's own field proves only that nobody changed it, while "who actually
/// handed this over" is something only the channel knows.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiReceivedMessage {
    /// The sending device as the channel reports it, hexadecimal.
    pub sender: String,
    /// The message bytes.
    pub message: Vec<u8>,
}

/// A channel that can move sync payloads. **Implemented by the host side.**
///
/// Corresponds to [`qualia2fa_core::transport::Transport`]. An implementation forwards to a
/// real transport, **with no decisions of its own**: every protocol rule (what the bytes
/// mean, whether a payload was already applied, whether a sender is acceptable) lives in the
/// core.
///
/// # Contract the implementation must satisfy
///
/// 1. **`receive` must report the sender truthfully**, not just hand back bytes. On a
///    broadcast channel any device can replay a payload someone else sent, so "the payload
///    says it is from B" and "C actually sent it" can hold at the same time. The core turns
///    the comparison into a hard check, so misreporting the sender only makes the sync fail.
/// 2. **`send` must respect [`FfiRecipient`]**; `One` must not degrade into a broadcast.
/// 3. **`receive` must not block indefinitely.** With no message available it returns
///    `Ok(None)`, which the core reports as "no session found"; how long to wait is the
///    host side's decision, because the core has no clock.
/// 4. **A `single_use` channel must fail its second use** with
///    [`FfiError::Qr`]`{ kind: "transport_already_used" }`.
/// 5. **Device identifiers are 64 hexadecimal characters**: the 32-byte device fingerprint
///    (`qualia_dik::DeviceId`), the same value the pairing flow shows as a device identity.
#[uniffi::export(with_foreign)]
pub trait FfiTransport: Send + Sync {
    /// What this channel can do.
    fn capabilities(&self) -> FfiTransportCapabilities;

    /// This device's identifier, hexadecimal.
    ///
    /// It fills in the `sender` of outgoing payloads, so both sides of an exchange agree on
    /// who sent what.
    fn local_device(&self) -> String;

    /// Sends one message.
    fn send(&self, to: FfiRecipient, message: Vec<u8>) -> Result<(), FfiError>;

    /// Takes one message off the channel.
    ///
    /// `Ok(None)` means "nothing available right now", which is a normal state and not an
    /// error; `Err` means the channel itself failed.
    fn receive(&self) -> Result<Option<FfiReceivedMessage>, FfiError>;

    /// Every peer in the current session.
    ///
    /// Zero or one element on a two-party channel. This defines what `All` means.
    fn peers(&self) -> Result<Vec<String>, FfiError>;
}

/// Forwarding implementation of the core `Transport`: bridges trait calls to the host-side
/// channel, after parsing this device's identifier **once** when the adapter is built.
///
/// Parsing up front is what makes it possible to satisfy the core trait at all: the core
/// asks for `local_device()` as a value that cannot fail, so an identifier that cannot be
/// parsed has to be reported before the session starts rather than in the middle of it.
struct ForeignTransport {
    /// The host-side channel.
    channel: Arc<dyn FfiTransport>,
    /// This device's identifier, parsed once.
    me: DeviceId,
}

impl ForeignTransport {
    /// Builds the adapter, rejecting an unparsable local device identifier.
    fn new(channel: Arc<dyn FfiTransport>) -> Result<Self, FfiError> {
        let me = parse_device_id(&channel.local_device())?;
        Ok(Self { channel, me })
    }
}

impl Transport for ForeignTransport {
    fn capabilities(&self) -> TransportCapabilities {
        self.channel.capabilities().into()
    }

    fn local_device(&self) -> DeviceId {
        self.me
    }

    fn send(&self, to: Recipient, message: &[u8]) -> Result<(), Error> {
        let to = match to {
            Recipient::One(id) => FfiRecipient::One {
                device_id: id.to_hex(),
            },
            Recipient::All => FfiRecipient::All,
        };
        self.channel
            .send(to, message.to_vec())
            .map_err(transport_error_to_core_error)
    }

    fn receive(&self) -> Result<(DeviceId, Vec<u8>), Error> {
        match self
            .channel
            .receive()
            .map_err(transport_error_to_core_error)?
        {
            Some(received) => {
                let sender =
                    parse_device_id(&received.sender).map_err(|_| Error::TransportFailed {
                        reason: "the channel reported a device identifier that is not hexadecimal",
                    })?;
                Ok((sender, received.message))
            }
            None => Err(Error::SyncNoSessionFound),
        }
    }

    fn peers(&self) -> Result<Vec<DeviceId>, Error> {
        self.channel
            .peers()
            .map_err(transport_error_to_core_error)?
            .iter()
            .map(|id| {
                parse_device_id(id).map_err(|_| Error::TransportFailed {
                    reason: "the channel reported a device identifier that is not hexadecimal",
                })
            })
            .collect()
    }
}

/// Parses a device identifier: exactly 64 hexadecimal characters.
///
/// The form is the one every other device identifier at this boundary uses (see
/// [`FfiTransport`] point 5), so a value taken from a pairing screen can be compared with
/// one from a sync payload without conversion.
fn parse_device_id(text: &str) -> Result<DeviceId, FfiError> {
    let invalid = || FfiError::InvalidDeviceId {
        kind: "device_id".to_owned(),
    };
    let bytes = text.as_bytes();
    if bytes.len() != DEVICE_ID_LEN * 2 {
        return Err(invalid());
    }

    let mut id = [0_u8; DEVICE_ID_LEN];
    for (index, slot) in id.iter_mut().enumerate() {
        let high = hex_digit(bytes[index * 2]).map_err(|_| invalid())?;
        let low = hex_digit(bytes[index * 2 + 1]).map_err(|_| invalid())?;
        *slot = (high << 4) | low;
    }
    Ok(DeviceId::from_bytes(id))
}

/// Converts a failure reported by a host-side channel back into a core error.
///
/// The channel reports failures as [`FfiError::Qr`], whose `kind` is stable (see
/// [`FfiError::kind`]). Two of them have a core equivalent the protocol reacts to, and they
/// are the two where the reaction differs:
///
/// - `transport_already_used`: a one-shot channel was used twice.
/// - `sync_no_session_found`: nothing to receive. A channel that prefers `Ok(None)` for
///   that state never produces it, but one that carries the core's wording does.
///
/// Everything else becomes [`Error::TransportFailed`] with an opaque reason: the channel's
/// own message belongs to the channel and is not part of the protocol layer.
fn transport_error_to_core_error(source: FfiError) -> Error {
    match &source {
        FfiError::Qr { kind, .. } if kind == "transport_already_used" => {
            Error::TransportAlreadyUsed
        }
        FfiError::Qr { kind, .. } if kind == "sync_no_session_found" => Error::SyncNoSessionFound,
        _ => Error::TransportFailed {
            reason: "the host-side channel reported a failure",
        },
    }
}

/// What a payload asks the peer to do.
///
/// Mirrors [`qualia2fa_core::sync::PayloadKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiPayloadKind {
    /// The sender's full state: accept it and merge.
    Vault,
    /// A request: send me your full state.
    Request,
}

impl From<FfiPayloadKind> for PayloadKind {
    fn from(value: FfiPayloadKind) -> Self {
        match value {
            FfiPayloadKind::Vault => Self::Vault,
            FfiPayloadKind::Request => Self::Request,
        }
    }
}

/// Which route one share takes.
///
/// Mirrors [`qualia2fa_core::transport::SharePlan`]. "Does not fit" is a route, not a
/// failure: a request (which carries no records) goes out first and the payload is left to a
/// channel that can carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiSharePlan {
    /// The whole payload fits this channel.
    FullPayload {
        /// Size in bytes after sealing.
        len: u64,
    },
    /// It does not fit: a link on another channel is needed first.
    LinkEstablishment {
        /// Number of bytes the payload needs.
        needed: u64,
        /// Largest number of bytes this channel can carry.
        limit: u64,
    },
}

impl From<SharePlan> for FfiSharePlan {
    fn from(value: SharePlan) -> Self {
        match value {
            SharePlan::FullPayload { len } => Self::FullPayload { len: len as u64 },
            SharePlan::LinkEstablishment { needed, limit } => Self::LinkEstablishment {
                needed: needed as u64,
                limit: limit as u64,
            },
        }
    }
}

/// What the user decided about one conflict.
///
/// Mirrors [`qualia2fa_core::sync::Decision`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiDecision {
    /// Keep the state of this device; the peer's version is discarded.
    KeepLocal,
    /// Take the peer's version, discarding the state of this device.
    TakeIncoming,
}

impl From<FfiDecision> for Decision {
    fn from(value: FfiDecision) -> Self {
        match value {
            FfiDecision::KeepLocal => Self::KeepLocal,
            FfiDecision::TakeIncoming => Self::TakeIncoming,
        }
    }
}

/// One side of a conflict, as far as it can be shown.
///
/// **No secret crosses here.** A conflict is displayed so the user can tell two versions
/// apart, and a name, a service, an account and a note are what that needs; the seed would
/// only add a second copy of key material in the host process, where it cannot be erased.
/// The decision itself is applied inside Rust, from the copy the conflict already holds.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiConflictSide {
    /// Display name.
    pub name: String,
    /// Issuer (service name), if any.
    pub issuer: Option<String>,
    /// Account name.
    pub account: String,
    /// Note.
    pub note: String,
    /// Last modification time of this version (Unix seconds, from the device that wrote it).
    pub updated_at: u64,
}

impl FfiConflictSide {
    /// Reads the displayable fields of one entry.
    fn from_entry(entry: &Entry) -> Self {
        Self {
            name: entry.name.clone(),
            issuer: entry.issuer.clone(),
            account: entry.account.clone(),
            note: entry.note.clone(),
            updated_at: entry.updated_at,
        }
    }
}

/// One disagreement a human has to settle.
///
/// The fields are **normalized**, which is not how the core stores them: there,
/// `DeletionConflict` keeps the peer's record in one field and the local tombstone in
/// another, because that is what has to be written back. Here:
///
/// - `local` is the live entry **this device** holds, if it holds one;
/// - `incoming` is the live entry the **peer** sent, if it sent one.
///
/// A tombstone has nothing to display, so the side that deleted is `None`. Which side
/// deleted is what `kind` says.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiConflict {
    /// The entry in disagreement, as 32 hexadecimal characters.
    pub entry_id: String,
    /// Stable identifier of the shape; see [`conflict_kind`].
    pub kind: String,
    /// The local version, when this device holds a live entry.
    pub local: Option<FfiConflictSide>,
    /// The peer's version, when the peer sent a live entry.
    pub incoming: Option<FfiConflictSide>,
    /// Whether the local version is the later one.
    ///
    /// A **hint for the user interface**, not a basis for a decision: the peer fills in its
    /// own timestamps. The core never picks a side from it, and neither does the host side.
    pub local_is_newer: bool,
}

impl FfiConflict {
    /// Converts one conflict for display, normalizing the two sides.
    ///
    /// The local side of `peer_deleted` is **read from the vault** rather than taken from
    /// the conflict: the core leaves it out on purpose (it is already stored, and copying
    /// it would duplicate key material for a screen that only shows names), so the vault is
    /// where that version lives.
    fn from_core(conflict: &Conflict, vault: &Vault) -> Self {
        let (local, incoming, local_is_newer) = match &conflict.kind {
            ConflictKind::EntryMismatch { local, incoming } => (
                Some(FfiConflictSide::from_entry(local)),
                Some(FfiConflictSide::from_entry(incoming)),
                false,
            ),
            ConflictKind::DeletionConflict {
                local,
                local_is_newer,
                ..
            } => (
                vault
                    .get(&conflict.entry_id)
                    .map(FfiConflictSide::from_entry),
                local
                    .as_ref()
                    .map(|entry| FfiConflictSide::from_entry(entry)),
                *local_is_newer,
            ),
        };
        Self {
            entry_id: conflict.entry_id.to_string(),
            kind: conflict_kind(conflict).to_owned(),
            local,
            incoming,
            local_is_newer,
        }
    }
}

/// Names the shape of a conflict, in the form the host side branches on.
///
/// # Stability contract
///
/// These strings are part of the public interface: new values may be added, but an existing
/// one must not be renamed or change meaning. A client must have a fallback branch for
/// values it does not know, because a newer library may report a shape it has never seen.
///
/// | value | meaning | deciding |
/// |---|---|---|
/// | `entry_mismatch` | both sides hold a live entry with different content | either version |
/// | `peer_deleted` | the peer reports a deletion; this device holds a newer entry | keep the entry, or accept the deletion |
/// | `local_deleted` | this device reports a deletion; the peer still holds an entry | keep it deleted, or restore the peer's entry |
#[must_use]
pub fn conflict_kind(conflict: &Conflict) -> &'static str {
    match &conflict.kind {
        ConflictKind::EntryMismatch { .. } => "entry_mismatch",
        ConflictKind::DeletionConflict { local: None, .. } => "peer_deleted",
        ConflictKind::DeletionConflict { local: Some(_), .. } => "local_deleted",
    }
}

/// The result of one receive.
///
/// Mirrors [`qualia2fa_core::transport::SyncOutcome`], with the counters as plain numbers so
/// the host side can summarize a sync without looking at the conflicts.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiSyncOutcome {
    /// Identifier of the payload just processed, hexadecimal.
    pub sync_id: String,
    /// Number of entries added.
    pub added: u64,
    /// Number of tombstones added.
    pub tombstones_added: u64,
    /// Number of deletions applied.
    pub deletions_applied: u64,
    /// Number of records whose content was already identical.
    pub unchanged: u64,
    /// Whether this sync changed nothing at all.
    ///
    /// Reported by the core rather than computed here: "nothing changed" and "everything
    /// was already there" are one condition, and assembling it at a second place is how the
    /// two stop agreeing.
    pub made_no_change: bool,
    /// Whether conflicts are waiting for a decision.
    pub needs_adjudication: bool,
    /// The conflicts themselves, to show the user.
    pub conflicts: Vec<FfiConflict>,
}

/// One synchronization session against one channel.
///
/// # It borrows the vault, so the vault must not be reassigned while it is used
///
/// The session works on the [`FfiVault`] object it was opened with. The host side keeps that
/// object alive; the merge writes into it, and the host side **must persist it afterwards**
/// ([`FfiVault::serialize`]) or the merged records are lost when the process ends.
///
/// # The replay log lives in this object
///
/// The core keeps a log of processed payload identifiers so that the same payload is not
/// decrypted and merged again. It is not persisted, for the same reason the pairing session
/// is not: a log written to disk is another store to keep in step with the vault, and the
/// code channel is out-of-band and one-shot, so the practical exposure is a user who
/// re-applies a code they already applied — which merges to the same content. A long-lived
/// broadcast channel (a LAN) will need the log to survive a restart, and that is the point
/// at which it becomes worth persisting.
///
/// # Only one exchange at a time
///
/// A session accepts payloads from **any** peer: the channel it is used with has confirmed
/// the peer out of band (the user carried the code). A channel that carries several peers
/// has to restrict them instead, and that entry point is not exposed yet, because no such
/// channel exists.
#[derive(uniffi::Object)]
pub struct FfiSyncSession {
    /// The vault being synchronized: master key and records both stay on this side.
    vault: Arc<FfiVault>,
    /// Identifiers of the payloads already processed.
    seen: std::sync::Mutex<SeenSyncIds>,
    /// Conflicts of the last receive that are waiting for a decision.
    pending: std::sync::Mutex<Vec<Conflict>>,
}

#[uniffi::export]
impl FfiSyncSession {
    /// Opens a session on an unlocked vault.
    #[uniffi::constructor]
    pub fn open(vault: Arc<FfiVault>) -> Arc<Self> {
        Arc::new(Self {
            vault,
            seen: std::sync::Mutex::new(SeenSyncIds::new()),
            pending: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// Asks which route sharing this vault's state takes on `transport`.
    ///
    /// Sends nothing and displays nothing: the answer is needed **before** a code is shown,
    /// and [`FfiSyncSession::send`] seals and sends in one step, leaving no chance to look
    /// at the size first.
    pub fn plan_share(&self, transport: Arc<dyn FfiTransport>) -> Result<FfiSharePlan, FfiError> {
        let transport = ForeignTransport::new(transport)?;
        let mut vault = self.vault.lock();
        let mut seen = self.lock_seen();
        let (master, contents) = vault.split_mut();
        let session = SyncSession::open(master, contents, &mut seen);
        Ok(session.plan_share(&transport)?.into())
    }

    /// Seals this vault's state (or a request for the peer's) and sends it.
    ///
    /// Returns the payload identifier, hexadecimal. The payload is **not** recorded in the
    /// replay log: that log holds what this device received, and recording an outgoing
    /// payload would make this device reject its own payload when a peer sends it back.
    pub fn send(
        &self,
        transport: Arc<dyn FfiTransport>,
        to: FfiRecipient,
        kind: FfiPayloadKind,
    ) -> Result<String, FfiError> {
        let transport = ForeignTransport::new(transport)?;
        let to = Recipient::try_from(to)?;
        let mut vault = self.vault.lock();
        let mut seen = self.lock_seen();
        let (master, contents) = vault.split_mut();
        let session = SyncSession::open(master, contents, &mut seen);
        Ok(to_hex(&session.send(&transport, to, kind.into())?))
    }

    /// Receives one message and merges its records into the vault.
    ///
    /// The conflicts of this receive **replace** the ones still waiting from the previous
    /// one: a decision belongs to the merge that reported it, and carrying a conflict
    /// forward from an older merge would apply a decision to content the user is no longer
    /// looking at. The host side must decide before receiving again, or accept that those
    /// conflicts are dropped.
    ///
    /// # Errors
    ///
    /// Every rejected payload keeps its own error: `sync_no_session_found` when the channel
    /// had nothing, `sync_already_applied` for a payload that was already processed,
    /// `sync_sender_mismatch` when the envelope's sender and the payload's disagree, and the
    /// authentication failures of the payload itself. **Both the vault and the replay log are
    /// left unchanged** when it fails.
    pub fn receive(&self, transport: Arc<dyn FfiTransport>) -> Result<FfiSyncOutcome, FfiError> {
        let transport = ForeignTransport::new(transport)?;

        let (record, conflicts) = {
            let mut vault = self.vault.lock();
            let mut seen = self.lock_seen();
            let (master, contents) = vault.split_mut();
            let mut session = SyncSession::open(master, contents, &mut seen);
            let outcome = session.receive(&transport)?;

            let made_no_change = outcome.made_no_change();
            let needs_adjudication = outcome.needs_adjudication();
            let merge = outcome.merge;
            let record = FfiSyncOutcome {
                sync_id: to_hex(&outcome.sync_id),
                added: merge.added as u64,
                tombstones_added: merge.tombstones_added as u64,
                deletions_applied: merge.deletions_applied as u64,
                unchanged: merge.unchanged as u64,
                made_no_change,
                needs_adjudication,
                conflicts: merge
                    .conflicts
                    .iter()
                    .map(|conflict| FfiConflict::from_core(conflict, vault.vault()))
                    .collect(),
            };
            (record, merge.conflicts)
        };

        *self.lock_pending() = conflicts;
        Ok(record)
    }

    /// The conflicts waiting for a decision, in the order the merge reported them.
    #[must_use]
    pub fn pending_conflicts(&self) -> Vec<FfiConflict> {
        let vault = self.vault.lock();
        self.lock_pending()
            .iter()
            .map(|conflict| FfiConflict::from_core(conflict, vault.vault()))
            .collect()
    }

    /// Applies one decision to the vault.
    ///
    /// `entry_id` names the conflict, which is the identifier the conflict record carries.
    /// An identifier rather than a position on purpose: a position shifts as soon as one
    /// conflict is decided, and a caller that kept the list it displayed would then decide
    /// the wrong entry.
    ///
    /// What each decision means for each shape is documented on
    /// [`qualia2fa_core::sync::Decision`]; the rules stay in the core.
    ///
    /// # Errors
    ///
    /// [`FfiError::UnknownConflict`] when nothing is waiting for that identifier, and the
    /// core's error when the conflict no longer describes the vault (the entry was deleted
    /// or re-created in the meantime). Nothing is written when the call fails, and the
    /// conflict stays pending.
    pub fn adjudicate(&self, entry_id: String, decision: FfiDecision) -> Result<(), FfiError> {
        let conflict = {
            let mut pending = self.lock_pending();
            let index = pending
                .iter()
                .position(|conflict| conflict.entry_id.to_string() == entry_id)
                .ok_or_else(|| FfiError::UnknownConflict {
                    entry_id: entry_id.clone(),
                })?;
            pending.remove(index)
        };

        let outcome = {
            let mut vault = self.vault.lock();
            adjudicate(vault.vault_mut(), &conflict, decision.into())
        };
        match outcome {
            Ok(_) => Ok(()),
            Err(error) => {
                // The decision did not apply, so the conflict is still open and has to stay
                // where the caller can see it.
                self.lock_pending().push(conflict);
                Err(error.into())
            }
        }
    }
}

impl FfiSyncSession {
    /// Takes the replay-log lock, ignoring poisoning (see [`FfiVault::lock`]).
    fn lock_seen(&self) -> std::sync::MutexGuard<'_, SeenSyncIds> {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Takes the pending-conflict lock, ignoring poisoning.
    ///
    /// **Lock order**: this lock is taken while the vault lock is held in
    /// [`FfiSyncSession::pending_conflicts`], so the vault always comes first.
    /// [`FfiSyncSession::adjudicate`] takes a conflict **out** of the list and releases this
    /// lock before it reaches for the vault, so the two orders never nest into a cycle.
    fn lock_pending(&self) -> std::sync::MutexGuard<'_, Vec<Conflict>> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Lower-case hexadecimal form of a byte string.
///
/// Same form as every other identifier at this boundary; the core's own `Display` is used
/// where the type has one (`EntryId`), and this covers the raw byte strings that do not.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0F), 16).unwrap_or('0'));
    }
    out
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
            Err(other) => panic!("unexpected error kind {}", other.kind()),
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
            core_error_kind(&Error::SyncAlreadyApplied),
            core_error_kind(&Error::SyncNoSessionFound),
            core_error_kind(&Error::SyncSenderMismatch),
            core_error_kind(&Error::SyncAuthenticationFailed),
            core_error_kind(&Error::SyncIdLogFull { limit: 4096 }),
            core_error_kind(&Error::TransportFailed { reason: "test" }),
            core_error_kind(&Error::TransportAlreadyUsed),
            core_error_kind(&Error::TransportMessageTooLarge {
                needed: 100,
                limit: 10,
            }),
            core_error_kind(&Error::TransportUnsupported { operation: "test" }),
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

    // ── Synchronization across the boundary ──────────────────────────

    /// A channel for tests: two queues and no protocol of its own.
    ///
    /// It makes no decisions on purpose. A channel that de-duplicated, reordered or
    /// retried would hide exactly the defects these tests are looking for, because every
    /// protocol rule is supposed to live in the core.
    struct MemoryChannel {
        /// This device's identifier, hexadecimal.
        me: String,
        /// The capabilities this channel declares.
        caps: FfiTransportCapabilities,
        /// Outbound queue: `(recipient, bytes)`.
        outbox: std::sync::Mutex<Vec<(FfiRecipient, Vec<u8>)>>,
        /// Inbound queue, with the sender the channel claims for each message.
        inbox: std::sync::Mutex<Vec<FfiReceivedMessage>>,
        /// Peers this channel claims.
        peers: Vec<String>,
    }

    impl MemoryChannel {
        /// An empty two-party channel for the device with this identifier.
        fn new(me: String) -> Self {
            Self {
                me,
                caps: FfiTransportCapabilities {
                    roster: FfiRoster::TwoParty,
                    // The code channel of the application is text: the user carries the
                    // payload by hand, so it has no per-message limit.
                    max_message_len: None,
                    max_qr_version: None,
                    single_use: false,
                    can_carry_payload: true,
                },
                outbox: std::sync::Mutex::new(Vec::new()),
                inbox: std::sync::Mutex::new(Vec::new()),
                peers: Vec::new(),
            }
        }

        /// Moves this channel's outbound queue into another channel's inbound queue.
        ///
        /// The outbound queue is **not** cleared, so one payload can be delivered again —
        /// which is how the replay cases are exercised.
        ///
        /// With `honest` set to `false` the claimed sender is replaced by this channel's
        /// own identifier, which models a third party handing over somebody else's payload.
        fn deliver_to(&self, target: &Self, honest: bool) {
            let outbox = self.outbox.lock().expect("no lock poisoning in tests");
            let mut inbox = target.inbox.lock().expect("no lock poisoning in tests");
            for (recipient, bytes) in outbox.iter() {
                let addressed = match recipient {
                    FfiRecipient::All => true,
                    FfiRecipient::One { device_id } => *device_id == target.me,
                };
                if !addressed {
                    continue;
                }
                inbox.push(FfiReceivedMessage {
                    sender: if honest {
                        self.me.clone()
                    } else {
                        target.me.clone()
                    },
                    message: bytes.clone(),
                });
            }
        }

        /// Discards every message in the outbound queue.
        fn clear_outbox(&self) {
            self.outbox
                .lock()
                .expect("no lock poisoning in tests")
                .clear();
        }

        /// Pushes a message straight into the inbound queue, as an attacker would.
        fn inject(&self, claimed_sender: String, message: Vec<u8>) {
            self.inbox
                .lock()
                .expect("no lock poisoning in tests")
                .push(FfiReceivedMessage {
                    sender: claimed_sender,
                    message,
                });
        }
    }

    impl FfiTransport for MemoryChannel {
        fn capabilities(&self) -> FfiTransportCapabilities {
            self.caps
        }

        fn local_device(&self) -> String {
            self.me.clone()
        }

        fn send(&self, to: FfiRecipient, message: Vec<u8>) -> Result<(), FfiError> {
            self.outbox
                .lock()
                .expect("no lock poisoning in tests")
                .push((to, message));
            Ok(())
        }

        fn receive(&self) -> Result<Option<FfiReceivedMessage>, FfiError> {
            let mut inbox = self.inbox.lock().expect("no lock poisoning in tests");
            if inbox.is_empty() {
                // "Nothing available" is a state, not a failure.
                return Ok(None);
            }
            Ok(Some(inbox.remove(0)))
        }

        fn peers(&self) -> Result<Vec<String>, FfiError> {
            Ok(self.peers.clone())
        }
    }

    /// A device identifier for tests: one hexadecimal digit repeated to 64 characters.
    fn test_device_id(digit: char) -> String {
        std::iter::repeat_n(digit, 64).collect()
    }

    /// Registers a vault and hands back the store holding its master key.
    fn registered_vault(label: &str) -> (Arc<FfiVault>, Arc<TestStore>) {
        let store = Arc::new(TestStore::default());
        let vault = FfiVault::register(
            Arc::new(TestKeys::default()),
            store.clone(),
            label.to_owned(),
        )
        .expect("registration should succeed");
        (vault, store)
    }

    /// The second device of the same account: the same master key, its own empty vault.
    fn vault_of_the_same_account(store: &TestStore) -> Arc<FfiVault> {
        let master = store
            .master
            .lock()
            .expect("no lock poisoning in tests")
            .clone()
            .expect("the account is registered, so a master key exists");
        FfiVault::from_master_key(master).expect("32 bytes are a master key")
    }

    /// Two devices of one account, both holding the same entry.
    struct TwoDevices {
        /// The first device's vault.
        vault_a: Arc<FfiVault>,
        /// The second device's vault.
        vault_b: Arc<FfiVault>,
        /// The first device's session.
        session_a: Arc<FfiSyncSession>,
        /// The second device's session.
        session_b: Arc<FfiSyncSession>,
        /// The first device's channel.
        channel_a: Arc<MemoryChannel>,
        /// The second device's channel.
        channel_b: Arc<MemoryChannel>,
        /// The identifier the two devices share.
        entry_id: String,
    }

    impl TwoDevices {
        /// Registers A, gives B the same master key, and syncs one entry from A to B.
        fn with_one_shared_entry() -> Self {
            let (vault_a, store_a) = registered_vault("device-a");
            let vault_b = vault_of_the_same_account(&store_a);
            let entry_id = vault_a
                .add_entry(sample_entry("GitHub"), NOW)
                .expect("the entry should be added");

            let devices = Self {
                session_a: FfiSyncSession::open(vault_a.clone()),
                session_b: FfiSyncSession::open(vault_b.clone()),
                channel_a: Arc::new(MemoryChannel::new(test_device_id('a'))),
                channel_b: Arc::new(MemoryChannel::new(test_device_id('b'))),
                vault_a,
                vault_b,
                entry_id,
            };

            let outcome = devices.sync_a_to_b();
            assert_eq!(outcome.added, 1, "precondition: B receives the entry");
            devices.channel_a.clear_outbox();
            devices
        }

        /// Sends A's state to B's channel and merges it there.
        fn sync_a_to_b(&self) -> FfiSyncOutcome {
            self.session_a
                .send(
                    self.channel_a.clone(),
                    FfiRecipient::All,
                    FfiPayloadKind::Vault,
                )
                .expect("sending should succeed");
            self.channel_a.deliver_to(&self.channel_b, true);
            self.session_b
                .receive(self.channel_b.clone())
                .expect("receiving should succeed")
        }
    }

    /// **The criterion for the whole feature**: two vaults exchange their entries through a
    /// channel, in one process.
    ///
    /// Asserting "no error" would not be enough: a session that sends an empty payload and
    /// merges nothing reports no error either. What is asserted is that the entry really
    /// arrives and keeps its identifier, that the way back changes nothing, and that a
    /// re-delivered payload is refused.
    #[test]
    fn two_vaults_complete_a_sync_across_the_boundary() {
        let (vault_a, store_a) = registered_vault("device-a");
        let vault_b = vault_of_the_same_account(&store_a);
        let entry_id = vault_a
            .add_entry(sample_entry("GitHub"), NOW)
            .expect("the entry should be added");
        assert_eq!(vault_b.entry_count(), 0, "precondition: B starts empty");

        let session_a = FfiSyncSession::open(vault_a.clone());
        let session_b = FfiSyncSession::open(vault_b.clone());
        let channel_a = Arc::new(MemoryChannel::new(test_device_id('a')));
        let channel_b = Arc::new(MemoryChannel::new(test_device_id('b')));

        let plan = session_a
            .plan_share(channel_a.clone())
            .expect("planning should succeed");
        assert!(
            matches!(plan, FfiSharePlan::FullPayload { len } if len > 0),
            "a vault with one entry plans as a full payload: {plan:?}"
        );

        let sync_id = session_a
            .send(channel_a.clone(), FfiRecipient::All, FfiPayloadKind::Vault)
            .expect("sending should succeed");
        assert_eq!(sync_id.len(), 64, "a payload identifier is 32 bytes in hex");

        channel_a.deliver_to(&channel_b, true);
        let outcome = session_b
            .receive(channel_b.clone())
            .expect("receiving should succeed");
        assert_eq!(outcome.added, 1, "the entry must arrive: {outcome:?}");
        assert!(
            !outcome.needs_adjudication,
            "an ordinary sync asks the user nothing: {outcome:?}"
        );
        assert!(!outcome.made_no_change, "something did change: {outcome:?}");
        assert_eq!(vault_b.entry_count(), 1);
        let arrived = vault_b.entries();
        assert_eq!(arrived[0].name, "GitHub");
        assert_eq!(
            arrived[0].id, entry_id,
            "the entry keeps its identifier, which is the only thing the two devices agree on"
        );

        let replay = session_b
            .receive(channel_b.clone())
            .expect_err("nothing is queued any more, so the channel reports no session");
        assert_eq!(replay.kind(), "sync_no_session_found");

        // Delivering the very same bytes again is a replay, and is refused.
        channel_a.deliver_to(&channel_b, true);
        let replay = session_b
            .receive(channel_b.clone())
            .expect_err("the same payload must not be applied twice");
        assert_eq!(replay.kind(), "sync_already_applied");

        session_b
            .send(channel_b.clone(), FfiRecipient::All, FfiPayloadKind::Vault)
            .expect("sending back should succeed");
        channel_b.deliver_to(&channel_a, true);
        let back = session_a
            .receive(channel_a.clone())
            .expect("receiving should succeed");
        assert!(
            back.made_no_change,
            "A already holds everything B has: {back:?}"
        );
        assert!(!back.needs_adjudication);
    }

    /// A payload that claims a different sender than the channel reports is refused.
    ///
    /// This is the third-party case: the payload is cryptographically valid, so only the
    /// channel's own report can tell that somebody else handed it over.
    #[test]
    fn a_payload_whose_sender_disagrees_with_the_channel_is_refused() {
        let devices = TwoDevices::with_one_shared_entry();
        let mut second_entry = sample_entry("GitLab");
        second_entry.name = "GitLab".to_owned();
        devices
            .vault_a
            .add_entry(second_entry, NOW + 10)
            .expect("the entry should be added");

        devices
            .session_a
            .send(
                devices.channel_a.clone(),
                FfiRecipient::All,
                FfiPayloadKind::Vault,
            )
            .expect("sending should succeed");
        devices.channel_a.deliver_to(&devices.channel_b, false);

        let error = devices
            .session_b
            .receive(devices.channel_b.clone())
            .expect_err("a misreported sender must be refused");
        assert_eq!(error.kind(), "sync_sender_mismatch");
        assert_eq!(
            devices.vault_b.entry_count(),
            1,
            "a refused payload must not modify the vault"
        );
    }

    /// A device identifier that is not hexadecimal is refused before anything is sent.
    #[test]
    fn an_identifier_that_is_not_hexadecimal_is_refused() {
        let (vault, _) = registered_vault("device-a");
        let session = FfiSyncSession::open(vault);
        let channel = Arc::new(MemoryChannel::new("not a device identifier".to_owned()));

        let error = session
            .send(channel, FfiRecipient::All, FfiPayloadKind::Vault)
            .expect_err("the identifier must be rejected");
        assert_eq!(error.kind(), "invalid_device_id");
    }

    /// A decision for a conflict that is not waiting is refused rather than applied to
    /// whatever now sits under that identifier.
    #[test]
    fn a_decision_for_a_conflict_that_is_not_waiting_is_refused() {
        let (vault, _) = registered_vault("device-a");
        let session = FfiSyncSession::open(vault);

        let error = session
            .adjudicate("0".repeat(32), FfiDecision::KeepLocal)
            .expect_err("nothing is waiting for this identifier");
        assert_eq!(error.kind(), "unknown_conflict");
    }

    /// A deletion the peer reports about an entry **edited here** is a decision for a human.
    ///
    /// The two directions of "one side deleted it" are pinned separately: here the peer
    /// deleted and this device edited afterwards; the nested test covers the other one.
    #[test]
    fn a_peer_deletion_of_an_edited_entry_is_reported_and_closed_by_the_decision() {
        let devices = TwoDevices::with_one_shared_entry();

        let mut edited = sample_entry("GitHub (work)");
        edited.id = devices.entry_id.clone();
        devices
            .vault_b
            .update_entry(edited, NOW + 120)
            .expect("the edit should be accepted");
        devices
            .vault_a
            .remove_entry(devices.entry_id.clone(), NOW + 60)
            .expect("the deletion should be accepted");

        let outcome = devices.sync_a_to_b();
        assert!(
            outcome.needs_adjudication,
            "a deletion against an edited entry must be reported: {outcome:?}"
        );
        assert_eq!(
            outcome.deletions_applied, 0,
            "nothing may be deleted before the user decides"
        );
        assert_eq!(
            devices.vault_b.entry_count(),
            1,
            "the entry is still there until the decision"
        );
        assert_eq!(outcome.conflicts.len(), 1);
        let conflict = &outcome.conflicts[0];
        assert_eq!(conflict.kind, "peer_deleted");
        assert_eq!(conflict.entry_id, devices.entry_id);
        assert_eq!(
            conflict
                .local
                .as_ref()
                .expect("the local version is shown")
                .name,
            "GitHub (work)"
        );
        assert!(
            conflict.incoming.is_none(),
            "the peer sent a tombstone, which has nothing to show"
        );
        assert!(
            devices.session_b.pending_conflicts().len() == 1,
            "the conflict stays available until it is decided"
        );

        devices
            .session_b
            .adjudicate(devices.entry_id.clone(), FfiDecision::TakeIncoming)
            .expect("the decision should apply");
        assert_eq!(devices.vault_b.entry_count(), 0, "the deletion is applied");
        assert_eq!(devices.vault_b.tombstone_count(), 1);
        assert!(
            devices.session_b.pending_conflicts().is_empty(),
            "a decided conflict stops being pending"
        );

        devices.channel_a.clear_outbox();
        let settled = devices.sync_a_to_b();
        assert!(
            !settled.needs_adjudication,
            "the decision must close the conflict: {settled:?}"
        );
    }

    /// An entry deleted **here** that the peer still holds can be kept deleted.
    #[test]
    fn a_local_deletion_can_be_confirmed_against_a_peer_that_still_has_the_entry() {
        let devices = TwoDevices::with_one_shared_entry();
        devices
            .vault_b
            .remove_entry(devices.entry_id.clone(), NOW + 60)
            .expect("the deletion should be accepted");

        let outcome = devices.sync_a_to_b();
        assert!(outcome.needs_adjudication, "{outcome:?}");
        let conflict = &outcome.conflicts[0];
        assert_eq!(conflict.kind, "local_deleted");
        assert!(
            conflict.local.is_none(),
            "this device holds only a tombstone, so there is no local version to show"
        );
        assert_eq!(
            conflict
                .incoming
                .as_ref()
                .expect("the peer's version is shown")
                .name,
            "GitHub"
        );

        devices
            .session_b
            .adjudicate(devices.entry_id.clone(), FfiDecision::KeepLocal)
            .expect("the decision should apply");
        assert_eq!(devices.vault_b.entry_count(), 0, "the entry stays deleted");
        assert!(
            devices.vault_b.tombstone_count() == 1,
            "the deletion is still recorded, so it keeps travelling"
        );
    }

    /// The same conflict, decided the other way: the entry comes back.
    ///
    /// This is the case that needs the tombstone to be dropped: keeping it next to a live
    /// entry would let the payload builder send the tombstone on its own, and the peer would
    /// delete the entry again.
    #[test]
    fn an_entry_deleted_here_can_be_restored_from_the_peer() {
        let devices = TwoDevices::with_one_shared_entry();
        devices
            .vault_b
            .remove_entry(devices.entry_id.clone(), NOW + 60)
            .expect("the deletion should be accepted");

        let outcome = devices.sync_a_to_b();
        assert_eq!(outcome.conflicts[0].kind, "local_deleted");
        devices
            .session_b
            .adjudicate(devices.entry_id.clone(), FfiDecision::TakeIncoming)
            .expect("the decision should apply");

        assert_eq!(devices.vault_b.entry_count(), 1, "the entry is back");
        assert_eq!(
            devices.vault_b.tombstone_count(),
            0,
            "the tombstone must be gone, or the peer would delete the entry again"
        );
        assert_eq!(
            devices
                .vault_b
                .entry(devices.entry_id.clone())
                .expect("the entry is readable")
                .name,
            "GitHub"
        );

        devices.channel_a.clear_outbox();
        let settled = devices.sync_a_to_b();
        assert!(
            !settled.needs_adjudication,
            "the decision must close the conflict: {settled:?}"
        );
        assert!(settled.made_no_change, "both sides now hold the same entry");
    }

    /// A payload that authenticates but is not a payload at all is refused without touching
    /// the vault, and the error says which layer rejected it.
    #[test]
    fn a_garbage_payload_is_refused_across_the_boundary() {
        let devices = TwoDevices::with_one_shared_entry();
        devices
            .channel_b
            .inject(test_device_id('a'), vec![0_u8; 200]);

        let error = devices
            .session_b
            .receive(devices.channel_b.clone())
            .expect_err("random bytes are not a payload");
        assert_eq!(
            error.kind(),
            "sync_bad_magic",
            "the header is checked before anything is decrypted"
        );
        assert_eq!(devices.vault_b.entry_count(), 1, "the vault is untouched");
    }
}
