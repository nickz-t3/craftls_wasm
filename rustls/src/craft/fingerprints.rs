//! Predefined browser fingerprints
//!
//! This module contains TLS fingerprints for various browsers.

#![allow(missing_docs)]

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use std::sync::LazyLock;

use super::*;
use crate::crypto::SignatureScheme;
use crate::msgs::enums::ExtensionType;

/// The signature algorithms of Chrome 108
pub static CHROME_108_SIGNATURE_ALGO: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA512,
];

/// Chrome 108 extension list
pub static CHROME_108_EXT: LazyLock<Vec<ExtensionSpec>> = LazyLock::new(|| {
    use ExtensionSpec::*;
    use KeepExtension::*;
    vec![
        Craft(CraftExtension::Grease1),
        Keep(Must(ExtensionType::ServerName)),
        Keep(Must(ExtensionType::ExtendedMasterSecret)),
        Craft(CraftExtension::RenegotiationInfo),
        Craft(CraftExtension::SupportedCurves(&[
            GreaseOr::Grease,
            GreaseOr::Value(NamedGroup::X25519),
            GreaseOr::Value(NamedGroup::secp256r1),
            GreaseOr::Value(NamedGroup::secp384r1),
        ])),
        Keep(Must(ExtensionType::ECPointFormats)),
        Keep(OrDefault(
            ExtensionType::SessionTicket,
            ExtensionType::SessionTicket,
        )),
        Craft(CraftExtension::Protocols(&[b"h2", b"http/1.1"])),
        Keep(Must(ExtensionType::StatusRequest)),
        Keep(Must(ExtensionType::SignatureAlgorithms)),
        Craft(CraftExtension::SignedCertificateTimestamp),
        Craft(CraftExtension::KeyShare(&[
            GreaseOr::Grease,
            GreaseOr::Value(NamedGroup::X25519),
        ])),
        Keep(Must(ExtensionType::PSKKeyExchangeModes)),
        Keep(Optional(ExtensionType::EarlyData)),
        Craft(CraftExtension::SupportedVersions(&[
            GreaseOr::Grease,
            GreaseOr::Value(ProtocolVersion::TLSv1_3),
            GreaseOr::Value(ProtocolVersion::TLSv1_2),
        ])),
        Keep(Optional(ExtensionType::Cookie)),
        Keep(Optional(ExtensionType::CompressCertificate)),
        Craft(CraftExtension::FakeApplicationSettings),
        Craft(CraftExtension::Grease2),
        Craft(CraftExtension::Padding),
        Keep(Optional(ExtensionType::PreSharedKey)),
    ]
});

/// Chrome cipher list
///
/// This list includes CBC and TLS_RSA ciphers for correctness, even though
/// they are not supported by rustls due to security concerns.
pub static CHROME_CIPHER: LazyLock<Vec<GreaseOrCipher>> = LazyLock::new(|| {
    use CipherSuite::*;
    vec![
        GreaseOrCipher::Grease,
        TLS13_AES_128_GCM_SHA256.into(),
        TLS13_AES_256_GCM_SHA384.into(),
        TLS13_CHACHA20_POLY1305_SHA256.into(),
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.into(),
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.into(),
    ]
});

/// Chrome 108 fingerprint set
pub static CHROME_108: LazyLock<FingerprintSet> = LazyLock::new(|| FingerprintSet {
    main: Fingerprint {
        extensions: &*CHROME_108_EXT,
        cipher: &*CHROME_CIPHER,
        shuffle_extensions: false,
    },
    test_alpn_http1: Fingerprint {
        extensions: &*CHROME_108_EXT,
        cipher: &*CHROME_CIPHER,
        shuffle_extensions: false,
    },
    test_no_alpn: Fingerprint {
        extensions: &*CHROME_108_EXT,
        cipher: &*CHROME_CIPHER,
        shuffle_extensions: false,
    },
});

/// Chrome 112 fingerprint set (with extension shuffling)
pub static CHROME_112: LazyLock<FingerprintSet> = LazyLock::new(|| FingerprintSet {
    main: Fingerprint {
        extensions: &*CHROME_108_EXT,
        cipher: &*CHROME_CIPHER,
        shuffle_extensions: true,
    },
    test_alpn_http1: Fingerprint {
        extensions: &*CHROME_108_EXT,
        cipher: &*CHROME_CIPHER,
        shuffle_extensions: true,
    },
    test_no_alpn: Fingerprint {
        extensions: &*CHROME_108_EXT,
        cipher: &*CHROME_CIPHER,
        shuffle_extensions: true,
    },
});

/// Safari 17.1 signature algorithms
pub static SAFARI_17_1_SIGNATURE_ALGO: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_SHA1_Legacy,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA1,
];

/// Safari 17.1 cipher list
pub static SAFARI_17_1_CIPHERS: LazyLock<Vec<GreaseOrCipher>> = LazyLock::new(|| {
    use CipherSuite::*;
    vec![
        GreaseOrCipher::Grease,
        TLS13_AES_128_GCM_SHA256.into(),
        TLS13_AES_256_GCM_SHA384.into(),
        TLS13_CHACHA20_POLY1305_SHA256.into(),
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.into(),
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.into(),
    ]
});

/// Safari 17.1 extension list
pub static SAFARI_17_1_EXT: LazyLock<Vec<ExtensionSpec>> = LazyLock::new(|| {
    use ExtensionSpec::*;
    use KeepExtension::*;
    vec![
        Craft(CraftExtension::Grease1),
        Keep(Must(ExtensionType::ServerName)),
        Keep(Must(ExtensionType::ExtendedMasterSecret)),
        Craft(CraftExtension::RenegotiationInfo),
        Craft(CraftExtension::SupportedCurves(&[
            GreaseOr::Grease,
            GreaseOr::Value(NamedGroup::X25519),
            GreaseOr::Value(NamedGroup::secp256r1),
            GreaseOr::Value(NamedGroup::secp384r1),
            GreaseOr::Value(NamedGroup::secp521r1),
        ])),
        Keep(Must(ExtensionType::ECPointFormats)),
        Craft(CraftExtension::Protocols(&[b"h2", b"http/1.1"])),
        Keep(Must(ExtensionType::StatusRequest)),
        Keep(Must(ExtensionType::SignatureAlgorithms)),
        Craft(CraftExtension::SignedCertificateTimestamp),
        Craft(CraftExtension::KeyShare(&[
            GreaseOr::Grease,
            GreaseOr::Value(NamedGroup::X25519),
        ])),
        Keep(Must(ExtensionType::PSKKeyExchangeModes)),
        Craft(CraftExtension::SupportedVersions(&[
            GreaseOr::Grease,
            GreaseOr::Value(ProtocolVersion::TLSv1_3),
            GreaseOr::Value(ProtocolVersion::TLSv1_2),
            GreaseOr::Value(ProtocolVersion::TLSv1_1),
            GreaseOr::Value(ProtocolVersion::TLSv1_0),
        ])),
        Keep(Optional(ExtensionType::Cookie)),
        Keep(Optional(ExtensionType::CompressCertificate)),
        Craft(CraftExtension::Grease2),
        Craft(CraftExtension::Padding),
    ]
});

/// Safari 17.1 fingerprint set
pub static SAFARI_17_1: LazyLock<FingerprintSet> = LazyLock::new(|| FingerprintSet {
    main: Fingerprint {
        extensions: &*SAFARI_17_1_EXT,
        cipher: &*SAFARI_17_1_CIPHERS,
        shuffle_extensions: false,
    },
    test_alpn_http1: Fingerprint {
        extensions: &*SAFARI_17_1_EXT,
        cipher: &*SAFARI_17_1_CIPHERS,
        shuffle_extensions: false,
    },
    test_no_alpn: Fingerprint {
        extensions: &*SAFARI_17_1_EXT,
        cipher: &*SAFARI_17_1_CIPHERS,
        shuffle_extensions: false,
    },
});

/// Firefox 105 signature algorithms
pub static FIREFOX_105_SIGNATURE_ALGO: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::ECDSA_SHA1_Legacy,
    SignatureScheme::RSA_PKCS1_SHA1,
];

/// Firefox 105 cipher list
pub static FIREFOX_105_CIPHERS: LazyLock<Vec<GreaseOrCipher>> = LazyLock::new(|| {
    use CipherSuite::*;
    vec![
        TLS13_AES_128_GCM_SHA256.into(),
        TLS13_CHACHA20_POLY1305_SHA256.into(),
        TLS13_AES_256_GCM_SHA384.into(),
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.into(),
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.into(),
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.into(),
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.into(),
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.into(),
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.into(),
    ]
});

/// Firefox 105 extension list
pub static FIREFOX_105_EXT: LazyLock<Vec<ExtensionSpec>> = LazyLock::new(|| {
    use ExtensionSpec::*;
    use KeepExtension::*;
    vec![
        Keep(Must(ExtensionType::ServerName)),
        Keep(Must(ExtensionType::ExtendedMasterSecret)),
        Craft(CraftExtension::RenegotiationInfo),
        Craft(CraftExtension::SupportedCurves(&[
            GreaseOr::Value(NamedGroup::X25519),
            GreaseOr::Value(NamedGroup::secp256r1),
            GreaseOr::Value(NamedGroup::secp384r1),
            GreaseOr::Value(NamedGroup::secp521r1),
            GreaseOr::Value(NamedGroup::FFDHE2048),
            GreaseOr::Value(NamedGroup::FFDHE3072),
        ])),
        Keep(Must(ExtensionType::ECPointFormats)),
        Craft(CraftExtension::Protocols(&[b"h2", b"http/1.1"])),
        Keep(Must(ExtensionType::StatusRequest)),
        Craft(CraftExtension::FakeDelegatedCredentials(&[
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ECDSA_SHA1_Legacy,
        ])),
        Craft(CraftExtension::KeyShare(&[
            GreaseOr::Value(NamedGroup::X25519),
            GreaseOr::Value(NamedGroup::secp256r1),
        ])),
        Craft(CraftExtension::SupportedVersions(&[
            GreaseOr::Value(ProtocolVersion::TLSv1_3),
            GreaseOr::Value(ProtocolVersion::TLSv1_2),
        ])),
        Keep(Must(ExtensionType::SignatureAlgorithms)),
        Keep(Must(ExtensionType::PSKKeyExchangeModes)),
        Craft(CraftExtension::FakeRecordSizeLimit(0x4001)),
        Craft(CraftExtension::Padding),
        Keep(Optional(ExtensionType::PreSharedKey)),
    ]
});

/// Firefox 105 fingerprint set
pub static FIREFOX_105: LazyLock<FingerprintSet> = LazyLock::new(|| FingerprintSet {
    main: Fingerprint {
        extensions: &*FIREFOX_105_EXT,
        cipher: &*FIREFOX_105_CIPHERS,
        shuffle_extensions: false,
    },
    test_alpn_http1: Fingerprint {
        extensions: &*FIREFOX_105_EXT,
        cipher: &*FIREFOX_105_CIPHERS,
        shuffle_extensions: false,
    },
    test_no_alpn: Fingerprint {
        extensions: &*FIREFOX_105_EXT,
        cipher: &*FIREFOX_105_CIPHERS,
        shuffle_extensions: false,
    },
});
