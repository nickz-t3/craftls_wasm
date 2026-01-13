//! Craftls - Customizable TLS ClientHello fingerprinting
//!
//! This module provides functionality to customize the TLS ClientHello message
//! to match browser fingerprints. This is useful for applications that need to
//! appear as specific browsers to avoid TLS fingerprinting detection.
//!
//! # Available Fingerprints
//!
//! * [`CHROME_108`] - Chrome 108 fingerprint
//! * [`CHROME_112`] - Chrome 112 fingerprint (with extension shuffling)
//! * [`SAFARI_17_1`] - Safari 17.1 fingerprint
//! * [`FIREFOX_105`] - Firefox 105 fingerprint
//!
//! # Example
//!
//! ```rust,ignore
//! use rustls::craft::CHROME_108;
//!
//! let config = rustls::ClientConfig::builder(provider)
//!     .with_root_certificates(root_store)
//!     .with_no_client_auth()
//!     .unwrap()
//!     .with_fingerprint(CHROME_108.builder());
//! ```

mod fingerprints;
pub use fingerprints::*;

use alloc::vec::Vec;
use core::fmt::Debug;

use rand::{thread_rng, Rng};

use crate::client::ClientConnectionData;
use crate::common_state::Context;
use crate::crypto::kx::{NamedGroup, StartedKeyExchange};
use crate::crypto::{CipherSuite, SignatureScheme};
use crate::enums::ProtocolVersion;
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::{ClientExtensions, HelloRetryRequest, KeyShareEntry};
use crate::ClientConfig;

/// Internal craft options stored in ClientConfig
#[derive(Clone, Debug, Default)]
pub struct CraftOptions(pub(crate) Option<FingerprintBuilder>);

impl CraftOptions {
    /// Check if craft options are enabled
    pub fn is_enabled(&self) -> bool {
        self.0.is_some()
    }

    fn get(&self) -> &FingerprintBuilder {
        self.0.as_ref().expect(
            "The tls client config doesn't contain a fingerprint, \
             please consider calling ClientConfig::with_fingerprint(...)",
        )
    }

    /// Apply fingerprint patches to extensions
    pub(crate) fn patch_extensions(
        &self,
        cx: &mut Context<'_, ClientConnectionData>,
        config: &ClientConfig,
        hrr: Option<&HelloRetryRequest>,
        exts: &mut ClientExtensions<'_>,
    ) {
        if let Some(builder) = &self.0 {
            builder
                .fingerprint
                .patch_extensions(cx, config, hrr, exts);
        }
    }

    /// Apply fingerprint patches to cipher suites
    pub(crate) fn patch_cipher_suites(
        &self,
        cx: &mut Context<'_, ClientConnectionData>,
        cipher_suites: &mut Vec<CipherSuite>,
    ) {
        if let Some(builder) = &self.0 {
            if builder.override_suite {
                builder
                    .fingerprint
                    .patch_cipher_suites(cx, cipher_suites);
            }
        }
    }
}

#[allow(dead_code)]
#[repr(usize)]
enum BoringSslGreaseIndex {
    Cipher,
    Group,
    Extension1,
    Extension2,
    Version,
    TicketExtension,
    EchConfigId,
    NumOfGrease,
}

#[derive(Debug)]
struct GreaseSeed([u16; BoringSslGreaseIndex::NumOfGrease as usize]);

impl GreaseSeed {
    fn get(&self, idx: BoringSslGreaseIndex) -> u16 {
        self.0[idx as usize]
    }
}

/// Connection-specific craft data
pub struct CraftConnectionData {
    grease_seed: GreaseSeed,
    /// Alternative key shares for fingerprint matching
    pub(crate) our_key_share_alt: Vec<StartedKeyExchange>,
    /// Extension ordering for consistent fingerprinting
    pub(crate) extension_order: Vec<usize>,
}

impl Debug for CraftConnectionData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CraftConnectionData")
            .field("grease_seed", &self.grease_seed)
            .field("our_key_share_alt", &"hidden")
            .finish()
    }
}

impl CraftConnectionData {
    /// Create new craft connection data with random GREASE seeds
    pub fn new() -> Self {
        use BoringSslGreaseIndex::*;
        let mut grease_seed = [0u16; NumOfGrease as usize];
        thread_rng().fill(&mut grease_seed);
        for seed in grease_seed.iter_mut() {
            let unit = (*seed & 0xf0u16) | 0x0au16;
            *seed = unit << 8 | unit;
        }
        if grease_seed[Extension1 as usize] == grease_seed[Extension2 as usize] {
            grease_seed[Extension2 as usize] ^= 0x1010;
        }
        Self {
            grease_seed: GreaseSeed(grease_seed),
            our_key_share_alt: Vec::new(),
            extension_order: Vec::new(),
        }
    }

    /// Find and remove a key share for the target group
    pub(crate) fn find_key_share(&mut self, target_group: NamedGroup) -> Option<StartedKeyExchange> {
        for i in 0..self.our_key_share_alt.len() {
            if self.our_key_share_alt[i].group() == target_group {
                return Some(self.our_key_share_alt.swap_remove(i));
            }
        }
        None
    }
}

impl Default for CraftConnectionData {
    fn default() -> Self {
        Self::new()
    }
}

/// An enum representing either a valid value of type `T` or a GREASE placeholder.
///
/// GREASE (Generate Random Extensions And Sustain Extensibility) values are
/// randomly generated per session to prevent TLS ecosystem ossification.
#[derive(Debug, Clone)]
pub enum GreaseOr<T> {
    /// A GREASE placeholder value, which will be generated randomly per session.
    Grease,
    /// A valid value of the generic type `T`.
    Value(T),
}

impl<T: Clone> GreaseOr<T> {
    /// Check if this is a GREASE placeholder
    pub fn is_grease(&self) -> bool {
        matches!(self, Self::Grease)
    }

    /// Get the value, panicking if it's GREASE
    pub fn val(&self) -> T {
        match self {
            Self::Grease => panic!("Cannot get value from GREASE placeholder"),
            Self::Value(t) => t.clone(),
        }
    }
}

pub(crate) trait CreateUnknown: Clone + Debug {
    fn create_unknown(grease: u16) -> Self;
}

impl<T> GreaseOr<T> {
    fn val_or(&self, grease: u16) -> T
    where
        T: CreateUnknown,
    {
        match self {
            Self::Grease => T::create_unknown(grease),
            Self::Value(t) => t.clone(),
        }
    }
}

impl<T> From<T> for GreaseOr<T> {
    fn from(value: T) -> Self {
        Self::Value(value)
    }
}

/// A type that can either hold a valid `NamedGroup` or serve as a GREASE placeholder.
pub type GreaseOrCurve = GreaseOr<NamedGroup>;

/// A type that can either hold a valid `ProtocolVersion` or serve as a GREASE placeholder.
pub type GreaseOrVersion = GreaseOr<ProtocolVersion>;

/// A type that can either hold a valid `CipherSuite` or serve as a GREASE placeholder.
pub type GreaseOrCipher = GreaseOr<CipherSuite>;

impl CreateUnknown for NamedGroup {
    fn create_unknown(grease: u16) -> Self {
        Self::Unknown(grease)
    }
}

impl CreateUnknown for ProtocolVersion {
    fn create_unknown(grease: u16) -> Self {
        Self::Unknown(grease)
    }
}

impl CreateUnknown for CipherSuite {
    fn create_unknown(grease: u16) -> Self {
        Self::Unknown(grease)
    }
}

/// Craft client extension provides customization to rustls client extensions
#[derive(Debug, Clone)]
pub enum CraftExtension {
    /// The first GREASE extension in the list
    Grease1,
    /// The second GREASE extension in the list
    Grease2,
    /// RenegotiationInfo extension
    RenegotiationInfo,
    /// SupportedCurves that supports GREASE or NamedGroup
    SupportedCurves(&'static [GreaseOrCurve]),
    /// SupportedVersions that supports GREASE or TLS versions
    SupportedVersions(&'static [GreaseOrVersion]),
    /// Signed Certificate Timestamp extension
    SignedCertificateTimestamp,
    /// KeyShare that supports GREASE or NamedGroup
    KeyShare(&'static [GreaseOrCurve]),
    /// Fake BoringSSL ApplicationSettings
    FakeApplicationSettings,
    /// Client Hello Padding extension (BoringSSL style)
    Padding,
    /// ALPN extension
    Protocols(&'static [&'static [u8]]),
    /// Fake DelegatedCredentials extension
    FakeDelegatedCredentials(&'static [SignatureScheme]),
    /// Fake RecordSizeLimit extension
    FakeRecordSizeLimit(u16),
}

/// Specifies the retention policy for rustls-generated extensions
#[derive(Debug, Clone)]
pub enum KeepExtension {
    /// Extension must be provided by rustls
    Must(ExtensionType),
    /// Extension may be provided by rustls
    Optional(ExtensionType),
    /// Extension should be provided by rustls, or use the default
    OrDefault(ExtensionType, ExtensionType),
}

/// Extension specification for fingerprinting
#[derive(Debug, Clone)]
pub enum ExtensionSpec {
    /// A craft extension
    Craft(CraftExtension),
    /// Keep a rustls extension
    Keep(KeepExtension),
}

/// Represents a TLS fingerprint
///
/// # Available Fingerprints
/// * [`CHROME_108`]
/// * [`CHROME_112`]
/// * [`SAFARI_17_1`]
/// * [`FIREFOX_105`]
#[derive(Debug, Clone, Default)]
pub struct Fingerprint {
    /// The TLS ClientHello extensions in order
    pub extensions: &'static [ExtensionSpec],
    /// Whether extensions should be randomly shuffled
    pub shuffle_extensions: bool,
    /// The cipher suites in order
    pub cipher: &'static [GreaseOrCipher],
}

impl Fingerprint {
    /// Create a builder for this fingerprint
    pub fn builder(&self) -> FingerprintBuilder {
        FingerprintBuilder {
            fingerprint: self.clone(),
            override_alpn: true,
            strict_mode: true,
            override_supported_curves: true,
            override_version: true,
            override_keyshare: true,
            override_cert_compress: true,
            override_suite: true,
        }
    }

    fn patch_extensions(
        &self,
        cx: &mut Context<'_, ClientConnectionData>,
        config: &ClientConfig,
        _hrr: Option<&HelloRetryRequest>,
        exts: &mut ClientExtensions<'_>,
    ) {
        // Apply GREASE to named groups if configured
        if let Some(named_groups) = &mut exts.named_groups {
            for spec in self.extensions.iter() {
                if let ExtensionSpec::Craft(CraftExtension::SupportedCurves(curves)) = spec {
                    // Insert GREASE at appropriate position
                    for (i, curve) in curves.iter().enumerate() {
                        if curve.is_grease() && i <= named_groups.len() {
                            let grease_group = cx
                                .data
                                .craft
                                .grease_seed
                                .get(BoringSslGreaseIndex::Group);
                            named_groups.insert(i, NamedGroup::Unknown(grease_group));
                            break;
                        }
                    }
                    break;
                }
            }
        }

        // Apply GREASE to supported versions if configured
        if let Some(versions) = &mut exts.supported_versions {
            for spec in self.extensions.iter() {
                if let ExtensionSpec::Craft(CraftExtension::SupportedVersions(vers)) = spec {
                    let grease_ver = cx
                        .data
                        .craft
                        .grease_seed
                        .get(BoringSslGreaseIndex::Version);
                    // Check if we need to add GREASE version
                    if vers.iter().any(|v| v.is_grease()) {
                        versions.grease = Some(ProtocolVersion::Unknown(grease_ver));
                    }
                    break;
                }
            }
        }

        // Apply GREASE to key shares if configured
        if let Some(key_shares) = &mut exts.key_shares {
            for spec in self.extensions.iter() {
                if let ExtensionSpec::Craft(CraftExtension::KeyShare(ks_spec)) = spec {
                    // Insert GREASE key share at appropriate position
                    for (i, ks) in ks_spec.iter().enumerate() {
                        if ks.is_grease() && i <= key_shares.len() {
                            let grease_group = cx
                                .data
                                .craft
                                .grease_seed
                                .get(BoringSslGreaseIndex::Group);
                            key_shares.insert(
                                i,
                                KeyShareEntry::new(NamedGroup::Unknown(grease_group), &[0]),
                            );
                            break;
                        }
                    }
                    break;
                }
            }
        }
    }

    fn patch_cipher_suites(
        &self,
        cx: &mut Context<'_, ClientConnectionData>,
        cipher_suites: &mut Vec<CipherSuite>,
    ) {
        *cipher_suites = self
            .cipher
            .iter()
            .map(|c| {
                c.val_or(
                    cx.data
                        .craft
                        .grease_seed
                        .get(BoringSslGreaseIndex::Cipher),
                )
            })
            .collect();
    }
}

/// Builder for configuring a fingerprint
#[derive(Debug, Clone)]
pub struct FingerprintBuilder {
    pub(crate) fingerprint: Fingerprint,
    pub(crate) override_alpn: bool,
    pub(crate) strict_mode: bool,
    pub(crate) override_supported_curves: bool,
    pub(crate) override_version: bool,
    pub(crate) override_keyshare: bool,
    pub(crate) override_cert_compress: bool,
    pub(crate) override_suite: bool,
}

impl FingerprintBuilder {
    /// Don't override ALPN settings
    ///
    /// Use this when working with HTTP clients that manage ALPN internally.
    pub fn do_not_override_alpn(mut self) -> Self {
        self.override_alpn = false;
        self
    }

    /// Disable key share override (for testing)
    pub fn dangerous_disable_override_keyshare(mut self) -> Self {
        self.override_keyshare = false;
        self
    }

    /// Disable cipher suite override (for testing)
    pub fn dangerous_disable_override_suite(mut self) -> Self {
        self.override_suite = false;
        self
    }

    /// Enter test mode with relaxed checking
    pub fn dangerous_craft_test_mode(mut self) -> Self {
        self.strict_mode = false;
        self.override_alpn = false;
        self.override_version = false;
        self.override_cert_compress = false;
        self
    }

    pub(crate) fn build(self) -> CraftOptions {
        CraftOptions(Some(self))
    }
}

/// Collection of fingerprint variants for different ALPN configurations
pub struct FingerprintSet {
    /// Default fingerprint for HTTP/2 clients
    pub main: Fingerprint,
    /// Fingerprint for HTTP/1.1 clients
    pub test_alpn_http1: Fingerprint,
    /// Fingerprint without ALPN
    pub test_no_alpn: Fingerprint,
}

impl core::ops::Deref for FingerprintSet {
    type Target = Fingerprint;

    fn deref(&self) -> &Self::Target {
        &self.main
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grease_seed_generation() {
        let data = CraftConnectionData::new();
        // GREASE values should be in the form 0x?A?A where ? is the same nibble
        let grease = data.grease_seed.get(BoringSslGreaseIndex::Cipher);
        assert_eq!(grease & 0x0f0f, 0x0a0a, "GREASE value should match pattern 0x?A?A");
        assert_eq!((grease >> 8) & 0xf0, (grease & 0xf0), "High and low bytes should have same high nibble");
    }

    #[test]
    fn test_grease_extension_values_differ() {
        let data = CraftConnectionData::new();
        let ext1 = data.grease_seed.get(BoringSslGreaseIndex::Extension1);
        let ext2 = data.grease_seed.get(BoringSslGreaseIndex::Extension2);
        assert_ne!(ext1, ext2, "GREASE extension values should differ");
    }

    #[test]
    fn test_grease_or_is_grease() {
        let grease: GreaseOr<NamedGroup> = GreaseOr::Grease;
        assert!(grease.is_grease());

        let value: GreaseOr<NamedGroup> = GreaseOr::Value(NamedGroup::X25519);
        assert!(!value.is_grease());
    }

    #[test]
    fn test_grease_or_val() {
        let value: GreaseOr<NamedGroup> = GreaseOr::Value(NamedGroup::X25519);
        assert_eq!(value.val(), NamedGroup::X25519);
    }

    #[test]
    #[should_panic(expected = "Cannot get value from GREASE placeholder")]
    fn test_grease_or_val_panics_on_grease() {
        let grease: GreaseOr<NamedGroup> = GreaseOr::Grease;
        let _ = grease.val();
    }

    #[test]
    fn test_grease_or_val_or_creates_unknown() {
        let grease: GreaseOrCurve = GreaseOr::Grease;
        let result = grease.val_or(0x0a0a);
        assert_eq!(result, NamedGroup::Unknown(0x0a0a));

        let value: GreaseOrCurve = GreaseOr::Value(NamedGroup::X25519);
        let result = value.val_or(0x0a0a);
        assert_eq!(result, NamedGroup::X25519);
    }

    #[test]
    fn test_fingerprint_builder_methods() {
        let fingerprint = Fingerprint::default();
        let builder = fingerprint.builder();

        // Test builder methods
        let builder = builder.do_not_override_alpn();
        assert!(!builder.override_alpn);

        let builder = builder.dangerous_disable_override_keyshare();
        assert!(!builder.override_keyshare);

        let builder = builder.dangerous_disable_override_suite();
        assert!(!builder.override_suite);
    }

    #[test]
    fn test_fingerprint_builder_test_mode() {
        let fingerprint = Fingerprint::default();
        let builder = fingerprint.builder().dangerous_craft_test_mode();

        assert!(!builder.strict_mode);
        assert!(!builder.override_alpn);
        assert!(!builder.override_version);
        assert!(!builder.override_cert_compress);
    }

    #[test]
    fn test_craft_options_default() {
        let opts = CraftOptions::default();
        assert!(!opts.is_enabled());
    }

    #[test]
    fn test_craft_connection_data_default() {
        let data = CraftConnectionData::default();
        assert!(data.our_key_share_alt.is_empty());
        assert!(data.extension_order.is_empty());
    }

    #[test]
    fn test_chrome_108_fingerprint_exists() {
        // Just verify the fingerprint can be accessed
        let fp = &*CHROME_108;
        assert!(!fp.extensions.is_empty());
        assert!(!fp.cipher.is_empty());
    }

    #[test]
    fn test_chrome_112_fingerprint_exists() {
        let fp = &*CHROME_112;
        assert!(!fp.extensions.is_empty());
        assert!(fp.shuffle_extensions); // Chrome 112 shuffles extensions
    }

    #[test]
    fn test_safari_17_1_fingerprint_exists() {
        let fp = &*SAFARI_17_1;
        assert!(!fp.extensions.is_empty());
        assert!(!fp.cipher.is_empty());
    }

    #[test]
    fn test_firefox_105_fingerprint_exists() {
        let fp = &*FIREFOX_105;
        assert!(!fp.extensions.is_empty());
        assert!(!fp.cipher.is_empty());
    }

    #[test]
    fn test_fingerprint_set_deref() {
        // Test that FingerprintSet derefs to its main fingerprint
        let fp_set = &*CHROME_108;
        let _extensions = fp_set.extensions; // Should access main.extensions
    }
}
