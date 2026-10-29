//! Ephemeral certificate authority used for transparent TLS interception.
//!
//! Each [`Ca`] generates a fresh root key + certificate in memory at
//! construction time. The root is never persisted to disk by this module —
//! callers may write the PEM to a tempfile so that child processes can trust
//! it via env vars like `NODE_EXTRA_CA_CERTS` / `CURL_CA_BUNDLE`, but the key
//! pair itself stays in process memory and dies with the process.
//!
//! Leaf certificates are minted on demand for each SNI hostname the proxy
//! sees, signed by the in-memory root, and cached so repeated requests to the
//! same host do not re-issue. A leaf shares the root's validity window, so a
//! cached leaf is good for exactly as long as the root that signed it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use anyhow::{Context, Result, anyhow};
use rcgen::string::Ia5String;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use time::{Duration, OffsetDateTime};

/// Default common name for the in-memory root certificate.
const ROOT_COMMON_NAME: &str = "hood ephemeral root";

/// Bound attacker-influenced SNI state. Hosts past this point are still served,
/// but their leaves are not retained for the lifetime of the process.
const MAX_CACHED_LEAVES: usize = 256;

/// Ephemeral root CA + leaf cert factory.
///
/// Cheap to clone — internally an `Arc` over the keypair and a shared cache.
#[derive(Clone)]
pub(crate) struct Ca {
    inner: Arc<Inner>,
}

struct Inner {
    /// Root distinguished name + key, in the form `signed_by` wants.
    root_issuer: Issuer<'static, KeyPair>,
    /// Root in DER, appended to every leaf chain we hand out.
    root_der: CertificateDer<'static>,
    root_pem: String,
    /// The root's validity window, which every leaf shares.
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl Inner {
    /// The leaf cache. Nothing panics while holding it, so a poisoned lock
    /// still guards a consistent map.
    fn cache(&self) -> MutexGuard<'_, HashMap<String, Arc<CertifiedKey>>> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl std::fmt::Debug for Ca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ca")
            .field("root_common_name", &ROOT_COMMON_NAME)
            .field("cached_leaves", &self.inner.cache().len())
            .finish()
    }
}

impl Ca {
    /// Generate a fresh root key + certificate.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation or certificate signing fails.
    pub(crate) fn generate() -> Result<Self> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        // Five minutes back tolerates a client clock running behind ours.
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::minutes(5);
        params.not_after = now + Duration::hours(24);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, ROOT_COMMON_NAME);
        dn.push(DnType::OrganizationName, "Atomdrift");
        params.distinguished_name = dn;

        let key = KeyPair::generate().context("generate root key")?;
        let cert = params.self_signed(&key).context("sign root cert")?;
        let root_pem = cert.pem();
        let root_der = CertificateDer::from(cert.der().to_vec());
        let (not_before, not_after) = (params.not_before, params.not_after);

        Ok(Self {
            inner: Arc::new(Inner {
                root_issuer: Issuer::new(params, key),
                root_der,
                root_pem,
                not_before,
                not_after,
                cache: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// PEM-encoded root certificate. Safe to share — contains no private key.
    #[must_use]
    pub(crate) fn root_pem(&self) -> &str {
        &self.inner.root_pem
    }

    /// Mint (or retrieve from cache) a leaf certificate signed by the root for
    /// the supplied DNS hostname or IP literal.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid host or a certificate generation failure.
    pub(crate) fn leaf_for(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        if let Some(hit) = self.inner.cache().get(host) {
            return Ok(Arc::clone(hit));
        }

        // Minted unlocked: concurrent handshakes to other hosts don't wait.
        let certified = self.mint_leaf(host)?;

        let mut cache = self.inner.cache();
        if cache.len() >= MAX_CACHED_LEAVES {
            return Ok(certified);
        }
        // Another thread might have populated it concurrently; prefer their copy.
        Ok(Arc::clone(
            cache.entry(host.to_owned()).or_insert(certified),
        ))
    }

    fn mint_leaf(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        let mut params = CertificateParams::default();
        let san = parse_san(host)?;
        params.subject_alt_names = vec![san];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.not_before = self.inner.not_before;
        params.not_after = self.inner.not_after;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;

        let leaf_key = KeyPair::generate().context("generate leaf key")?;
        let leaf_cert = params
            .signed_by(&leaf_key, &self.inner.root_issuer)
            .context("sign leaf cert")?;

        let cert_der = CertificateDer::from(leaf_cert.der().to_vec());
        let root_der = self.inner.root_der.clone();
        let key_der: PrivateKeyDer<'static> =
            PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into();

        let signing_key =
            rustls::crypto::ring::sign::any_supported_type(&key_der).context("load signing key")?;

        Ok(Arc::new(CertifiedKey::new(
            vec![cert_der, root_der],
            signing_key,
        )))
    }
}

fn parse_san(host: &str) -> Result<SanType> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SanType::IpAddress(ip));
    }
    let validated = rustls::pki_types::DnsName::try_from(host)
        .map_err(|e| anyhow!("invalid DNS name {host:?}: {e}"))?;
    let dns = Ia5String::try_from(validated.as_ref())
        .map_err(|e| anyhow!("invalid DNS name {host:?}: {e}"))?;
    Ok(SanType::DnsName(dns))
}

/// `rustls` cert resolver that mints leaves on the fly using a [`Ca`], for
/// one tunnel.
#[derive(Debug)]
pub(crate) struct CaResolver {
    ca: Ca,
    tunnel_host: String,
}

impl CaResolver {
    /// Wrap a CA for a tunnel to `tunnel_host`, which names the leaf when the
    /// client sends no SNI. Clients never send an IP literal as SNI (RFC 6066),
    /// so a tunnel to one, IPv4 or IPv6, has only its CONNECT target to go by.
    #[must_use]
    pub(crate) const fn new(ca: Ca, tunnel_host: String) -> Self {
        Self { ca, tunnel_host }
    }
}

impl ResolvesServerCert for CaResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = client_hello.server_name().unwrap_or(&self.tunnel_host);
        match self.ca.leaf_for(host) {
            Ok(ck) => Some(ck),
            Err(e) => {
                tracing::warn!(host, error = %e, "leaf mint failed");
                None
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use rustls::pki_types::pem::PemObject;

    use super::*;

    #[test]
    fn root_pem_round_trips() {
        let ca = Ca::generate().unwrap();
        let pem = ca.root_pem();
        assert!(pem.contains("BEGIN CERTIFICATE"));
        let parsed: Vec<_> = CertificateDer::pem_slice_iter(pem.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn leaf_cached_per_host() {
        let ca = Ca::generate().unwrap();
        let a1 = ca.leaf_for("example.com").unwrap();
        let a2 = ca.leaf_for("example.com").unwrap();
        let b = ca.leaf_for("other.test").unwrap();
        assert!(Arc::ptr_eq(&a1, &a2), "same host must hit cache");
        assert!(!Arc::ptr_eq(&a1, &b), "different host must mint fresh");
    }

    #[test]
    fn ip_literal_host() {
        let ca = Ca::generate().unwrap();
        let leaf = ca.leaf_for("127.0.0.1").unwrap();
        assert_eq!(leaf.cert.len(), 2, "leaf + root in chain");
    }

    #[test]
    fn invalid_hostname_rejected() {
        // SNI is attacker-chosen: anything that is not a DNS name or IP
        // literal must mint nothing.
        let ca = Ca::generate().unwrap();
        for host in ["näme.test", "a b.test", "a\0b.test", "a\nb.test", ""] {
            assert!(ca.leaf_for(host).is_err(), "{host:?}");
        }
    }
}
