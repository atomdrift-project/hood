//! End-to-end integration tests for the hood proxy.
//!
//! These tests stand up a small in-process HTTP server (over plain TCP for
//! the HTTP case, and a tokio-rustls-wrapped TCP for HTTPS), start a hood
//! proxy in front of it, and drive traffic through using reqwest configured
//! to trust the proxy's ephemeral CA. We don't depend on scan models here
//! — the scanner is [`hood::scanner::AllowAll`].

// Test code intentionally uses unwrap()/expect()/panic for fast-fail assertion
// semantics. Every other lint stays on — same bar as production code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use tokio::net::TcpListener;
use tokio_rustls::rustls::{self, pki_types::CertificateDer, pki_types::PrivateKeyDer};

use hood::go_bridge::GoBridge;
use hood::proxy::{Config, Proxy};
use hood::scanner::{AllowAll, BlockReason, DiskScanRequest, ScanRequest, Scanner, Verdict};

/// A scanner that blocks everything it is asked to inspect, in-memory or on
/// disk. Used to prove a path was *not* scanned: if a response still comes back
/// forwarded, the scanner was never consulted.
#[derive(Debug)]
struct BlockAll;

#[async_trait::async_trait]
impl Scanner for BlockAll {
    async fn scan(&self, _req: ScanRequest) -> Result<Verdict> {
        Ok(Verdict::Block(BlockReason::Hostile))
    }
    async fn scan_disk(&self, _req: DiskScanRequest) -> Result<Verdict> {
        Ok(Verdict::Block(BlockReason::Hostile))
    }
}

/// Body the test origin returns. Some plain ASCII so we don't accidentally
/// trip cleave/scan heuristics in tests that use the real scanner.
const PAYLOAD: &[u8] = b"hello from origin\n";

/// A larger, deterministic body used to exercise the spill-to-disk and
/// oversized-passthrough paths. 256 KiB so a small `max_body_bytes` forces a
/// spill and a small `max_scan_bytes` forces an unscanned forward.
fn big_payload() -> Vec<u8> {
    (0..256 * 1024).map(|i| (i % 251) as u8).collect()
}

async fn handle(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if req.uri().path() == "/redirect" {
        return Ok(Response::builder()
            .status(302)
            .header("location", "/hello")
            .body(Full::new(Bytes::new()))
            .unwrap());
    }
    let body = if req.uri().path() == "/big" {
        Bytes::from(big_payload())
    } else {
        Bytes::from_static(PAYLOAD)
    };
    Ok(Response::builder()
        .header("content-type", "application/octet-stream")
        .header("x-origin-marker", "yes")
        .body(Full::new(body))
        .unwrap())
}

async fn start_http_origin() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                drop(
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service_fn(handle))
                        .await,
                );
            });
        }
    });
    Ok(addr)
}

/// A throw-away origin TLS cert chain. Different CA from hood's (so we
/// exercise the upstream-TLS-verify code path of the proxy).
struct OriginTls {
    cert_chain: Vec<CertificateDer<'static>>,
    key_der: PrivateKeyDer<'static>,
    /// Root CA in PEM so the proxy can trust it for the test.
    root_pem: String,
}

fn make_origin_tls() -> Result<OriginTls> {
    let root_key = KeyPair::generate()?;
    let mut root_params = CertificateParams::default();
    root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "test origin root");
    root_params.distinguished_name = dn;
    let root_cert = root_params.self_signed(&root_key)?;

    let leaf_key = KeyPair::generate()?;
    let mut leaf_params = CertificateParams::default();
    leaf_params.subject_alt_names = vec![
        SanType::DnsName(rcgen::Ia5String::try_from("localhost".to_owned())?),
        SanType::IpAddress("127.0.0.1".parse()?),
    ];
    let leaf_cert = leaf_params.signed_by(&leaf_key, &root_cert, &root_key)?;

    Ok(OriginTls {
        cert_chain: vec![
            CertificateDer::from(leaf_cert.der().to_vec()),
            CertificateDer::from(root_cert.der().to_vec()),
        ],
        key_der: rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
        root_pem: root_cert.pem(),
    })
}

async fn start_https_origin() -> Result<(SocketAddr, String)> {
    let tls = make_origin_tls()?;
    let server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(tls.cert_chain, tls.key_der)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let root_pem = tls.root_pem.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls_stream) = acceptor.accept(stream).await else {
                    return;
                };
                drop(
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls_stream), service_fn(handle))
                        .await,
                );
            });
        }
    });
    Ok((addr, root_pem))
}

fn roots_from_pem(pem: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

/// Build a reqwest client that:
///   - routes through the hood proxy at `proxy_addr`
///   - trusts hood's ephemeral CA (so MITM cert verifies)
///   - trusts an additional CA (the origin's, for direct upstream TLS in proxy)
fn client_with_proxy(proxy_addr: SocketAddr, hood_ca_pem: &str) -> reqwest::Client {
    let proxy_url = format!("http://{proxy_addr}");
    let proxy_all = reqwest::Proxy::all(&proxy_url).unwrap();
    let mut builder = reqwest::Client::builder()
        .proxy(proxy_all)
        .danger_accept_invalid_certs(false)
        .tls_built_in_root_certs(true);
    for cert in rustls_pemfile::certs(&mut hood_ca_pem.as_bytes()).filter_map(Result::ok) {
        let der = cert.to_vec();
        builder = builder.add_root_certificate(reqwest::Certificate::from_der(&der).unwrap());
    }
    builder.build().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plaintext_http_round_trip_with_allow_all() -> Result<()> {
    drop(rustls::crypto::ring::default_provider().install_default());

    let origin_addr = start_http_origin().await?;
    let scanner: Arc<dyn Scanner> = Arc::new(AllowAll);
    let proxy = Proxy::new(scanner, Config::default())?;
    let hood_ca = proxy.ca_pem().to_owned();
    let handle = proxy.spawn().await?;

    let client = client_with_proxy(handle.addr, &hood_ca);
    let url = format!("http://{origin_addr}/hello");
    let resp = client.get(&url).send().await?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("x-origin-marker").unwrap(), "yes");
    let body = resp.bytes().await?;
    assert_eq!(body.as_ref(), PAYLOAD);

    handle.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_mitm_round_trip_with_allow_all() -> Result<()> {
    drop(rustls::crypto::ring::default_provider().install_default());

    let (origin_addr, origin_ca_pem) = start_https_origin().await?;
    let scanner: Arc<dyn Scanner> = Arc::new(AllowAll);

    let cfg = Config {
        extra_upstream_roots: roots_from_pem(&origin_ca_pem),
        ..Config::default()
    };
    let proxy = Proxy::new(scanner, cfg)?;
    let hood_ca = proxy.ca_pem().to_owned();
    let handle = proxy.spawn().await?;

    let client = client_with_proxy(handle.addr, &hood_ca);
    // Use "localhost" so reqwest sends SNI=localhost (the rustls SNI rule
    // says clients MUST NOT send an IP literal as SNI; without SNI the
    // proxy's leaf-cert resolver has nothing to mint).
    let url = format!("https://localhost:{}/hello", origin_addr.port());
    let resp = client.get(&url).send().await?;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await?;
    assert_eq!(body.as_ref(), PAYLOAD);

    handle.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn go_loopback_bridge_verifies_https_and_contains_redirects() -> Result<()> {
    drop(rustls::crypto::ring::default_provider().install_default());

    let (origin_addr, origin_ca_pem) = start_https_origin().await?;
    let scanner: Arc<dyn Scanner> = Arc::new(AllowAll);
    let cfg = Config {
        extra_upstream_roots: roots_from_pem(&origin_ca_pem),
        ..Config::default()
    };
    let proxy = Proxy::new(scanner, cfg)?;
    let token = proxy.go_bridge_token().to_owned();
    let handle = proxy.spawn().await?;
    let bridge = GoBridge::new(&format!("https://localhost:{}", origin_addr.port()), "off")?;
    let child = bridge.child_env(handle.addr, &token)?;

    // This client trusts no hood CA: like Go on macOS, it only speaks plain
    // HTTP to loopback. Hood verifies HTTPS on the upstream leg. The origin's
    // redirect must also be rewritten back through loopback before following.
    let client = reqwest::Client::builder().no_proxy().build()?;
    let resp = client
        .get(format!("{}/redirect", child.goproxy))
        .send()
        .await?;
    let status = resp.status();
    let origin_marker = resp.headers().get("x-origin-marker").cloned();
    let body = resp.bytes().await?;
    assert_eq!(
        status,
        200,
        "bridge response: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(origin_marker.unwrap(), "yes");
    assert_eq!(body.as_ref(), PAYLOAD);

    handle.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_body_spills_to_disk_and_forwards_intact() -> Result<()> {
    drop(rustls::crypto::ring::default_provider().install_default());

    let origin_addr = start_http_origin().await?;
    let scanner: Arc<dyn Scanner> = Arc::new(AllowAll);
    // RAM cap far below the 256 KiB body → spill to disk and scan from there
    // (AllowAll → allow); disk-scan cap generous so it's the scanned-from-disk
    // path, not the unscanned one.
    let cfg = Config {
        max_body_bytes: 4096,
        max_scan_bytes: 8 * 1024 * 1024,
        ..Config::default()
    };
    let proxy = Proxy::new(scanner, cfg)?;
    let hood_ca = proxy.ca_pem().to_owned();
    let handle = proxy.spawn().await?;

    let client = client_with_proxy(handle.addr, &hood_ca);
    let url = format!("http://{origin_addr}/big");
    let resp = client.get(&url).send().await?;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await?;
    assert_eq!(body.as_ref(), big_payload().as_slice());

    handle.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_body_forwards_unscanned_intact() -> Result<()> {
    drop(rustls::crypto::ring::default_provider().install_default());

    let origin_addr = start_http_origin().await?;
    // BlockAll would block anything it scans — so if the 256 KiB body still
    // comes back whole, it proves the body was forwarded *without* scanning
    // because it exceeded the disk-scan cap.
    let scanner: Arc<dyn Scanner> = Arc::new(BlockAll);
    let cfg = Config {
        max_body_bytes: 4096,
        max_scan_bytes: 16 * 1024, // 256 KiB body exceeds this → unscanned
        ..Config::default()
    };
    let proxy = Proxy::new(scanner, cfg)?;
    let hood_ca = proxy.ca_pem().to_owned();
    let handle = proxy.spawn().await?;

    let client = client_with_proxy(handle.addr, &hood_ca);
    let url = format!("http://{origin_addr}/big");
    let resp = client.get(&url).send().await?;
    assert_eq!(
        resp.status(),
        200,
        "oversized body must be forwarded, not blocked"
    );
    let body = resp.bytes().await?;
    assert_eq!(body.as_ref(), big_payload().as_slice());

    handle.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn head_request_is_forwarded_without_scanning() -> Result<()> {
    drop(rustls::crypto::ring::default_provider().install_default());

    // A HEAD reply carries no body. With BlockAll — which blocks anything it
    // scans — a HEAD that comes back forwarded proves the scanner was never
    // consulted (regression: an empty body was fed to the tar analyzer and
    // spuriously blocked as a scan error).
    let origin_addr = start_http_origin().await?;
    let scanner: Arc<dyn Scanner> = Arc::new(BlockAll);
    let proxy = Proxy::new(scanner, Config::default())?;
    let hood_ca = proxy.ca_pem().to_owned();
    let handle = proxy.spawn().await?;

    let client = client_with_proxy(handle.addr, &hood_ca);
    // `/big` would be a 256 KiB body on GET — definitely scanned-and-blocked if
    // the short-circuit failed.
    let url = format!("http://{origin_addr}/big");
    let resp = client.head(&url).send().await?;
    assert_eq!(
        resp.status(),
        200,
        "HEAD must be forwarded, not scan-blocked"
    );

    handle.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_returns_451() -> Result<()> {
    drop(rustls::crypto::ring::default_provider().install_default());

    let origin_addr = start_http_origin().await?;
    let scanner: Arc<dyn Scanner> = Arc::new(BlockAll);
    let proxy = Proxy::new(scanner, Config::default())?;
    let hood_ca = proxy.ca_pem().to_owned();
    let handle = proxy.spawn().await?;

    let client = client_with_proxy(handle.addr, &hood_ca);
    let url = format!("http://{origin_addr}/hello");
    let resp = client.get(&url).send().await?;
    assert_eq!(resp.status().as_u16(), 451);
    assert_eq!(
        resp.headers().get("x-hood-block-reason").unwrap(),
        "hostile"
    );

    handle.stop().await;
    Ok(())
}
