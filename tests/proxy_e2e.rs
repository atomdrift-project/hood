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
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rcgen::{CertificateParams, DistinguishedName, DnType, Issuer, KeyPair, SanType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{
    self, pki_types::CertificateDer, pki_types::PrivateKeyDer, pki_types::pem::PemObject,
};

use hood::go_bridge::GoBridge;
use hood::proxy::{Config, Proxy};
use hood::scanner::{
    AllowAll, Anticipated, BlockReason, Disclosure, DiskScanRequest, ScanRequest, Scanner, Verdict,
};

/// A scanner that blocks everything it is asked to decide. Used to prove a
/// path was *not* scanned: if a response still comes back forwarded, the
/// scanner was never consulted.
#[derive(Debug)]
struct BlockAll;

#[async_trait::async_trait]
impl Scanner for BlockAll {
    async fn scan(&self, _req: ScanRequest) -> Verdict {
        Verdict::Block(BlockReason::Hostile)
    }
    async fn scan_disk(&self, _req: DiskScanRequest) -> Verdict {
        Verdict::Block(BlockReason::Hostile)
    }
    fn scan_limit(&self, _url: &str, _limit: u64, _size: Option<u64>) -> Verdict {
        withheld("download exceeds inspection limit")
    }
    fn uninspectable(&self, _url: &str, why: &str) -> Verdict {
        withheld(why)
    }
}

/// What both test scanners answer for a payload they cannot inspect.
fn withheld(why: &str) -> Verdict {
    Verdict::Block(BlockReason::ScanError(why.to_owned()))
}

/// Body the test origin returns. Some plain ASCII so we don't accidentally
/// trip cleave/scan heuristics in tests that use the real scanner.
const PAYLOAD: &[u8] = b"hello from origin\n";

/// A larger, deterministic body used to exercise the spill-to-disk and
/// inspection-limit paths. 256 KiB so a small `max_body_bytes` forces a
/// spill and a small `max_scan_bytes` exercises the failure policy.
fn big_payload() -> Vec<u8> {
    (0_u8..=250).cycle().take(256 * 1024).collect()
}

async fn handle(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if req.uri().path() == "/redirect" {
        return Ok(Response::builder()
            .status(302)
            .header("location", "/hello")
            .body(Full::new(Bytes::new()))
            .unwrap());
    }
    if req.uri().path() == "/missing" {
        return Ok(Response::builder()
            .status(404)
            .body(Full::new(Bytes::from_static(b"no such package\n")))
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
    start_http_origin_at("127.0.0.1:0").await
}

async fn start_http_origin_at(bind: &str) -> Result<SocketAddr> {
    let listener = TcpListener::bind(bind).await?;
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
    let root_issuer = Issuer::new(root_params, root_key);

    let leaf_key = KeyPair::generate()?;
    let mut leaf_params = CertificateParams::default();
    leaf_params.subject_alt_names = vec![
        SanType::DnsName(rcgen::string::Ia5String::try_from("localhost".to_owned())?),
        SanType::IpAddress("127.0.0.1".parse()?),
        SanType::IpAddress("::1".parse()?),
    ];
    let leaf_cert = leaf_params.signed_by(&leaf_key, &root_issuer)?;

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
    start_https_origin_at("127.0.0.1:0").await
}

async fn start_https_origin_at(bind: &str) -> Result<(SocketAddr, String)> {
    let tls = make_origin_tls()?;
    let server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(tls.cert_chain, tls.key_der)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

    let listener = TcpListener::bind(bind).await?;
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
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

/// A reqwest client that routes through the hood proxy at `proxy_addr` and
/// trusts hood's ephemeral CA, so the intercepted leaf verifies.
fn client_with_proxy(proxy_addr: SocketAddr, hood_ca_pem: &str) -> reqwest::Client {
    let proxy_url = format!("http://{proxy_addr}");
    let proxy_all = reqwest::Proxy::all(&proxy_url).unwrap();
    let mut builder = reqwest::Client::builder()
        .proxy(proxy_all)
        .danger_accept_invalid_certs(false)
        .tls_built_in_root_certs(true);
    for cert in roots_from_pem(hood_ca_pem) {
        builder = builder.add_root_certificate(reqwest::Certificate::from_der(&cert).unwrap());
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

    let cfg = Config::default().with_extra_upstream_roots(roots_from_pem(&origin_ca_pem));
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
    let cfg = Config::default().with_extra_upstream_roots(roots_from_pem(&origin_ca_pem));
    let proxy = Proxy::new(scanner, cfg)?;
    let token = proxy.go_bridge_token().to_owned();
    let handle = proxy.spawn().await?;
    let bridge = GoBridge::new(&format!("https://localhost:{}", origin_addr.port()), "off")?;
    let child = bridge.child_env(handle.addr, &token);

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

/// Send one raw request to the proxy and read until it closes the connection.
/// Raw bytes keep the request target exactly as written: HTTP clients such as
/// reqwest always tunnel `https://` URLs rather than sending them absolute.
async fn raw_request(proxy: SocketAddr, head: &str) -> Result<String> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream.write_all(head.as_bytes()).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(String::from_utf8_lossy(&response).into_owned())
}

fn absolute_get(authority: &str) -> String {
    format!(
        "GET https://{authority}/hello HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zig_mode_refuses_zig_tunnels_and_verifies_upstream() -> Result<()> {
    drop(rustls::crypto::ring::default_provider().install_default());

    let (origin_addr, origin_ca_pem) = start_https_origin().await?;
    let scanner: Arc<dyn Scanner> = Arc::new(AllowAll);
    let cfg = Config::default()
        .with_extra_upstream_roots(roots_from_pem(&origin_ca_pem))
        .with_zig_clients(true);
    let handle = Proxy::new(scanner, cfg)?.spawn().await?;
    let authority = format!("localhost:{}", origin_addr.port());

    // The request Zig's std.http sends. A refused tunnel must be a 4xx, or
    // Zig keeps tunneling.
    let refused = raw_request(
        handle.addr,
        &format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: zig/0.17.0 (std.http)\r\nConnection: close\r\n\r\n"
        ),
    )
    .await?;
    assert!(refused.starts_with("HTTP/1.1 405"), "{refused}");

    // The client trusts no hood CA; hood verifies the origin itself.
    let response = raw_request(handle.addr, &absolute_get(&authority)).await?;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("x-origin-marker: yes"), "{response}");
    assert!(
        response.contains(std::str::from_utf8(PAYLOAD)?),
        "{response}"
    );

    handle.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zig_mode_keeps_mitm_for_other_clients() -> Result<()> {
    drop(rustls::crypto::ring::default_provider().install_default());

    // `zig build` steps may run curl, git, or other CA-trusting clients.
    // Their tunnels must still be intercepted and scanned, not refused.
    let (origin_addr, origin_ca_pem) = start_https_origin().await?;
    let cfg = Config::default()
        .with_extra_upstream_roots(roots_from_pem(&origin_ca_pem))
        .with_zig_clients(true);
    let proxy = Proxy::new(Arc::new(BlockAll), cfg)?;
    let hood_ca = proxy.ca_pem().to_owned();
    let handle = proxy.spawn().await?;

    let client = client_with_proxy(handle.addr, &hood_ca);
    let url = format!("https://localhost:{}/hello", origin_addr.port());
    let resp = client.get(&url).send().await?;
    assert_eq!(resp.status().as_u16(), 451, "tunneled GET was not scanned");

    handle.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absolute_https_requires_opt_in_and_a_trusted_upstream() -> Result<()> {
    drop(rustls::crypto::ring::default_provider().install_default());

    let (origin_addr, origin_ca_pem) = start_https_origin().await?;
    let authority = format!("localhost:{}", origin_addr.port());

    // Default mode keeps the MITM tunnel and rejects absolute-form HTTPS.
    let cfg = Config::default().with_extra_upstream_roots(roots_from_pem(&origin_ca_pem));
    let handle = Proxy::new(Arc::new(AllowAll), cfg)?.spawn().await?;
    let response = raw_request(handle.addr, &absolute_get(&authority)).await?;
    assert!(response.starts_with("HTTP/1.1 502"), "{response}");
    handle.stop().await;

    // Opting in never relaxes upstream verification: an origin signed by an
    // unknown CA is refused rather than fetched.
    let cfg = Config::default().with_zig_clients(true);
    let handle = Proxy::new(Arc::new(AllowAll), cfg)?.spawn().await?;
    let response = raw_request(handle.addr, &absolute_get(&authority)).await?;
    assert!(response.starts_with("HTTP/1.1 502"), "{response}");
    assert!(!response.contains("x-origin-marker"), "{response}");
    handle.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plaintext_http_inside_connect_tunnel_is_forwarded_and_scanned() -> Result<()> {
    drop(rustls::crypto::ring::default_provider().install_default());

    // pnpm and Zig tunnel `http://` requests through CONNECT without TLS.
    let origin_addr = start_http_origin().await?;
    let handle = Proxy::new(Arc::new(AllowAll), Config::default())?
        .spawn()
        .await?;
    let tunnel = format!(
        "CONNECT {origin_addr} HTTP/1.1\r\nHost: {origin_addr}\r\n\r\nGET /hello HTTP/1.1\r\nHost: {origin_addr}\r\nConnection: close\r\n\r\n"
    );
    let response = raw_request(handle.addr, &tunnel).await?;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("x-origin-marker: yes"), "{response}");
    assert!(
        response.contains(std::str::from_utf8(PAYLOAD)?),
        "{response}"
    );
    handle.stop().await;

    let handle = Proxy::new(Arc::new(BlockAll), Config::default())?
        .spawn()
        .await?;
    let response = raw_request(handle.addr, &tunnel).await?;
    assert!(
        response.contains("HTTP/1.1 451"),
        "tunneled HTTP was not scanned: {response}"
    );
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
    let cfg = Config::default().with_scan_limits(4096, 8 * 1024 * 1024)?;
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
async fn oversized_body_follows_the_scanners_limit_decision() -> Result<()> {
    drop(rustls::crypto::ring::default_provider().install_default());

    let origin_addr = start_http_origin().await?;
    let scanner: Arc<dyn Scanner> = Arc::new(BlockAll);
    // Past the limit, the scanner's `scan_limit` answer is final; this one
    // withholds, so nothing oversized slips through unasked.
    let cfg = Config::default().with_scan_limits(4096, 16 * 1024)?;
    let proxy = Proxy::new(scanner, cfg)?;
    let hood_ca = proxy.ca_pem().to_owned();
    let handle = proxy.spawn().await?;

    let client = client_with_proxy(handle.addr, &hood_ca);
    let url = format!("http://{origin_addr}/big");
    let resp = client.get(&url).send().await?;
    assert_eq!(resp.status(), 451);

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

/// Records what the proxy tells a scanner of each download's provenance: once
/// as the request goes out, and again with the response.
#[derive(Debug, Default)]
struct Provenance(std::sync::Mutex<Vec<(&'static str, Disclosure)>>);

#[async_trait::async_trait]
impl Scanner for Provenance {
    fn anticipate(self: Arc<Self>, _url: &str, disclosure: Disclosure) -> Anticipated {
        self.0.lock().unwrap().push(("request", disclosure));
        Anticipated::default()
    }
    async fn scan(&self, req: ScanRequest) -> Verdict {
        self.0.lock().unwrap().push(("response", req.disclosure));
        Verdict::Allow
    }
    async fn scan_disk(&self, req: DiskScanRequest) -> Verdict {
        self.0.lock().unwrap().push(("response", req.disclosure));
        Verdict::Allow
    }
    fn scan_limit(&self, _url: &str, _limit: u64, _size: Option<u64>) -> Verdict {
        Verdict::Allow
    }
    fn uninspectable(&self, _url: &str, _why: &str) -> Verdict {
        Verdict::Allow
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_scanner_hears_of_a_download_when_it_is_requested_and_what_it_may_disclose()
-> Result<()> {
    use Disclosure::{Coordinate, Digest, Nothing};
    drop(rustls::crypto::ring::default_provider().install_default());

    let origin_addr = start_http_origin().await?;
    let scanner = Arc::new(Provenance::default());
    let proxy = Proxy::new(scanner.clone(), Config::default())?;
    let hood_ca = proxy.ca_pem().to_owned();
    let handle = proxy.spawn().await?;
    let client = client_with_proxy(handle.addr, &hood_ca);
    let get = |path: &str| client.get(format!("http://{origin_addr}{path}"));
    let heard = || std::mem::take(&mut *scanner.0.lock().unwrap());

    get("/hello").send().await?.bytes().await?;
    assert_eq!(heard(), [("request", Coordinate), ("response", Coordinate)]);

    // Credentials make the download private, whatever its URL.
    for (header, value) in [("authorization", "Bearer secret"), ("cookie", "session=1")] {
        get("/hello").header(header, value).send().await?;
        assert_eq!(heard(), [("request", Nothing), ("response", Nothing)]);
    }
    let post = client.post(format!("http://{origin_addr}/hello"));
    post.send().await?;
    assert_eq!(heard(), [("request", Digest), ("response", Digest)]);

    // An error page is not the package its URL names.
    assert_eq!(get("/missing").send().await?.status(), 404);
    assert_eq!(heard(), [("request", Coordinate), ("response", Digest)]);

    // A HEAD brings nothing to scan, so nothing is begun for it.
    client
        .head(format!("http://{origin_addr}/hello"))
        .send()
        .await?;
    assert_eq!(heard(), []);

    handle.stop().await;
    Ok(())
}

/// A scanner that clears everything it inspects but withholds anything it
/// cannot inspect. A 451 from it proves the payload was refused as
/// uninspectable, not judged.
#[derive(Debug)]
struct ClearsInspected;

#[async_trait::async_trait]
impl Scanner for ClearsInspected {
    async fn scan(&self, _req: ScanRequest) -> Verdict {
        Verdict::Allow
    }
    async fn scan_disk(&self, _req: DiskScanRequest) -> Verdict {
        Verdict::Allow
    }
    fn scan_limit(&self, _url: &str, _limit: u64, _size: Option<u64>) -> Verdict {
        withheld("download exceeds inspection limit")
    }
    fn uninspectable(&self, _url: &str, why: &str) -> Verdict {
        withheld(why)
    }
}

/// An origin that answers every connection with `response`, verbatim — for
/// framings and headers a well-behaved server would not send.
async fn start_raw_origin(response: Vec<u8>) -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let response = Arc::new(response);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let response = Arc::clone(&response);
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0_u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                drop(stream.write_all(&response).await);
            });
        }
    });
    Ok(addr)
}

/// [`big_payload`] as a chunked response, so its length is never declared.
fn chunked_big_response() -> Vec<u8> {
    let mut response =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
    for chunk in big_payload().chunks(16 * 1024) {
        response.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        response.extend_from_slice(chunk);
        response.extend_from_slice(b"\r\n");
    }
    response.extend_from_slice(b"0\r\n\r\n");
    response
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn undeclared_oversized_body_streams_through_intact_when_allowed() -> Result<()> {
    drop(rustls::crypto::ring::default_provider().install_default());

    // Past the 16 KiB scan limit hood stops spilling and streams the rest
    // straight from upstream; the client must still get every byte, in order.
    let origin_addr = start_raw_origin(chunked_big_response()).await?;
    let cfg = Config::default().with_scan_limits(4096, 16 * 1024)?;
    let proxy = Proxy::new(Arc::new(AllowAll), cfg)?;
    let hood_ca = proxy.ca_pem().to_owned();
    let handle = proxy.spawn().await?;

    let client = client_with_proxy(handle.addr, &hood_ca);
    let resp = client
        .get(format!("http://{origin_addr}/big"))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await?.as_ref(), big_payload().as_slice());

    handle.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn undeclared_oversized_body_follows_the_scanner_decision() -> Result<()> {
    drop(rustls::crypto::ring::default_provider().install_default());

    let origin_addr = start_raw_origin(chunked_big_response()).await?;
    let cfg = Config::default().with_scan_limits(4096, 16 * 1024)?;
    let proxy = Proxy::new(Arc::new(ClearsInspected), cfg)?;
    let hood_ca = proxy.ca_pem().to_owned();
    let handle = proxy.spawn().await?;

    let client = client_with_proxy(handle.addr, &hood_ca);
    let resp = client
        .get(format!("http://{origin_addr}/big"))
        .send()
        .await?;
    assert_eq!(resp.status().as_u16(), 451);

    handle.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encoded_response_cannot_pass_as_inspected() -> Result<()> {
    drop(rustls::crypto::ring::default_provider().install_default());

    // hood asked for `identity`; a server that compresses anyway would have
    // the scanner read compressed bytes while a decoding client runs the
    // expanded payload.
    let encoded = format!(
        "HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        PAYLOAD.len()
    );
    let mut response = encoded.into_bytes();
    response.extend_from_slice(PAYLOAD);
    let origin_addr = start_raw_origin(response).await?;
    let proxy = Proxy::new(Arc::new(ClearsInspected), Config::default())?;
    let hood_ca = proxy.ca_pem().to_owned();
    let handle = proxy.spawn().await?;

    let client = client_with_proxy(handle.addr, &hood_ca);
    let resp = client
        .get(format!("http://{origin_addr}/x.tgz"))
        .send()
        .await?;
    assert_eq!(resp.status().as_u16(), 451);

    handle.stop().await;
    Ok(())
}

/// Whether this host can listen on the IPv6 loopback; some containers cannot.
async fn ipv6_loopback() -> bool {
    let available = TcpListener::bind("[::1]:0").await.is_ok();
    if !available {
        eprintln!("no IPv6 loopback here; skipping");
    }
    available
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv6_literal_origin_round_trips_over_http() -> Result<()> {
    drop(rustls::crypto::ring::default_provider().install_default());
    if !ipv6_loopback().await {
        return Ok(());
    }

    let origin_addr = start_http_origin_at("[::1]:0").await?;
    let proxy = Proxy::new(Arc::new(AllowAll), Config::default())?;
    let hood_ca = proxy.ca_pem().to_owned();
    let handle = proxy.spawn().await?;

    let client = client_with_proxy(handle.addr, &hood_ca);
    let resp = client
        .get(format!("http://{origin_addr}/hello"))
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await?.as_ref(), PAYLOAD);

    handle.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv6_literal_origin_round_trips_over_https_without_sni() -> Result<()> {
    drop(rustls::crypto::ring::default_provider().install_default());
    if !ipv6_loopback().await {
        return Ok(());
    }

    // An IP-literal URL carries no SNI, so the leaf must be named for the
    // CONNECT target; hood then dials and verifies the bare IPv6 address.
    let (origin_addr, origin_ca_pem) = start_https_origin_at("[::1]:0").await?;
    let cfg = Config::default().with_extra_upstream_roots(roots_from_pem(&origin_ca_pem));
    let proxy = Proxy::new(Arc::new(AllowAll), cfg)?;
    let hood_ca = proxy.ca_pem().to_owned();
    let handle = proxy.spawn().await?;

    // reqwest 0.12 cannot tunnel TLS to an IPv6 literal (it hands the
    // bracketed host to `ServerName`), so the client side is driven by hand.
    let mut tunnel = TcpStream::connect(handle.addr).await?;
    tunnel
        .write_all(
            format!("CONNECT {origin_addr} HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n").as_bytes(),
        )
        .await?;
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(tunnel.read(&mut byte).await?, 1, "proxy closed the CONNECT");
        head.push(byte[0]);
    }
    assert!(
        head.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&head)
    );

    let mut roots = rustls::RootCertStore::empty();
    for cert in roots_from_pem(&hood_ca) {
        roots.add(cert)?;
    }
    let client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::IpAddress(origin_addr.ip().into());
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(client_cfg))
        .connect(server_name, tunnel)
        .await?;
    tls.write_all(
        format!("GET /hello HTTP/1.1\r\nHost: {origin_addr}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await?;
    let mut response = Vec::new();
    // The proxy may close without a TLS close_notify; what arrived is enough.
    drop(tls.read_to_end(&mut response).await);
    let response = String::from_utf8_lossy(&response);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response.ends_with(std::str::from_utf8(PAYLOAD)?),
        "{response}"
    );

    handle.stop().await;
    Ok(())
}

/// A scanner that decides nothing until the test opens its gate, standing
/// in for an assessment that takes a while.
#[derive(Debug)]
struct Gated {
    gate: tokio::sync::Semaphore,
    verdict: Verdict,
}

impl Gated {
    fn new(verdict: Verdict) -> Arc<Self> {
        Arc::new(Self {
            gate: tokio::sync::Semaphore::new(0),
            verdict,
        })
    }

    async fn decide(&self) -> Verdict {
        drop(self.gate.acquire().await);
        self.verdict.clone()
    }
}

#[async_trait::async_trait]
impl Scanner for Gated {
    async fn scan(&self, _req: ScanRequest) -> Verdict {
        self.decide().await
    }
    async fn scan_disk(&self, _req: DiskScanRequest) -> Verdict {
        self.decide().await
    }
    fn scan_limit(&self, _url: &str, _limit: u64, _size: Option<u64>) -> Verdict {
        withheld("download exceeds inspection limit")
    }
    fn uninspectable(&self, _url: &str, why: &str) -> Verdict {
        withheld(why)
    }
}

/// The user agent brew gives its curl.
const BREW_AGENT: &str = "Homebrew/5.0.0 (Macintosh; arm64 Mac OS X 26.0) curl/8.7.1";

/// Longer than a held download stays silent, shorter than brew's patience.
const HELD: Duration = Duration::from_secs(4);

/// Start a brew-serving proxy over `scanner` and request `/big` from a fresh
/// origin as `agent`. The response future is returned unawaited.
async fn brew_request(
    scanner: Arc<dyn Scanner>,
    agent: &str,
) -> Result<(hood::proxy::Handle, reqwest::RequestBuilder)> {
    drop(rustls::crypto::ring::default_provider().install_default());
    let origin_addr = start_http_origin().await?;
    let proxy = Proxy::new(scanner, Config::default().with_brew_clients(true))?;
    let hood_ca = proxy.ca_pem().to_owned();
    let handle = proxy.spawn().await?;
    let request = client_with_proxy(handle.addr, &hood_ca)
        .get(format!("http://{origin_addr}/big"))
        .header("user-agent", agent);
    Ok((handle, request))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_brew_download_is_kept_alive_then_completed() -> Result<()> {
    let scanner = Gated::new(Verdict::Allow);
    let (handle, request) = brew_request(scanner.clone(), BREW_AGENT).await?;

    // Headers and a first trickle arrive while the scanner is still deciding.
    let mut response = tokio::time::timeout(HELD, request.send()).await??;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers().get("accept-ranges").unwrap(), "none");
    let payload = big_payload();
    let mut body = tokio::time::timeout(HELD, response.chunk())
        .await??
        .unwrap()
        .to_vec();
    assert!(!body.is_empty() && body.len() < payload.len());

    scanner.gate.add_permits(1);
    while let Some(chunk) = response.chunk().await? {
        body.extend_from_slice(&chunk);
    }
    assert_eq!(body, payload);

    handle.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_brew_download_is_cut_short_when_blocked() -> Result<()> {
    let scanner = Gated::new(Verdict::Block(BlockReason::Hostile));
    let (handle, request) = brew_request(scanner.clone(), BREW_AGENT).await?;

    let mut response = tokio::time::timeout(HELD, request.send()).await??;
    let mut body = tokio::time::timeout(HELD, response.chunk())
        .await??
        .unwrap()
        .to_vec();

    scanner.gate.add_permits(1);
    let cut_short = loop {
        match response.chunk().await {
            Ok(Some(chunk)) => body.extend_from_slice(&chunk),
            Ok(None) => break false,
            Err(_) => break true,
        }
    };
    assert!(cut_short, "a blocked transfer must not end cleanly");
    let payload = big_payload();
    assert!(body.len() < payload.len() && payload.starts_with(&body));

    handle.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_homebrew_curl_is_sent_an_unassessed_byte() -> Result<()> {
    // Another client in the same run sees nothing until the verdict.
    let scanner = Gated::new(Verdict::Allow);
    let (handle, request) = brew_request(scanner.clone(), "curl/8.7.1").await?;
    assert!(
        tokio::time::timeout(HELD, request.send()).await.is_err(),
        "a held response was answered early"
    );
    handle.stop().await;

    // And a prompt verdict is answered as for any client, block page and all.
    let (handle, request) = brew_request(Arc::new(BlockAll), BREW_AGENT).await?;
    assert_eq!(request.send().await?.status().as_u16(), 451);
    handle.stop().await;
    Ok(())
}

/// An origin answering with the `Range` header it was sent.
async fn start_range_echo_origin() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let service = service_fn(|req: Request<Incoming>| async move {
                    let range = format!("{:?}", req.headers().get("range"));
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from(range))))
                });
                drop(
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await,
                );
            });
        }
    });
    Ok(addr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn homebrew_curl_is_never_offered_a_resume() -> Result<()> {
    drop(rustls::crypto::ring::default_provider().install_default());

    let origin_addr = start_range_echo_origin().await?;
    let scanner: Arc<dyn Scanner> = Arc::new(AllowAll);
    let proxy = Proxy::new(scanner, Config::default().with_brew_clients(true))?;
    let hood_ca = proxy.ca_pem().to_owned();
    let handle = proxy.spawn().await?;
    let client = client_with_proxy(handle.addr, &hood_ca);
    let get = |agent| {
        client
            .get(format!("http://{origin_addr}/"))
            .header("user-agent", agent)
            .header("range", "bytes=5-")
            .send()
    };

    // A tail fetched by range could complete a file hood cut short.
    let brew = get(BREW_AGENT).await?;
    assert_eq!(brew.headers().get("accept-ranges").unwrap(), "none");
    assert_eq!(brew.text().await?, "None");

    let other = get("curl/8.7.1").await?;
    assert!(other.headers().get("accept-ranges").is_none());
    assert_eq!(other.text().await?, r#"Some("bytes=5-")"#);

    handle.stop().await;
    Ok(())
}

/// Open a CONNECT tunnel to `authority` as `agent` and fetch `/hello` over
/// TLS inside it, trusting only `origin_ca_pem`: the origin's own
/// certificate, never one hood minted.
async fn fetch_through_tunnel(
    proxy: SocketAddr,
    authority: &str,
    agent: &str,
    origin_ca_pem: &str,
) -> Result<String> {
    let mut tunnel = TcpStream::connect(proxy).await?;
    tunnel
        .write_all(
            format!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: {agent}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        anyhow::ensure!(
            tunnel.read(&mut byte).await? == 1,
            "proxy closed the tunnel"
        );
        head.push(byte[0]);
    }
    anyhow::ensure!(head.starts_with(b"HTTP/1.1 200"), "tunnel refused");

    let mut roots = rustls::RootCertStore::empty();
    for cert in roots_from_pem(origin_ca_pem) {
        roots.add(cert)?;
    }
    let client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(client_cfg))
        .connect("localhost".try_into()?, tunnel)
        .await?;
    tls.write_all(
        format!("GET /hello HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await?;
    let mut response = Vec::new();
    drop(tls.read_to_end(&mut response).await);
    Ok(String::from_utf8_lossy(&response).into_owned())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn brew_mode_relays_git_tunnels_without_interception() -> Result<()> {
    drop(rustls::crypto::ring::default_provider().install_default());

    let (origin_addr, origin_ca_pem) = start_https_origin().await?;
    let authority = format!("localhost:{}", origin_addr.port());
    let git = "git/2.50.1";

    // The scanner blocks all it is asked about, and is never asked: git
    // speaks TLS to the origin itself, end to end.
    let brew = Proxy::new(
        Arc::new(BlockAll),
        Config::default().with_brew_clients(true),
    )?
    .spawn()
    .await?;
    let response = fetch_through_tunnel(brew.addr, &authority, git, &origin_ca_pem).await?;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response.ends_with(std::str::from_utf8(PAYLOAD)?),
        "{response}"
    );
    // Every other client of the same run is still intercepted.
    assert!(
        fetch_through_tunnel(brew.addr, &authority, BREW_AGENT, &origin_ca_pem)
            .await
            .is_err()
    );
    brew.stop().await;

    // Outside a brew run, so is git.
    let plain = Proxy::new(Arc::new(BlockAll), Config::default())?
        .spawn()
        .await?;
    assert!(
        fetch_through_tunnel(plain.addr, &authority, git, &origin_ca_pem)
            .await
            .is_err()
    );
    plain.stop().await;
    Ok(())
}
