//! HTTP/1.1 forward proxy with transparent TLS interception.
//!
//! The proxy binds an ephemeral port on `127.0.0.1` (never any other
//! interface) and handles two request shapes:
//!
//! - Absolute-form requests like `GET http://example.com/path HTTP/1.1`
//!   (plaintext HTTP). The proxy opens a fresh upstream TCP connection,
//!   forwards the request, buffers the response body, scans it, and either
//!   forwards the response or returns a synthetic 451 to the client.
//!
//! - `CONNECT host:port` (TLS tunnels). The proxy answers `200 Connection
//!   Established`, terminates TLS on the upgraded stream using a leaf cert
//!   minted by the ephemeral [`Ca`], and serves HTTP/1.1 on the decrypted
//!   side — feeding requests through the same forward-and-scan path as the
//!   plaintext branch.
//!
//! Hop-by-hop headers are stripped on both legs and `Accept-Encoding` is forced
//! to `identity` on outbound so we never have to decompress for scanning.
//!
//! Response bodies are handled by size to bound memory. First a pre-fetch PURL
//! gate can skip (known-good) or block (known-bad) before a byte is downloaded.
//! Otherwise: a body within the configured in-memory limit is buffered and
//! scanned in RAM; a larger one spills to a temp file and is scanned from disk
//! (cleave memory-maps it) up to the configured scan limit; past that it is
//! forwarded unscanned. Forwarded large bodies stream back from the spill file,
//! so a multi-gigabyte transfer never materializes whole in RAM.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::client::conn::http1 as client_http1;
use hyper::header::{
    ACCEPT_ENCODING, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HOST, HeaderMap, HeaderName,
    HeaderValue, LOCATION,
};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::io::ReaderStream;

use crate::ca::{Ca, CaResolver};
use crate::go_bridge;
use crate::scanner::{BlockReason, DiskScanRequest, Prefetch, ScanRequest, Scanner, Verdict};

/// The proxy's response body. A [`BoxBody`] so one return type covers three
/// shapes: a fully-buffered small response ([`full_body`]), an upstream body
/// streamed straight through ([`passthrough_body`]), and a large payload
/// streamed back from its on-disk spill file ([`file_body`]).
type ProxyBody = BoxBody<Bytes, std::io::Error>;

/// Wrap fully-buffered bytes as a [`ProxyBody`].
fn full_body(bytes: Bytes) -> ProxyBody {
    // `Full`'s error type is `Infallible`; widen it to the boxed error type.
    Full::new(bytes).map_err(|e| match e {}).boxed()
}

/// Stream an upstream body straight through to the client without buffering —
/// used for known-good-PURL skips and payloads too large to scan.
fn passthrough_body(body: Incoming) -> ProxyBody {
    body.map_err(std::io::Error::other).boxed()
}

/// Stream a spill file back to the client. The file is read in chunks, so a
/// multi-gigabyte forward never materializes in RAM. The caller unlinks the
/// path before handing back the [`tokio::fs::File`]; the open descriptor keeps
/// the data alive until the body is fully sent, then the OS reclaims it.
fn file_body(file: tokio::fs::File) -> ProxyBody {
    StreamBody::new(ReaderStream::new(file).map_ok(Frame::data)).boxed()
}

/// Upper bound on a response body buffered *in memory* for scanning. Larger
/// responses spill to a temp file and are scanned from disk instead (up to
/// [`MAX_SCAN_BYTES_DEFAULT`]). Tunable via `HOOD_MAX_BODY_MB`; the default is
/// generous enough for npm tarballs and binary installers, low enough that a
/// single in-RAM response can't OOM the host.
const MAX_BODY_BYTES_DEFAULT: u64 = 256 * 1024 * 1024;

/// Upper bound on a response body scanned *from disk*. Between
/// [`MAX_BODY_BYTES_DEFAULT`] and this, the body is streamed to a temp file and
/// scanned there (cleave memory-maps it, so RAM stays bounded). Past this, the
/// body is too large to scan and is forwarded unscanned — bounded only by the
/// pre-fetch PURL gate. Tunable via `HOOD_MAX_SCAN_MB`.
const MAX_SCAN_BYTES_DEFAULT: u64 = 2 * 1024 * 1024 * 1024;

/// Generate an independent 128-bit route token for the loopback Go bridge.
/// This must not be derived from the public CA certificate: the certificate is
/// deliberately shared with the child process and is not secret key material.
fn bridge_token() -> Result<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).context("generate Go bridge route token")?;
    let mut out = String::with_capacity(32);
    for byte in random {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(out)
}

/// Resolve the in-memory body cap from the environment, falling back to the default.
fn max_body_bytes_from_env() -> Result<u64> {
    Ok(mb_env("HOOD_MAX_BODY_MB")?.unwrap_or(MAX_BODY_BYTES_DEFAULT))
}

/// Resolve the disk-scan cap from the environment, falling back to the default.
fn max_scan_bytes_from_env() -> Result<u64> {
    Ok(mb_env("HOOD_MAX_SCAN_MB")?.unwrap_or(MAX_SCAN_BYTES_DEFAULT))
}

/// Read a megabyte-valued env var and convert it to bytes.
fn mb_env(name: &str) -> Result<Option<u64>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .ok_or_else(|| anyhow!("{name} is not valid UTF-8"))?;
    Ok(Some(megabytes_to_bytes(name, value)?))
}

fn megabytes_to_bytes(name: &str, value: &str) -> Result<u64> {
    let megabytes = value
        .parse::<u64>()
        .with_context(|| format!("parse {name}={value:?} as megabytes"))?;
    megabytes
        .checked_mul(1024 * 1024)
        .ok_or_else(|| anyhow!("{name}={value:?} exceeds the supported byte range"))
}

/// Hop-by-hop headers per RFC 7230 §6.1. These never propagate end-to-end.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
];

/// Configuration for a new proxy instance.
#[derive(Debug, Clone)]
pub struct Config {
    /// Maximum response body buffered in RAM for scanning. Larger responses
    /// spill to disk and are scanned from there.
    max_body_bytes: u64,
    /// Maximum response body scanned from disk. Larger responses are forwarded
    /// unscanned (bounded only by the pre-fetch PURL gate).
    max_scan_bytes: u64,
    /// Bind address. Forced to a loopback address for safety.
    bind: SocketAddr,
    /// Additional roots used to verify upstream TLS. Intended for private PKI
    /// and deterministic tests; native platform roots are always loaded too.
    extra_upstream_roots: Vec<rustls::pki_types::CertificateDer<'static>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_body_bytes: MAX_BODY_BYTES_DEFAULT,
            max_scan_bytes: MAX_SCAN_BYTES_DEFAULT,
            // 127.0.0.1:0 → kernel-assigned ephemeral port.
            bind: ([127, 0, 0, 1], 0).into(),
            extra_upstream_roots: Vec::new(),
        }
    }
}

impl Config {
    /// Build configuration using Hood's environment overrides.
    ///
    /// # Errors
    ///
    /// Returns an error if the configured limits are zero or out of order.
    pub fn from_env() -> Result<Self> {
        Self::default().with_scan_limits(max_body_bytes_from_env()?, max_scan_bytes_from_env()?)
    }

    /// Set the in-memory and total scan limits.
    ///
    /// # Errors
    ///
    /// Returns an error if `max_body_bytes` is zero or exceeds
    /// `max_scan_bytes`.
    pub fn with_scan_limits(mut self, max_body_bytes: u64, max_scan_bytes: u64) -> Result<Self> {
        if max_body_bytes == 0 {
            return Err(anyhow!("max_body_bytes must be greater than zero"));
        }
        if max_scan_bytes < max_body_bytes {
            return Err(anyhow!(
                "max_scan_bytes ({max_scan_bytes}) must be at least max_body_bytes ({max_body_bytes})",
            ));
        }
        self.max_body_bytes = max_body_bytes;
        self.max_scan_bytes = max_scan_bytes;
        Ok(self)
    }

    /// Set the listener address.
    ///
    /// # Errors
    ///
    /// Returns an error unless `bind` is loopback-only.
    pub fn with_bind(mut self, bind: SocketAddr) -> Result<Self> {
        if !bind.ip().is_loopback() {
            return Err(anyhow!(
                "refusing to bind on non-loopback address: {}",
                bind.ip(),
            ));
        }
        self.bind = bind;
        Ok(self)
    }

    /// Add roots used to verify private upstream TLS endpoints.
    #[must_use]
    pub fn with_extra_upstream_roots(
        mut self,
        roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    ) -> Self {
        self.extra_upstream_roots = roots;
        self
    }
}

/// A ready-to-bind proxy. Cheap to clone (everything is `Arc` inside).
#[derive(Clone)]
pub struct Proxy {
    inner: Arc<Inner>,
}

struct Inner {
    scanner: Arc<dyn Scanner>,
    ca: Ca,
    tls_acceptor: TlsAcceptor,
    upstream_tls: Arc<ClientConfig>,
    go_bridge_token: String,
    config: Config,
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy")
            .field("config", &self.inner.config)
            .field("scanner", &self.inner.scanner)
            .finish()
    }
}

impl Proxy {
    /// Build a proxy. Generates an ephemeral CA and loads native TLS roots
    /// for verifying upstream servers.
    ///
    /// # Errors
    ///
    /// Returns an error if certificate generation or TLS setup fails.
    pub fn new(scanner: Arc<dyn Scanner>, config: Config) -> Result<Self> {
        let ca = Ca::generate()?;
        let go_bridge_token = bridge_token()?;
        let resolver = Arc::new(CaResolver::new(ca.clone()));
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

        let mut roots = RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            // Individual cert failures are common (expired/unsupported algos);
            // skip them and keep building the set.
            drop(roots.add(cert));
        }
        for cert in &config.extra_upstream_roots {
            drop(roots.add(cert.clone()));
        }
        if roots.is_empty() {
            return Err(anyhow!(
                "no native TLS roots found; cannot verify upstream servers",
            ));
        }
        let mut upstream_tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        upstream_tls.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(Self {
            inner: Arc::new(Inner {
                scanner,
                ca,
                tls_acceptor,
                upstream_tls: Arc::new(upstream_tls),
                go_bridge_token,
                config,
            }),
        })
    }

    /// PEM of the ephemeral root CA — write this to a file and point child
    /// processes at it via the tool-specific env var.
    #[must_use]
    pub fn ca_pem(&self) -> &str {
        self.inner.ca.root_pem()
    }

    /// Unpredictable per-run token protecting the loopback Go bridge route.
    #[must_use]
    pub fn go_bridge_token(&self) -> &str {
        &self.inner.go_bridge_token
    }

    /// Bind the listener and start accepting. Returns a handle for shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error if the listener cannot bind or report its address.
    pub async fn spawn(self) -> Result<Handle> {
        let listener = TcpListener::bind(self.inner.config.bind)
            .await
            .with_context(|| format!("bind {}", self.inner.config.bind))?;
        let addr = listener.local_addr().context("local_addr")?;
        let shutdown = Arc::new(Notify::new());
        let signal = Arc::clone(&shutdown);
        let proxy = self.clone();
        let task = tokio::spawn(async move { accept_loop(listener, proxy, signal).await });
        Ok(Handle {
            addr,
            shutdown,
            task: Some(task),
        })
    }
}

/// Running-proxy handle. Drop or `stop()` to terminate.
#[derive(Debug)]
pub struct Handle {
    /// Bound address (with the kernel-assigned port resolved).
    pub addr: SocketAddr,
    shutdown: Arc<Notify>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Handle {
    /// Signal shutdown and wait for the accept loop to exit.
    pub async fn stop(mut self) {
        self.shutdown.notify_waiters();
        if let Some(task) = self.task.take() {
            // Best-effort: connection failures are logged at their source.
            drop(task.await);
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.shutdown.notify_waiters();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn accept_loop(listener: TcpListener, proxy: Proxy, shutdown: Arc<Notify>) {
    loop {
        tokio::select! {
            biased;
            () = shutdown.notified() => {
                tracing::debug!("proxy shutdown");
                return;
            }
            acc = listener.accept() => match acc {
                Ok((stream, peer)) => {
                    tracing::trace!(%peer, "accept");
                    let proxy = proxy.clone();
                    tokio::spawn(async move {
                        serve_inbound_plain(stream, proxy).await;
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                }
            }
        }
    }
}

/// Serve an inbound plaintext connection. Handles both plain HTTP forwarding
/// and CONNECT upgrades (which transition into the TLS-MITM path).
async fn serve_inbound_plain(stream: TcpStream, proxy: Proxy) {
    let proxy_clone = proxy.clone();
    let svc = service_fn(move |req| {
        let proxy = proxy_clone.clone();
        async move { Ok::<_, Infallible>(proxy.dispatch_inbound(req, None).await) }
    });
    if let Err(e) = server_http1::Builder::new()
        .keep_alive(true)
        .serve_connection(TokioIo::new(stream), svc)
        .with_upgrades()
        .await
    {
        tracing::trace!(error = %e, "inbound connection ended");
    }
}

/// Serve an inbound MITM-decrypted connection. The authority (host:port from
/// the original CONNECT) is threaded through so we know how to reach upstream.
async fn serve_inbound_mitm<IO>(stream: IO, proxy: Proxy, authority: String)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let proxy_clone = proxy.clone();
    let authority = Arc::<str>::from(authority);
    let svc = service_fn(move |req| {
        let proxy = proxy_clone.clone();
        let authority = Arc::clone(&authority);
        async move { Ok::<_, Infallible>(proxy.dispatch_inbound(req, Some(authority)).await) }
    });
    if let Err(e) = server_http1::Builder::new()
        .keep_alive(true)
        .serve_connection(TokioIo::new(stream), svc)
        .await
    {
        tracing::trace!(error = %e, "mitm connection ended");
    }
}

impl Proxy {
    /// Top-level request dispatcher. `mitm_authority` is `Some(host:port)`
    /// when we're handling the decrypted side of a CONNECT tunnel.
    async fn dispatch_inbound(
        &self,
        mut req: Request<Incoming>,
        mitm_authority: Option<Arc<str>>,
    ) -> Response<ProxyBody> {
        // CONNECT only ever arrives on the plaintext side.
        if req.method() == Method::CONNECT && mitm_authority.is_none() {
            return self.handle_connect(req);
        }

        // Go on macOS cannot trust hood's ephemeral CA from SSL_CERT_FILE.
        // Its module and sumdb requests instead arrive as authenticated,
        // origin-form loopback HTTP requests. Restore the encoded upstream URL
        // before feeding them into the normal verified+scanned forward path.
        let mut go_bridge_request = false;
        if mitm_authority.is_none() && req.uri().path().starts_with(go_bridge::ROUTE_PREFIX) {
            if !matches!(*req.method(), Method::GET | Method::HEAD) {
                return error_response(StatusCode::METHOD_NOT_ALLOWED, "Go bridge requires GET");
            }
            match go_bridge::resolve_request(req.uri(), &self.inner.go_bridge_token) {
                Ok(Some(target)) => match target.as_str().parse::<Uri>() {
                    Ok(uri) => {
                        *req.uri_mut() = uri;
                        go_bridge_request = true;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "invalid Go bridge target URI");
                        return error_response(StatusCode::BAD_REQUEST, "invalid Go bridge target");
                    }
                },
                Ok(None) => {
                    return error_response(StatusCode::NOT_FOUND, "unknown Go bridge route");
                }
                Err(e) => {
                    tracing::warn!(error = %format!("{e:#}"), "invalid Go bridge request");
                    return error_response(StatusCode::BAD_REQUEST, "invalid Go bridge request");
                }
            }
        }

        match self
            .handle_forward(req, mitm_authority, go_bridge_request)
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "forward failed");
                error_response(StatusCode::BAD_GATEWAY, "upstream error")
            }
        }
    }

    fn handle_connect(&self, mut req: Request<Incoming>) -> Response<ProxyBody> {
        let Some(authority) = req.uri().authority().cloned() else {
            return error_response(StatusCode::BAD_REQUEST, "CONNECT requires authority");
        };
        let authority = authority.to_string();
        let proxy = self.clone();
        // Take the OnUpgrade future before spawning so the spawned task does
        // not need to hold the Request<Incoming> across .await.
        let on_upgrade = hyper::upgrade::on(&mut req);
        tokio::spawn(run_mitm_after_upgrade(proxy, on_upgrade, authority));
        Response::builder()
            .status(StatusCode::OK)
            .body(full_body(Bytes::new()))
            .unwrap_or_else(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "build resp"))
    }
}

async fn run_mitm_after_upgrade(
    proxy: Proxy,
    on_upgrade: hyper::upgrade::OnUpgrade,
    authority: String,
) {
    let upgraded = match on_upgrade.await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(authority, error = %e, "upgrade failed");
            return;
        }
    };
    let io = TokioIo::new(upgraded);
    let tls = match proxy.inner.tls_acceptor.accept(io).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(authority, error = %e, "tls accept failed");
            return;
        }
    };
    // From this point on, traffic is plaintext HTTP/1.1 inside our TLS server.
    serve_inbound_mitm(tls, proxy, authority).await;
}

impl Proxy {
    async fn handle_forward(
        &self,
        mut req: Request<Incoming>,
        mitm_authority: Option<Arc<str>>,
        go_bridge_request: bool,
    ) -> Result<Response<ProxyBody>> {
        let (mut target_url, host_header) =
            resolve_target(&req, mitm_authority.as_deref(), go_bridge_request)?;
        let redirect_base = target_url.clone();
        let url_authorization = take_url_authorization(&mut target_url)?;
        // Captured before `req` is consumed by the upstream call: a HEAD request
        // never carries a response body to scan.
        let method = req.method().clone();
        let host = target_url
            .host_str()
            .ok_or_else(|| anyhow!("no host"))?
            .to_owned();
        let is_https = target_url.scheme() == "https";
        let port = target_url.port().unwrap_or(if is_https { 443 } else { 80 });

        // Rewrite request: switch to origin-form URI, drop hop-by-hop, force identity encoding.
        let mut origin_form = target_url.path().to_owned();
        if let Some(q) = target_url.query() {
            origin_form.push('?');
            origin_form.push_str(q);
        }
        let new_uri: Uri = origin_form.parse().context("rebuild origin-form uri")?;
        *req.uri_mut() = new_uri;

        let headers = req.headers_mut();
        strip_hop_by_hop(headers)?;
        // Some clients send Proxy-Connection; hop-by-hop strip covers it. Reset Host.
        headers.insert(HOST, HeaderValue::try_from(host_header.as_str())?);
        if let Some(authorization) = url_authorization {
            headers.insert(AUTHORIZATION, authorization);
        }
        // Force identity so we always see plaintext bytes for scanning.
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));

        let scan_url = target_url.to_string();

        // Pre-fetch PURL gate — decided from the URL alone, before any download.
        match self.inner.scanner.prefetch(&scan_url) {
            Prefetch::Block(reason) => {
                tracing::warn!(url = %scan_url, verdict = reason.label(), "block (pre-fetch purl)");
                return Ok(blocked_response(&scan_url, &reason));
            }
            Prefetch::SkipForward => {
                // Known-good PURL: stream straight through, no buffering, no scan.
                let response = upstream_request(&self.inner, &host, port, is_https, req).await?;
                let (mut parts, body) = response.into_parts();
                if go_bridge_request {
                    rewrite_go_bridge_location(
                        &mut parts.headers,
                        &redirect_base,
                        &self.inner.go_bridge_token,
                    );
                }
                tracing::debug!(url = %scan_url, "forward (known-good purl skip)");
                return build_response(parts.status, &parts.headers, passthrough_body(body), None);
            }
            Prefetch::Proceed => {}
        }

        // Open upstream connection (no pool for v1; one TCP per request).
        let response = upstream_request(&self.inner, &host, port, is_https, req).await?;
        let (mut parts, body) = response.into_parts();
        if go_bridge_request {
            rewrite_go_bridge_location(
                &mut parts.headers,
                &redirect_base,
                &self.inner.go_bridge_token,
            );
        }

        // A response with no body — a HEAD reply, a 204/304, or an explicit zero
        // length — has nothing to scan. Forward it as-is (preserving upstream
        // headers, e.g. a HEAD's echoed Content-Length); handing an empty buffer
        // to the analyzer just yields a spurious "unexpected end of file" block.
        if is_bodyless(&method, parts.status, &parts.headers) {
            tracing::debug!(url = %scan_url, "forward (no body to scan)");
            return build_response(parts.status, &parts.headers, passthrough_body(body), None);
        }

        let ram_cap = self.inner.config.max_body_bytes;
        let disk_cap = self.inner.config.max_scan_bytes;

        // A declared Content-Length past the disk-scan cap: too large to scan, so
        // forward it straight through unscanned rather than spilling gigabytes.
        if content_length(&parts.headers).is_some_and(|len| len > disk_cap) {
            tracing::debug!(url = %scan_url, "forward (declared >scan cap, unscanned)");
            return build_response(parts.status, &parts.headers, passthrough_body(body), None);
        }

        let buffered = collect_or_spill(body, &scan_url, ram_cap, disk_cap).await?;
        self.finish_scanned_response(buffered, &scan_url, parts.status, &parts.headers)
            .await
    }

    async fn finish_scanned_response(
        &self,
        buffered: Buffered,
        scan_url: &str,
        status: StatusCode,
        headers: &HeaderMap,
    ) -> Result<Response<ProxyBody>> {
        match buffered {
            Buffered::Memory(bytes) if bytes.is_empty() => {
                tracing::debug!(url = scan_url, "forward (empty body)");
                build_response(status, headers, full_body(bytes), Some(0))
            }
            Buffered::Memory(bytes) => {
                let verdict = self
                    .inner
                    .scanner
                    .scan(ScanRequest {
                        url: scan_url.to_owned(),
                        body: bytes.to_vec(),
                    })
                    .await
                    .context("scanner")?;
                match verdict {
                    Verdict::Allow => {
                        let len = bytes.len() as u64;
                        tracing::debug!(
                            url = scan_url,
                            status = status.as_u16(),
                            bytes = len,
                            "forward"
                        );
                        build_response(status, headers, full_body(bytes), Some(len))
                    }
                    Verdict::Block(reason) => {
                        tracing::warn!(url = scan_url, verdict = reason.label(), "block");
                        Ok(blocked_response(scan_url, &reason))
                    }
                }
            }
            Buffered::Spilled {
                tmp,
                path,
                sha256,
                len,
                scan,
            } => {
                let verdict = if scan {
                    self.inner
                        .scanner
                        .scan_disk(DiskScanRequest {
                            url: scan_url.to_owned(),
                            path: path.clone(),
                            sha256,
                        })
                        .await
                        .context("disk scanner")?
                } else {
                    tracing::debug!(
                        url = scan_url,
                        len,
                        "forward (spilled >scan cap, unscanned)"
                    );
                    Verdict::Allow
                };
                match verdict {
                    Verdict::Allow => {
                        let file = tokio::fs::File::open(&path)
                            .await
                            .context("reopen spill file for forwarding")?;
                        tracing::debug!(
                            url = scan_url,
                            status = status.as_u16(),
                            bytes = len,
                            "forward (from disk)"
                        );
                        let response = build_response(status, headers, file_body(file), Some(len));
                        drop(tmp);
                        response
                    }
                    Verdict::Block(reason) => {
                        tracing::warn!(
                            url = scan_url,
                            bytes = len,
                            verdict = reason.label(),
                            "block"
                        );
                        Ok(blocked_response(scan_url, &reason))
                    }
                }
            }
        }
    }
}

/// Build the upstream URL and Host header value for a request.
///
/// - In the plaintext-forward case, the request URI is absolute and the URL
///   is taken from it directly.
/// - In the MITM case, the URI is origin-form; the authority comes from the
///   original CONNECT.
fn resolve_target(
    req: &Request<Incoming>,
    mitm_authority: Option<&str>,
    allow_absolute_https: bool,
) -> Result<(url::Url, String)> {
    if let Some(authority) = mitm_authority {
        let path = req
            .uri()
            .path_and_query()
            .map_or_else(|| "/".to_owned(), ToString::to_string);
        let url =
            url::Url::parse(&format!("https://{authority}{path}")).context("build mitm url")?;
        // RFC 7230 §5.4: the Host header should match the request target.
        let host_header = authority_header(&url).unwrap_or_else(|_| authority.to_owned());
        return Ok((url, host_header));
    }
    let uri = req.uri();
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| anyhow!("missing scheme in absolute URI"))?;
    if scheme != "http" && !(allow_absolute_https && scheme == "https") {
        return Err(anyhow!(
            "plaintext proxy only accepts http://; got {scheme}",
        ));
    }
    let url = url::Url::parse(&uri.to_string()).context("parse absolute uri")?;
    let host_header = authority_header(&url)?;
    Ok((url, host_header))
}

/// Render an HTTP Host value, retaining the brackets required around IPv6
/// literals. `Url::host_str()` intentionally omits those brackets.
fn authority_header(url: &url::Url) -> Result<String> {
    let host = url
        .host()
        .ok_or_else(|| anyhow!("absolute URI missing host"))?;
    Ok(url
        .port()
        .map_or_else(|| host.to_string(), |port| format!("{host}:{port}")))
}

async fn upstream_request(
    inner: &Inner,
    host: &str,
    port: u16,
    is_https: bool,
    req: Request<Incoming>,
) -> Result<Response<Incoming>> {
    let tcp = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("connect {host}:{port}"))?;
    // TCP_NODELAY is advisory — some platforms reject; not fatal.
    drop(tcp.set_nodelay(true));

    if is_https {
        let server_name = ServerName::try_from(host.to_owned())
            .map_err(|e| anyhow!("invalid SNI {host}: {e}"))?;
        let connector = TlsConnector::from(Arc::clone(&inner.upstream_tls));
        let tls = connector
            .connect(server_name, tcp)
            .await
            .context("upstream tls handshake")?;
        send_one(tls, req).await
    } else {
        send_one(tcp, req).await
    }
}

async fn send_one<IO>(io: IO, req: Request<Incoming>) -> Result<Response<Incoming>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = client_http1::handshake(TokioIo::new(io))
        .await
        .context("http1 handshake")?;
    // The connection driver must be polled for I/O to progress. Spawn it.
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::trace!(error = %e, "upstream connection driver");
        }
    });
    let resp = sender.send_request(req).await.context("send_request")?;
    Ok(resp)
}

/// Outcome of reading an upstream body under the size policy.
enum Buffered {
    /// Fit within the in-RAM cap — buffered whole and scanned in memory.
    Memory(Bytes),
    /// Spilled to a temporary file (dropping `tmp` unlinks it). `scan` is true
    /// when the payload is within the disk-scan cap; false when it is too large
    /// to scan and must be forwarded from disk unscanned.
    Spilled {
        tmp: tempfile::NamedTempFile,
        path: std::path::PathBuf,
        sha256: [u8; 32],
        len: u64,
        scan: bool,
    },
}

/// Read an upstream body, buffering it in RAM up to `ram_cap`, then spilling the
/// remainder to a temp file (up to and past `disk_cap`). The SHA-256 is computed
/// while streaming so the disk path never re-reads the payload just to hash it.
async fn collect_or_spill(
    body: Incoming,
    url: &str,
    ram_cap: u64,
    disk_cap: u64,
) -> Result<Buffered> {
    let mut body = body;
    let mut buf: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.context("read upstream frame")?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if buf.len() as u64 + data.len() as u64 > ram_cap {
            // Cross into spill mode, carrying the RAM prefix and the frame that
            // tipped us over the cap.
            return spill_to_disk(body, url, buf, data, disk_cap).await;
        }
        buf.extend_from_slice(&data);
    }
    Ok(Buffered::Memory(Bytes::from(buf)))
}

/// Drain the rest of an oversized body to a temp file, hashing as we go.
async fn spill_to_disk(
    mut body: Incoming,
    url: &str,
    prefix: Vec<u8>,
    overflow: Bytes,
    disk_cap: u64,
) -> Result<Buffered> {
    let tmp = tempfile::Builder::new()
        .prefix("hood-")
        .suffix(&temp_suffix(url))
        .tempfile()
        .context("create spill file")?;
    let path = tmp.path().to_path_buf();
    let mut file = tokio::fs::File::from_std(tmp.reopen().context("reopen spill file")?);

    let mut hasher = Sha256::new();
    let mut len: u64 = 0;
    for chunk in [prefix.as_slice(), overflow.as_ref()] {
        hasher.update(chunk);
        file.write_all(chunk).await.context("write spill file")?;
        len += chunk.len() as u64;
    }
    while let Some(frame) = body.frame().await {
        let frame = frame.context("read upstream frame")?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        hasher.update(&data);
        file.write_all(&data).await.context("write spill file")?;
        len += data.len() as u64;
    }
    file.flush().await.context("flush spill file")?;
    drop(file); // close the write handle before the file is read back for scanning

    let sha256: [u8; 32] = hasher.finalize().into();
    Ok(Buffered::Spilled {
        tmp,
        path,
        sha256,
        len,
        scan: len <= disk_cap,
    })
}

/// Derive a filename suffix from a URL so a spill file carries the payload's real
/// extension — cleave's type detection keys on it. Empty when there's no clean,
/// short, alphanumeric extension to copy.
fn temp_suffix(url: &str) -> String {
    let basename = url.rsplit('/').next().unwrap_or("");
    let basename = basename.split(['?', '#']).next().unwrap_or(basename);
    match basename.rsplit_once('.') {
        Some((_, ext))
            if !ext.is_empty()
                && ext.len() <= 16
                && ext.bytes().all(|b| b.is_ascii_alphanumeric()) =>
        {
            format!(".{ext}")
        }
        _ => String::new(),
    }
}

/// True when a response is defined to carry no message body, so scanning it is
/// both pointless and — for archive-typed URLs — actively wrong (an empty buffer
/// trips cleave's "unexpected end of file"). Covers HEAD replies, `204 No
/// Content`, `304 Not Modified`, and an explicit `Content-Length: 0`.
fn is_bodyless(method: &Method, status: StatusCode, headers: &hyper::HeaderMap) -> bool {
    *method == Method::HEAD
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
        || content_length(headers) == Some(0)
}

/// Parse a `Content-Length` header into a byte count, if present and well-formed.
fn content_length(headers: &hyper::HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

/// Build a forwarded response: copy the upstream status and headers minus
/// hop-by-hop, and — when the body length is known exactly (a buffered or
/// disk-forwarded body) — set a fresh `Content-Length`, overriding any inherited
/// one. Pass `content_length: None` to stream through with the upstream framing.
fn build_response(
    status: StatusCode,
    headers: &hyper::HeaderMap,
    body: ProxyBody,
    content_length: Option<u64>,
) -> Result<Response<ProxyBody>> {
    let mut builder = Response::builder().status(status);
    let mut headers = headers.clone();
    strip_hop_by_hop(&mut headers).context("sanitize upstream response headers")?;
    for (k, v) in &headers {
        // When we set our own length, drop the inherited one to avoid duplicates.
        if content_length.is_some() && *k == CONTENT_LENGTH {
            continue;
        }
        builder = builder.header(k, v);
    }
    if let Some(len) = content_length {
        builder = builder.header(CONTENT_LENGTH, len);
    }
    builder.body(body).context("build response")
}

/// Convert credentials embedded in a configured GOPROXY/GOSUMDB URL into an
/// Authorization header, then remove them from the URL before scanning or
/// logging it. Relative redirects retain credentials through `redirect_base`.
fn take_url_authorization(target: &mut url::Url) -> Result<Option<HeaderValue>> {
    if target.username().is_empty() && target.password().is_none() {
        return Ok(None);
    }
    let username = percent_encoding::percent_decode_str(target.username()).collect::<Vec<_>>();
    let password = target.password().map_or_else(Vec::new, |password| {
        percent_encoding::percent_decode_str(password).collect::<Vec<_>>()
    });
    let mut credentials = Vec::with_capacity(username.len() + password.len() + 1);
    credentials.extend_from_slice(&username);
    credentials.push(b':');
    credentials.extend_from_slice(&password);
    let value = HeaderValue::try_from(format!("Basic {}", STANDARD.encode(credentials)))
        .context("encode upstream URL credentials")?;
    target
        .set_username("")
        .map_err(|()| anyhow!("remove upstream URL username"))?;
    target
        .set_password(None)
        .map_err(|()| anyhow!("remove upstream URL password"))?;
    Ok(Some(value))
}

/// Keep redirects from escaping the macOS Go loopback bridge. Module proxies
/// commonly redirect zip payloads to object storage; an absolute HTTPS
/// Location would otherwise send Go back through the CA path it cannot trust.
fn rewrite_go_bridge_location(headers: &mut hyper::HeaderMap, request_url: &url::Url, token: &str) {
    let Some(raw) = headers.get(LOCATION).and_then(|value| value.to_str().ok()) else {
        return;
    };
    let Ok(mut target) = request_url.join(raw) else {
        tracing::warn!(location = raw, "invalid upstream Go bridge redirect");
        return;
    };
    if !matches!(target.scheme(), "http" | "https") {
        tracing::warn!(
            location = raw,
            scheme = target.scheme(),
            "unsupported Go bridge redirect"
        );
        return;
    }
    target.set_fragment(None);
    let local = go_bridge::redirect_location(token, &target);
    match HeaderValue::try_from(local) {
        Ok(value) => {
            headers.insert(LOCATION, value);
        }
        Err(e) => {
            tracing::warn!(error = %e, "could not encode Go bridge redirect");
        }
    }
}

fn strip_hop_by_hop(headers: &mut hyper::HeaderMap) -> Result<()> {
    // RFC 7230 also makes every field named by `Connection` hop-by-hop. Merely
    // removing the standard list can forward attacker-selected connection
    // metadata and enables request-smuggling differentials between hops.
    let mut to_remove = Vec::<HeaderName>::new();
    for value in headers.get_all(CONNECTION) {
        let value = value
            .to_str()
            .context("Connection header contains non-ASCII bytes")?;
        for token in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            to_remove.push(
                HeaderName::from_bytes(token.as_bytes())
                    .with_context(|| format!("invalid Connection header token {token:?}"))?,
            );
        }
    }
    to_remove.extend(headers.keys().filter(|k| is_hop_by_hop(k)).cloned());
    for k in to_remove {
        headers.remove(k);
    }
    Ok(())
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP
        .iter()
        .any(|h| name.as_str().eq_ignore_ascii_case(h))
}

fn error_response(status: StatusCode, msg: &str) -> Response<ProxyBody> {
    // Header values are static ASCII; the only way this could fail is an
    // invalid status (impossible — typed input). On the off chance the builder
    // returns Err we fall back to a bodyless response with the requested code.
    let body = full_body(Bytes::from(format!("{msg}\n")));
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body)
        .unwrap_or_else(|_| {
            let mut fallback = Response::new(full_body(Bytes::new()));
            *fallback.status_mut() = status;
            fallback
        })
}

fn blocked_response(url: &str, reason: &BlockReason) -> Response<ProxyBody> {
    // RFC 7725: 451 Unavailable for Legal Reasons. We bend the semantics — it's
    // closer to "withheld by middleware policy" — but no closer code exists,
    // and it's distinctive enough that tools and humans can spot it.
    let body = format!(
        "hood blocked this response.\nurl: {url}\nverdict: {}\n",
        reason.label(),
    );
    let status = StatusCode::from_u16(451).unwrap_or(StatusCode::FORBIDDEN);
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-hood-block-reason", reason.label())
        .body(full_body(Bytes::from(body)))
        .unwrap_or_else(|_| error_response(StatusCode::FORBIDDEN, "blocked"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use hyper::header::HeaderMap;

    #[test]
    fn rejects_non_loopback_bind() {
        assert!(
            Config::default()
                .with_bind(([0, 0, 0, 0], 0).into())
                .is_err()
        );
    }

    #[test]
    fn rejects_invalid_scan_limits() {
        assert!(Config::default().with_scan_limits(0, 1).is_err());
        assert!(Config::default().with_scan_limits(2, 1).is_err());
    }

    #[test]
    fn rejects_invalid_environment_limits() {
        assert!(megabytes_to_bytes("LIMIT", "not-a-number").is_err());
        assert!(megabytes_to_bytes("LIMIT", &u64::MAX.to_string()).is_err());
    }

    #[test]
    fn strip_hop_by_hop_removes_listed_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", "close".parse().unwrap());
        headers.insert("keep-alive", "timeout=5".parse().unwrap());
        headers.insert("content-type", "text/plain".parse().unwrap());
        strip_hop_by_hop(&mut headers).unwrap();
        assert!(!headers.contains_key("connection"));
        assert!(!headers.contains_key("keep-alive"));
        assert!(headers.contains_key("content-type"));
    }

    #[test]
    fn strip_hop_by_hop_removes_connection_nominated_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", "x-internal, keep-alive".parse().unwrap());
        headers.insert("x-internal", "do-not-forward".parse().unwrap());
        headers.insert("content-type", "text/plain".parse().unwrap());
        strip_hop_by_hop(&mut headers).unwrap();
        assert!(!headers.contains_key("x-internal"));
        assert!(!headers.contains_key("connection"));
        assert!(headers.contains_key("content-type"));
    }

    #[test]
    fn hop_by_hop_check_is_case_insensitive() {
        assert!(is_hop_by_hop(&HeaderName::from_static("transfer-encoding")));
        assert!(is_hop_by_hop(&HeaderName::from_static("upgrade")));
        assert!(!is_hop_by_hop(&HeaderName::from_static("content-type")));
    }

    #[test]
    fn bridge_url_credentials_become_basic_auth_and_leave_logs() {
        let mut target = url::Url::parse("https://user:p%40ss@proxy.example/base").unwrap();
        let authorization = take_url_authorization(&mut target).unwrap().unwrap();
        assert_eq!(authorization, "Basic dXNlcjpwQHNz");
        assert_eq!(target.as_str(), "https://proxy.example/base");
    }
}
