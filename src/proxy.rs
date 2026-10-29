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
//! - Absolute-form `https://` requests, accepted only when
//!   [`Config::with_zig_clients`] is enabled. Zig's HTTP client cannot trust
//!   hood's CA, so its CONNECT is refused with 405 and it falls back to
//!   absolute form; hood performs the verified upstream TLS handshake itself.
//!   The plaintext leg never leaves loopback.
//!
//! Hop-by-hop headers are stripped on both legs and `Accept-Encoding` is forced
//! to `identity` on outbound so we never have to decompress for scanning.
//!
//! Response bodies are held until assessment. A body within the configured
//! in-memory limit is buffered and scanned in RAM; a larger one spills to a
//! temp file and is scanned from disk (cleave memory-maps it) up to the
//! configured scan limit. Past that limit nothing more is written, and the
//! scanner decides the download unscanned ([`Scanner::scan_limit`]). Forwarded
//! large bodies stream back from the spill file, so a multi-gigabyte transfer
//! never materializes whole in RAM.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use futures_util::{StreamExt, TryStreamExt};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, BodyStream, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::client::conn::http1 as client_http1;
use hyper::header::{
    ACCEPT_ENCODING, AUTHORIZATION, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE,
    HOST, HeaderMap, HeaderName, HeaderValue, LOCATION, USER_AGENT,
};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::io::ReaderStream;
use tokio_util::sync::CancellationToken;

use crate::ca::{Ca, CaResolver};
use crate::go_bridge;
use crate::output::ShownUrl;
use crate::scanner::{BlockReason, DiskScanRequest, ScanRequest, Scanner, Verdict};

/// The proxy's response body. A [`BoxBody`] so one return type covers three
/// shapes: a fully-buffered small response ([`full_body`]), an upstream body
/// streamed straight through ([`passthrough_body`]), and a large payload
/// streamed back from its on-disk spill file.
type ProxyBody = BoxBody<Bytes, std::io::Error>;

/// Wrap fully-buffered bytes as a [`ProxyBody`].
fn full_body(bytes: Bytes) -> ProxyBody {
    // `Full`'s error type is `Infallible`; widen it to the boxed error type.
    Full::new(bytes).map_err(|e| match e {}).boxed()
}

/// Stream an upstream body straight through to the client without buffering —
/// used only for inspection failures the scanner's policy explicitly allows.
fn passthrough_body(body: Incoming) -> ProxyBody {
    body.map_err(std::io::Error::other).boxed()
}

/// Upper bound on a response body buffered *in memory* for scanning. Larger
/// responses spill to a temp file and are scanned from there; cleave
/// memory-maps it, so scanning costs no more either way. Enough for nearly every
/// package, and small enough that a burst of parallel downloads stays cheap.
const MAX_BODY_BYTES_DEFAULT: u64 = 64 * 1024 * 1024;

/// How long reaching an origin may take: TCP connect, then TLS handshake, each.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long an origin may take to send response headers. Registries that
/// build an archive on request answer slowly, so this is generous.
const UPSTREAM_RESPONSE_TIMEOUT: Duration = Duration::from_mins(2);

/// How long an origin may leave a response body idle. Per frame, so a slow
/// but moving multi-gigabyte download is never cut off.
const UPSTREAM_IDLE_TIMEOUT: Duration = Duration::from_mins(2);

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
    /// Maximum response body inspected; `u64::MAX`, the default, inspects
    /// everything. Larger responses are decided by [`Scanner::scan_limit`].
    max_scan_bytes: u64,
    /// Bind address. Forced to a loopback address for safety.
    bind: SocketAddr,
    /// Additional roots used to verify upstream TLS. Intended for private PKI
    /// and deterministic tests; native platform roots are always loaded too.
    extra_upstream_roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    /// Refuse CONNECT from Zig's HTTP client; accept absolute-form `https://`.
    zig_clients: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_body_bytes: MAX_BODY_BYTES_DEFAULT,
            max_scan_bytes: u64::MAX,
            // 127.0.0.1:0 → kernel-assigned ephemeral port.
            bind: ([127, 0, 0, 1], 0).into(),
            extra_upstream_roots: Vec::new(),
            zig_clients: false,
        }
    }
}

impl Config {
    /// Set the in-memory and total scan limits.
    ///
    /// # Errors
    ///
    /// Returns an error if `max_body_bytes` is zero or exceeds
    /// `max_scan_bytes`.
    pub fn with_scan_limits(mut self, max_body_bytes: u64, max_scan_bytes: u64) -> Result<Self> {
        if max_body_bytes == 0 {
            bail!("max_body_bytes must be greater than zero");
        }
        if max_scan_bytes < max_body_bytes {
            bail!(
                "max_scan_bytes ({max_scan_bytes}) must be at least max_body_bytes ({max_body_bytes})",
            );
        }
        self.max_body_bytes = max_body_bytes;
        self.max_scan_bytes = max_scan_bytes;
        Ok(self)
    }

    /// Inspect at most `limit` bytes of a response, deciding anything larger
    /// with [`Scanner::scan_limit`]; `None` inspects everything.
    ///
    /// # Errors
    ///
    /// Returns an error if `limit` is below the in-memory buffer size.
    pub fn with_scan_limit(self, limit: Option<u64>) -> Result<Self> {
        let max_body_bytes = self.max_body_bytes;
        self.with_scan_limits(max_body_bytes, limit.unwrap_or(u64::MAX))
    }

    /// Set the listener address.
    ///
    /// # Errors
    ///
    /// Returns an error unless `bind` is loopback-only.
    pub fn with_bind(mut self, bind: SocketAddr) -> Result<Self> {
        if !bind.ip().is_loopback() {
            bail!("refusing to bind on non-loopback address: {}", bind.ip());
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

    /// Serve Zig's `std.http` client, which trusts only fixed system stores.
    ///
    /// CONNECT requests with Zig's default user agent are refused, so Zig
    /// falls back to absolute-form requests; those `https://` requests are
    /// accepted and fetched over verified upstream TLS. Every other client
    /// keeps the CONNECT/MITM path. A client misreporting its user agent only
    /// chooses which scanned path it takes, and fails closed on the wrong one.
    #[must_use]
    pub const fn with_zig_clients(mut self, enabled: bool) -> Self {
        self.zig_clients = enabled;
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
    /// Built on first use: loading platform roots takes ~130 ms on macOS,
    /// longer than many child commands run. See [`Inner::upstream_tls`].
    upstream_tls: tokio::sync::OnceCell<Arc<ClientConfig>>,
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
    /// Build a proxy. Generates an ephemeral CA; native TLS roots for
    /// verifying upstream servers load in the background once it is spawned.
    ///
    /// # Errors
    ///
    /// Returns an error if certificate or route-token generation fails.
    pub fn new(scanner: Arc<dyn Scanner>, config: Config) -> Result<Self> {
        let ca = Ca::generate()?;
        // An independent 128-bit route token for the loopback Go bridge. It
        // must not be derived from the CA certificate, which is deliberately
        // shared with the child process and is not secret key material.
        let mut random = [0_u8; 16];
        rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut random)
            .map_err(|error| anyhow!("generate Go bridge route token: {error:?}"))?;
        let go_bridge_token = crate::scanner::hex(&random);

        Ok(Self {
            inner: Arc::new(Inner {
                scanner,
                ca,
                upstream_tls: tokio::sync::OnceCell::new(),
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
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(accept_loop(listener, self.clone(), shutdown.clone()));
        // Load upstream roots while the child starts rather than delaying it.
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            if let Err(e) = inner.upstream_tls().await {
                tracing::warn!(error = %format!("{e:#}"), "upstream TLS unavailable");
            }
        });
        Ok(Handle {
            addr,
            shutdown,
            task: Some(task),
        })
    }
}

impl Inner {
    /// Upstream TLS client configuration, built once off the async workers.
    /// Every HTTPS forward waits for it; a failure fails that forward closed
    /// and is retried on the next one.
    async fn upstream_tls(&self) -> Result<Arc<ClientConfig>> {
        self.upstream_tls
            .get_or_try_init(|| async {
                let extra = self.config.extra_upstream_roots.clone();
                let (tx, rx) = tokio::sync::oneshot::channel();
                // A detached thread, not `spawn_blocking`: runtime shutdown
                // waits for blocking tasks, which would charge this load to
                // runs that finish without needing it.
                std::thread::Builder::new()
                    .name("hood-tls-roots".to_owned())
                    .spawn(move || drop(tx.send(upstream_tls_config(&extra))))
                    .context("spawn upstream TLS loader")?;
                rx.await.context("upstream TLS loader exited")?
            })
            .await
            .cloned()
    }
}

/// Platform trust roots, loaded once per process and shared by the proxy's
/// upstream verifier and the Beamline client. Loading takes ~130 ms on macOS,
/// so it runs on background threads; [`Proxy::spawn`] starts it while the
/// child process starts.
pub(crate) fn native_roots() -> &'static RootCertStore {
    static ROOTS: std::sync::OnceLock<RootCertStore> = std::sync::OnceLock::new();
    ROOTS.get_or_init(|| {
        let native = rustls_native_certs::load_native_certs();
        for error in &native.errors {
            tracing::debug!(%error, "native trust store partly unreadable");
        }
        let mut roots = RootCertStore::empty();
        // Platform stores routinely hold roots rustls cannot use (expired,
        // unsupported algorithms); skipping them is expected, so only counted.
        let (added, ignored) = roots.add_parsable_certificates(native.certs);
        tracing::debug!(added, ignored, "native trust roots loaded");
        roots
    })
}

/// Build the verifier for upstream servers from the platform roots plus any
/// configured extras. Unlike the platform's, a configured root that rustls
/// rejects is an error: someone chose it, and expects it to be trusted.
fn upstream_tls_config(
    extra_roots: &[rustls::pki_types::CertificateDer<'static>],
) -> Result<Arc<ClientConfig>> {
    let mut roots = native_roots().clone();
    for cert in extra_roots {
        roots
            .add(cert.clone())
            .context("add configured upstream TLS root")?;
    }
    if roots.is_empty() {
        bail!("no native TLS roots found; cannot verify upstream servers");
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Running-proxy handle. Drop or `stop()` to terminate.
#[derive(Debug)]
pub struct Handle {
    /// Bound address (with the kernel-assigned port resolved).
    pub addr: SocketAddr,
    shutdown: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Handle {
    /// Signal shutdown and wait for the accept loop to exit.
    pub async fn stop(mut self) {
        self.shutdown.cancel();
        if let Some(task) = self.task.take() {
            // Best-effort: connection failures are logged at their source.
            drop(task.await);
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// How long the accept loop pauses after a failed accept. Running out of file
/// descriptors fails every accept at once; retrying immediately would spin.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

async fn accept_loop(listener: TcpListener, proxy: Proxy, shutdown: CancellationToken) {
    loop {
        tokio::select! {
            biased;
            // Cancellation is sticky, so a stop issued before this loop first
            // polls is still seen.
            () = shutdown.cancelled() => {
                tracing::debug!("proxy shutdown");
                return;
            }
            acc = listener.accept() => match acc {
                Ok((stream, peer)) => {
                    tracing::trace!(%peer, "accept");
                    tokio::spawn(serve_inbound_plain(stream, proxy.clone()));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                }
            }
        }
    }
}

/// Serve an inbound plaintext connection. Handles both plain HTTP forwarding
/// and CONNECT upgrades (which transition into the TLS-MITM path).
async fn serve_inbound_plain(stream: TcpStream, proxy: Proxy) {
    let svc = service_fn(move |req| {
        let proxy = proxy.clone();
        async move { Ok::<_, Infallible>(proxy.dispatch_inbound(req, None).await) }
    });
    if let Err(e) = server_http1::Builder::new()
        .serve_connection(TokioIo::new(stream), svc)
        .with_upgrades()
        .await
    {
        tracing::trace!(error = %e, "inbound connection ended");
    }
}

/// Serve the inside of a CONNECT tunnel. `origin` (`https://host:port` for
/// decrypted TLS, `http://host:port` for plaintext) comes from the original
/// CONNECT and tells us how to reach upstream.
async fn serve_inbound_tunnel<IO>(stream: IO, proxy: Proxy, origin: String)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let origin = Arc::<str>::from(origin);
    let svc = service_fn(move |req| {
        let proxy = proxy.clone();
        let origin = Arc::clone(&origin);
        async move { Ok::<_, Infallible>(proxy.dispatch_inbound(req, Some(origin)).await) }
    });
    if let Err(e) = server_http1::Builder::new()
        .serve_connection(TokioIo::new(stream), svc)
        .await
    {
        tracing::trace!(error = %e, "tunnel connection ended");
    }
}

impl Proxy {
    /// Top-level request dispatcher. `tunnel_origin` is `Some(scheme://host:port)`
    /// when we're handling the inside of a CONNECT tunnel.
    async fn dispatch_inbound(
        &self,
        mut req: Request<Incoming>,
        tunnel_origin: Option<Arc<str>>,
    ) -> Response<ProxyBody> {
        // CONNECT only ever arrives on the plaintext side.
        if req.method() == Method::CONNECT && tunnel_origin.is_none() {
            // Zig's CONNECT never carries caller headers, so it always sends
            // the default `zig/<version> (std.http)` user agent.
            let zig = req
                .headers()
                .get(USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|agent| agent.starts_with("zig/"));
            if self.inner.config.zig_clients && zig {
                // A 4xx, not 5xx: Zig treats a server error as possibly
                // transient and keeps trying to tunnel.
                tracing::debug!(authority = ?req.uri().authority(), "refuse Zig CONNECT; expecting absolute-form https");
                return error_response(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "send absolute-form requests instead of CONNECT",
                );
            }
            return self.handle_connect(req);
        }

        // Go on macOS cannot trust hood's ephemeral CA from SSL_CERT_FILE.
        // Its module and sumdb requests instead arrive as authenticated,
        // origin-form loopback HTTP requests. Restore the encoded upstream URL
        // before feeding them into the normal verified+scanned forward path.
        let mut go_bridge_request = false;
        if tunnel_origin.is_none() && req.uri().path().starts_with(go_bridge::ROUTE_PREFIX) {
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
            .handle_forward(req, tunnel_origin, go_bridge_request)
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
        // The leaf's name when the client sends no SNI: the bare host, since
        // an IPv6 literal is bracketed in an authority but not in a SAN.
        let host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let proxy = self.clone();
        // Take the OnUpgrade future before spawning so the spawned task does
        // not need to hold the Request<Incoming> across .await.
        let on_upgrade = hyper::upgrade::on(&mut req);
        tokio::spawn(run_mitm_after_upgrade(
            proxy,
            on_upgrade,
            authority.to_string(),
            host,
        ));
        Response::new(full_body(Bytes::new()))
    }
}

async fn run_mitm_after_upgrade(
    proxy: Proxy,
    on_upgrade: hyper::upgrade::OnUpgrade,
    authority: String,
    host: String,
) {
    let upgraded = match on_upgrade.await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(authority, error = %e, "upgrade failed");
            return;
        }
    };
    let mut io = TokioIo::new(upgraded);
    // Some clients (pnpm, Zig) tunnel plain HTTP for `http://` URLs. A TLS
    // stream opens with a handshake record; anything else is served as HTTP.
    let mut first = [0_u8; 1];
    match io.read(&mut first).await {
        Ok(0) => return,
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(authority, error = %e, "tunnel read failed");
            return;
        }
    }
    let io = Prefixed {
        first: Some(first[0]),
        io,
    };
    if first[0] != TLS_HANDSHAKE {
        tracing::debug!(authority, "plaintext HTTP tunnel");
        serve_inbound_tunnel(io, proxy, format!("http://{authority}")).await;
        return;
    }
    let resolver = CaResolver::new(proxy.inner.ca.clone(), host);
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls = match TlsAcceptor::from(Arc::new(server_config)).accept(io).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(authority, error = %e, "tls accept failed");
            return;
        }
    };
    // From this point on, traffic is plaintext HTTP/1.1 inside our TLS server.
    serve_inbound_tunnel(tls, proxy, format!("https://{authority}")).await;
}

/// TLS record content type of a handshake, the first byte of every TLS stream.
const TLS_HANDSHAKE: u8 = 0x16;

/// A stream that yields one already-read byte before the rest of `io`.
struct Prefixed<IO> {
    first: Option<u8>,
    io: IO,
}

impl<IO: AsyncRead + Unpin> AsyncRead for Prefixed<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() > 0
            && let Some(byte) = this.first.take()
        {
            buf.put_slice(&[byte]);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.io).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Prefixed<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

impl Proxy {
    async fn handle_forward(
        &self,
        mut req: Request<Incoming>,
        tunnel_origin: Option<Arc<str>>,
        go_bridge_request: bool,
    ) -> Result<Response<ProxyBody>> {
        let (mut target_url, host_header) = resolve_target(
            &req,
            tunnel_origin.as_deref(),
            go_bridge_request || self.inner.config.zig_clients,
        )?;
        // A Go bridge redirect resolves against the request as configured,
        // credentials included; see `take_url_authorization`.
        let redirect_base = go_bridge_request.then(|| target_url.clone());
        let allow_purl = permits_public_coordinate(req.method(), req.headers(), &target_url);
        let url_authorization = take_url_authorization(&mut target_url)?;
        // Captured before `req` is consumed by the upstream call: a HEAD request
        // never carries a response body to scan.
        let method = req.method().clone();
        // The bare address to dial and verify: `host_str()` brackets an IPv6
        // literal, a form neither the socket nor the TLS server name accepts.
        let host = match target_url.host().ok_or_else(|| anyhow!("no host"))? {
            url::Host::Domain(domain) => domain.to_owned(),
            url::Host::Ipv4(ip) => ip.to_string(),
            url::Host::Ipv6(ip) => ip.to_string(),
        };
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

        // One upstream connection per request: nothing is pooled, so nothing
        // one request did can be reused by another.
        let response = upstream_request(&self.inner, &host, port, is_https, req).await?;
        let (mut parts, body) = response.into_parts();
        if let Some(base) = &redirect_base {
            rewrite_go_bridge_location(&mut parts.headers, base, &self.inner.go_bridge_token)?;
        }

        // A response with no body — a HEAD reply, a 204/304, or an explicit zero
        // length — has nothing to scan; handing an empty buffer to the analyzer
        // just yields a spurious "unexpected end of file" block. Its headers are
        // kept (a HEAD's echoed Content-Length), but its body is sent empty, not
        // streamed: whatever upstream framing might still deliver is unscanned.
        if method == Method::HEAD
            || parts.status == StatusCode::NO_CONTENT
            || parts.status == StatusCode::NOT_MODIFIED
            || content_length(&parts.headers) == Some(0)
        {
            tracing::debug!(url = %ShownUrl(&scan_url), "forward (no body to scan)");
            drop(body);
            return build_response(parts.status, parts.headers, full_body(Bytes::new()), None);
        }

        let ram_cap = self.inner.config.max_body_bytes;
        let disk_cap = self.inner.config.max_scan_bytes;

        // The request asked for `identity`. A server that encodes anyway would
        // have hood inspect compressed bytes while a decoding client runs what
        // they expand to, so an encoded body is one hood cannot inspect.
        if let Some(encoding) = content_encoding(&parts.headers) {
            let why = format!("response is {encoding}-encoded despite an identity request");
            let verdict = self.inner.scanner.uninspectable(&scan_url, &why);
            return uninspected(verdict, &scan_url, parts.status, parts.headers, || {
                Ok(passthrough_body(body))
            });
        }

        // A declared oversized download is never buffered.
        if let Some(len) = content_length(&parts.headers).filter(|&len| len > disk_cap) {
            let verdict = self
                .inner
                .scanner
                .scan_limit(&scan_url, disk_cap, Some(len));
            return uninspected(verdict, &scan_url, parts.status, parts.headers, || {
                Ok(passthrough_body(body))
            });
        }

        let size_hint = content_length(&parts.headers);
        let buffered = collect_or_spill(body, &scan_url, size_hint, ram_cap, disk_cap).await?;
        self.finish_scanned_response(
            buffered,
            &scan_url,
            allow_purl && parts.status.is_success(),
            parts.status,
            parts.headers,
        )
        .await
    }

    async fn finish_scanned_response(
        &self,
        buffered: Buffered,
        scan_url: &str,
        allow_purl: bool,
        status: StatusCode,
        headers: HeaderMap,
    ) -> Result<Response<ProxyBody>> {
        match buffered {
            Buffered::Memory { bytes, .. } if bytes.is_empty() => {
                tracing::debug!(url = %ShownUrl(scan_url), "forward (empty body)");
                build_response(status, headers, full_body(bytes), Some(0))
            }
            Buffered::Memory { bytes, sha256 } => {
                let verdict = self
                    .inner
                    .scanner
                    .scan(ScanRequest {
                        url: scan_url.to_owned(),
                        allow_purl,
                        body: bytes.clone(),
                        sha256,
                    })
                    .await;
                match verdict {
                    Verdict::Allow => {
                        let len = bytes.len() as u64;
                        tracing::debug!(
                            url = %ShownUrl(scan_url),
                            status = status.as_u16(),
                            bytes = len,
                            "forward"
                        );
                        build_response(status, headers, full_body(bytes), Some(len))
                    }
                    Verdict::Block(reason) => {
                        tracing::warn!(url = %ShownUrl(scan_url), verdict = reason.label(), "block");
                        Ok(blocked_response(scan_url, &reason))
                    }
                }
            }
            Buffered::Spilled { tmp, sha256, len } => {
                let verdict = self
                    .inner
                    .scanner
                    .scan_disk(DiskScanRequest {
                        url: scan_url.to_owned(),
                        allow_purl,
                        path: tmp.path().to_path_buf(),
                        sha256,
                    })
                    .await;
                match verdict {
                    Verdict::Allow => {
                        tracing::debug!(
                            url = %ShownUrl(scan_url),
                            status = status.as_u16(),
                            bytes = len,
                            "forward (from disk)"
                        );
                        let body = BodyExt::boxed(StreamBody::new(spill_stream(&tmp)?));
                        build_response(status, headers, body, Some(len))
                    }
                    Verdict::Block(reason) => {
                        tracing::warn!(
                            url = %ShownUrl(scan_url),
                            bytes = len,
                            verdict = reason.label(),
                            "block"
                        );
                        Ok(blocked_response(scan_url, &reason))
                    }
                }
            }
            Buffered::Oversized {
                tmp,
                overflow,
                rest,
            } => {
                let limit = self.inner.config.max_scan_bytes;
                let verdict = self.inner.scanner.scan_limit(scan_url, limit, None);
                uninspected(verdict, scan_url, status, headers, || {
                    // What was spilled, then the frame that crossed the limit,
                    // then the rest of the upstream body, unread by hood.
                    let body = spill_stream(&tmp)?
                        .chain(futures_util::stream::iter([Ok(Frame::data(overflow))]))
                        .chain(TryStreamExt::map_err(
                            BodyStream::new(rest),
                            std::io::Error::other,
                        ));
                    Ok(BodyExt::boxed(StreamBody::new(body)))
                })
            }
        }
    }
}

/// Answer for a body hood does not scan, as the scanner decided: withheld, or
/// streamed through as `body` builds it.
fn uninspected(
    verdict: Verdict,
    scan_url: &str,
    status: StatusCode,
    headers: HeaderMap,
    body: impl FnOnce() -> Result<ProxyBody>,
) -> Result<Response<ProxyBody>> {
    match verdict {
        Verdict::Block(reason) => {
            tracing::warn!(url = %ShownUrl(scan_url), verdict = reason.label(), "block");
            Ok(blocked_response(scan_url, &reason))
        }
        Verdict::Allow => {
            tracing::debug!(url = %ShownUrl(scan_url), status = status.as_u16(), "forward (unscanned)");
            build_response(status, headers, body()?, None)
        }
    }
}

/// Stream a spill file back out. It is reopened through the temp file's own
/// handle, which refuses a file swapped in at its path since it was written;
/// the open descriptor keeps it alive after the path is unlinked.
fn spill_stream(
    tmp: &tempfile::NamedTempFile,
) -> Result<impl futures_util::Stream<Item = std::io::Result<Frame<Bytes>>> + use<>> {
    let file = tmp.reopen().context("reopen spill file for forwarding")?;
    Ok(ReaderStream::new(tokio::fs::File::from_std(file)).map_ok(Frame::data))
}

/// The codings a response's `Content-Encoding` applies beyond `identity`, if
/// any. A value that is not ASCII is one hood cannot read, so it counts too.
fn content_encoding(headers: &HeaderMap) -> Option<String> {
    let mut codings = Vec::new();
    for value in headers.get_all(CONTENT_ENCODING) {
        let Ok(value) = value.to_str() else {
            return Some("unreadably".to_owned());
        };
        codings.extend(
            value
                .split(',')
                .map(str::trim)
                .filter(|coding| !coding.is_empty() && !coding.eq_ignore_ascii_case("identity")),
        );
    }
    (!codings.is_empty()).then(|| codings.join("+"))
}

/// Build the upstream URL and Host header value for a request.
///
/// - In the plaintext-forward case, the request URI is absolute and the URL
///   is taken from it directly.
/// - Inside a CONNECT tunnel, the URI is origin-form; the scheme and
///   authority come from the tunnel.
fn resolve_target(
    req: &Request<Incoming>,
    tunnel_origin: Option<&str>,
    allow_absolute_https: bool,
) -> Result<(url::Url, String)> {
    if let Some(origin) = tunnel_origin {
        let path = req
            .uri()
            .path_and_query()
            .map_or_else(|| "/".to_owned(), ToString::to_string);
        let url = url::Url::parse(&format!("{origin}{path}")).context("build tunnel url")?;
        // RFC 7230 §5.4: the Host header should match the request target.
        let host_header = authority_header(&url)?;
        return Ok((url, host_header));
    }
    let uri = req.uri();
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| anyhow!("missing scheme in absolute URI"))?;
    if scheme != "http" && !(allow_absolute_https && scheme == "https") {
        bail!("plaintext proxy only accepts http://; got {scheme}");
    }
    let url = url::Url::parse(&uri.to_string()).context("parse absolute uri")?;
    let host_header = authority_header(&url)?;
    Ok((url, host_header))
}

/// Render an HTTP Host value: the host as a URL writes it, IPv6 literals in
/// brackets, plus any explicit port.
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
    let tcp = tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .with_context(|| format!("connect {host} port {port}: timed out"))?
        .with_context(|| format!("connect {host} port {port}"))?;
    // TCP_NODELAY is advisory — some platforms reject; not fatal.
    drop(tcp.set_nodelay(true));

    if is_https {
        let server_name = ServerName::try_from(host.to_owned())
            .map_err(|e| anyhow!("invalid SNI {host}: {e}"))?;
        let connector = TlsConnector::from(inner.upstream_tls().await?);
        let tls = tokio::time::timeout(
            UPSTREAM_CONNECT_TIMEOUT,
            connector.connect(server_name, tcp),
        )
        .await
        .context("upstream TLS handshake timed out")?
        .context("upstream TLS handshake")?;
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
    tokio::time::timeout(UPSTREAM_RESPONSE_TIMEOUT, sender.send_request(req))
        .await
        .context("upstream response timed out")?
        .context("send_request")
}

/// Capture provenance before URL credentials are moved into headers.
fn permits_public_coordinate(method: &Method, headers: &HeaderMap, url: &url::Url) -> bool {
    method == Method::GET
        && !headers.contains_key(AUTHORIZATION)
        && !headers.contains_key("cookie")
        && url.username().is_empty()
        && url.password().is_none()
}

/// Outcome of reading an upstream body under the size policy.
enum Buffered {
    /// Fit within the in-RAM cap — buffered whole and scanned in memory.
    Memory { bytes: Bytes, sha256: [u8; 32] },
    /// Fit within the disk-scan cap — spilled whole to a temporary file
    /// (dropping `tmp` unlinks it) and scanned from there.
    Spilled {
        tmp: tempfile::NamedTempFile,
        sha256: [u8; 32],
        len: u64,
    },
    /// Crossed the disk-scan cap. Reading stopped there, so a hostile server
    /// cannot fill the disk: `tmp` holds what came before `overflow`, the frame
    /// that crossed, and `rest` is the upstream body not yet read. The scanner
    /// decides it unscanned ([`Scanner::scan_limit`]).
    Oversized {
        tmp: tempfile::NamedTempFile,
        overflow: Bytes,
        rest: Incoming,
    },
}

/// The next data frame of an upstream body, skipping trailers.
async fn next_data(body: &mut Incoming) -> Result<Option<Bytes>> {
    while let Some(frame) = tokio::time::timeout(UPSTREAM_IDLE_TIMEOUT, body.frame())
        .await
        .context("upstream body stalled")?
    {
        if let Ok(data) = frame.context("read upstream frame")?.into_data() {
            return Ok(Some(data));
        }
    }
    Ok(None)
}

/// Read an upstream body, buffering it in RAM up to `ram_cap`, then spilling the
/// remainder to a temp file up to `disk_cap`. The SHA-256 is computed frame by
/// frame as the body streams, so nothing is ever re-read just to hash it.
/// `size_hint`, the declared length, only sizes the buffer.
async fn collect_or_spill(
    mut body: Incoming,
    url: &str,
    size_hint: Option<u64>,
    ram_cap: u64,
    disk_cap: u64,
) -> Result<Buffered> {
    let capacity = usize::try_from(size_hint.unwrap_or(0).min(ram_cap)).unwrap_or(0);
    let mut buf = Vec::with_capacity(capacity);
    let mut hasher = Sha256::new();
    while let Some(data) = next_data(&mut body).await? {
        if buf.len() as u64 + data.len() as u64 > ram_cap {
            // Cross into spill mode, carrying the RAM prefix (already hashed)
            // and the frame that tipped us over the cap.
            return spill_to_disk(body, url, hasher, buf, data, disk_cap).await;
        }
        hasher.update(&data);
        buf.extend_from_slice(&data);
    }
    Ok(Buffered::Memory {
        bytes: Bytes::from(buf),
        sha256: hasher.finalize().into(),
    })
}

/// Drain the rest of a body too large for RAM to a temp file, hashing as we
/// go, and stop at `disk_cap`. `hasher` has already seen `prefix`.
async fn spill_to_disk(
    mut body: Incoming,
    url: &str,
    mut hasher: Sha256,
    prefix: Vec<u8>,
    overflow: Bytes,
    disk_cap: u64,
) -> Result<Buffered> {
    let tmp = tempfile::Builder::new()
        .prefix("hood-")
        .suffix(&temp_suffix(url))
        .tempfile()
        .context("create spill file")?;
    let mut file = tokio::fs::File::from_std(tmp.reopen().context("reopen spill file")?);

    file.write_all(&prefix).await.context("write spill file")?;
    let mut len = prefix.len() as u64;
    let mut chunk = overflow;
    loop {
        if len + chunk.len() as u64 > disk_cap {
            file.flush().await.context("flush spill file")?;
            return Ok(Buffered::Oversized {
                tmp,
                overflow: chunk,
                rest: body,
            });
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await.context("write spill file")?;
        len += chunk.len() as u64;
        match next_data(&mut body).await? {
            Some(next) => chunk = next,
            None => break,
        }
    }
    file.flush().await.context("flush spill file")?;
    drop(file); // close the write handle before the file is read back for scanning

    let sha256: [u8; 32] = hasher.finalize().into();
    Ok(Buffered::Spilled { tmp, sha256, len })
}

/// Derive a filename suffix from a URL so a spill file carries the payload's real
/// extension — cleave's type detection keys on it. Empty when there's no clean,
/// short, alphanumeric extension to copy.
fn temp_suffix(url: &str) -> String {
    // The query and fragment go first: a `/` inside one (`?r=/a.txt`) must not
    // let the server choose the extension cleave sees.
    let path = url.split(['?', '#']).next().unwrap_or_default();
    let basename = path.rsplit('/').next().unwrap_or_default();
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

/// Parse a `Content-Length` header into a byte count, if present and well-formed.
fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

/// Build a forwarded response from the upstream status and headers, minus
/// hop-by-hop ones. When the body length is known exactly (a buffered or
/// disk-forwarded body) it replaces any inherited `Content-Length`; `None`
/// streams through with the upstream framing.
fn build_response(
    status: StatusCode,
    mut headers: HeaderMap,
    body: ProxyBody,
    content_length: Option<u64>,
) -> Result<Response<ProxyBody>> {
    strip_hop_by_hop(&mut headers).context("sanitize upstream response headers")?;
    if let Some(len) = content_length {
        headers.insert(CONTENT_LENGTH, HeaderValue::from(len));
    }
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
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

/// Keep redirects from escaping the Go loopback bridge. Module proxies
/// commonly redirect zip payloads to object storage; an absolute HTTPS
/// Location would otherwise send Go back through the CA path it cannot trust.
///
/// # Errors
///
/// An HTTPS origin redirecting to plain HTTP. Go refuses that downgrade
/// itself, but behind the bridge it only ever sees loopback HTTP, so hood
/// refuses it on Go's behalf.
fn rewrite_go_bridge_location(
    headers: &mut HeaderMap,
    request_url: &url::Url,
    token: &str,
) -> Result<()> {
    let Some(raw) = headers.get(LOCATION).and_then(|value| value.to_str().ok()) else {
        return Ok(());
    };
    let Ok(mut target) = request_url.join(raw) else {
        tracing::warn!(location = raw, "invalid upstream Go bridge redirect");
        return Ok(());
    };
    match (request_url.scheme(), target.scheme()) {
        ("https", "http") => bail!("refusing Go bridge redirect from HTTPS to HTTP"),
        (_, "http" | "https") => {}
        (_, scheme) => {
            tracing::warn!(location = raw, scheme, "unsupported Go bridge redirect");
            return Ok(());
        }
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
    Ok(())
}

fn strip_hop_by_hop(headers: &mut HeaderMap) -> Result<()> {
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
    // Header names are stored lowercase, as the list is.
    HOP_BY_HOP.contains(&name.as_str())
}

/// A plain-text response hood writes itself.
fn text_response(status: StatusCode, text: String) -> Response<ProxyBody> {
    let mut response = Response::new(full_body(Bytes::from(text)));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn error_response(status: StatusCode, msg: &str) -> Response<ProxyBody> {
    text_response(status, format!("{msg}\n"))
}

fn blocked_response(url: &str, reason: &BlockReason) -> Response<ProxyBody> {
    // RFC 7725: 451 Unavailable for Legal Reasons. We bend the semantics — it's
    // closer to "withheld by middleware policy" — but no closer code exists,
    // and it's distinctive enough that tools and humans can spot it.
    let label = reason.label();
    let mut response = text_response(
        StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
        format!("hood blocked this response.\nurl: {url}\nverdict: {label}\n"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-hood-block-reason"),
        HeaderValue::from_static(label),
    );
    response
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_requests_never_disclose_coordinates() {
        let url = url::Url::parse("https://registry.npmjs.org/demo/-/demo-1.tgz").unwrap();
        let empty = HeaderMap::new();
        assert!(permits_public_coordinate(&Method::GET, &empty, &url));
        assert!(!permits_public_coordinate(&Method::POST, &empty, &url));
        for header in ["authorization", "cookie"] {
            let mut headers = HeaderMap::new();
            headers.insert(header, HeaderValue::from_static("private"));
            assert!(!permits_public_coordinate(&Method::GET, &headers, &url));
        }
        let credentialed =
            url::Url::parse("https://user:secret@registry.npmjs.org/demo/-/demo-1.tgz").unwrap();
        assert!(!permits_public_coordinate(
            &Method::GET,
            &empty,
            &credentialed
        ));
    }

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
    fn only_identity_content_encoding_is_inspectable() {
        let mut headers = HeaderMap::new();
        assert_eq!(content_encoding(&headers), None);
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("Identity"));
        assert_eq!(content_encoding(&headers), None);
        headers.append(CONTENT_ENCODING, HeaderValue::from_static("gzip, br"));
        assert_eq!(content_encoding(&headers).as_deref(), Some("gzip+br"));
        let mut opaque = HeaderMap::new();
        opaque.insert(
            CONTENT_ENCODING,
            HeaderValue::from_bytes(b"\xffzip").unwrap(),
        );
        assert!(content_encoding(&opaque).is_some());
    }

    #[test]
    fn bridge_url_credentials_become_basic_auth_and_leave_logs() {
        let mut target = url::Url::parse("https://user:p%40ss@proxy.example/base").unwrap();
        let authorization = take_url_authorization(&mut target).unwrap().unwrap();
        assert_eq!(authorization, "Basic dXNlcjpwQHNz");
        assert_eq!(target.as_str(), "https://proxy.example/base");
    }

    /// On a current-thread runtime the accept loop has not run when `spawn`
    /// returns; a stop issued then must still end it.
    #[tokio::test]
    async fn stop_before_the_accept_loop_runs_still_stops() {
        drop(rustls::crypto::ring::default_provider().install_default());
        let proxy = Proxy::new(Arc::new(crate::scanner::AllowAll), Config::default()).unwrap();
        let handle = proxy.spawn().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), handle.stop())
            .await
            .unwrap();
    }

    #[test]
    fn go_bridge_redirects_stay_on_the_bridge_and_never_downgrade() {
        let origin = url::Url::parse("https://proxy.golang.org/m/@v/v1.zip").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            LOCATION,
            HeaderValue::from_static("https://storage.example/m.zip"),
        );
        rewrite_go_bridge_location(&mut headers, &origin, "token").unwrap();
        let location = headers.get(LOCATION).unwrap().to_str().unwrap();
        assert!(location.starts_with(go_bridge::ROUTE_PREFIX), "{location}");

        let mut headers = HeaderMap::new();
        headers.insert(
            LOCATION,
            HeaderValue::from_static("http://storage.example/m.zip"),
        );
        assert!(rewrite_go_bridge_location(&mut headers, &origin, "token").is_err());
    }

    #[test]
    fn spill_suffix_comes_from_the_path_alone() {
        for (url, suffix) in [
            ("https://x/pkg-1.0.tgz", ".tgz"),
            ("https://x/pkg.tgz?r=/a.txt", ".tgz"),
            ("https://x/pkg.tgz#/a.txt", ".tgz"),
            ("https://x/download?file=a.exe", ""),
            ("https://x/archive.tar.gz", ".gz"),
            ("https://x/odd.t-z", ""),
            ("https://x/", ""),
        ] {
            assert_eq!(temp_suffix(url), suffix, "{url}");
        }
    }
}
