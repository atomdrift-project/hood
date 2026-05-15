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
//! Hop-by-hop headers are stripped on both legs, `Accept-Encoding` is forced
//! to `identity` on outbound so we never have to decompress for scanning, and
//! response bodies are capped at [`Proxy::max_body_bytes`] to bound memory.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::header::{HeaderName, HeaderValue, ACCEPT_ENCODING, CONTENT_LENGTH, HOST};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::ca::{Ca, CaResolver};
use crate::scanner::{BlockReason, ScanRequest, Scanner, Verdict};

/// Default upper bound on response body size accepted for scanning, in bytes.
/// Larger responses are rejected with 413.
pub const DEFAULT_MAX_BODY_BYTES: u64 = 256 * 1024 * 1024;

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

/// Headers that carry credentials. Their *names* are fine to log but values
/// must be redacted.
const SENSITIVE: &[&str] = &["authorization", "cookie", "set-cookie", "proxy-authorization"];

/// Configuration for a new proxy instance.
#[derive(Debug, Clone)]
pub struct Config {
    /// Maximum buffered response body. Larger responses are rejected.
    pub max_body_bytes: u64,
    /// Bind address. Forced to a loopback address for safety.
    pub bind: SocketAddr,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            // 127.0.0.1:0 → kernel-assigned ephemeral port.
            bind: ([127, 0, 0, 1], 0).into(),
        }
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
    pub fn new(scanner: Arc<dyn Scanner>, config: Config) -> Result<Self> {
        if !config.bind.ip().is_loopback() {
            return Err(anyhow!(
                "refusing to bind on non-loopback address: {}",
                config.bind.ip(),
            ));
        }
        let ca = Ca::generate()?;
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

    /// Bind the listener and start accepting. Returns a handle for shutdown.
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
            task,
        })
    }
}

/// Running-proxy handle. Drop or `stop()` to terminate.
#[derive(Debug)]
pub struct Handle {
    /// Bound address (with the kernel-assigned port resolved).
    pub addr: SocketAddr,
    shutdown: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl Handle {
    /// Signal shutdown and wait for the accept loop to exit.
    pub async fn stop(self) {
        self.shutdown.notify_waiters();
        // Best-effort: a panicked accept loop is logged elsewhere.
        drop(self.task.await);
    }
}

async fn accept_loop(listener: TcpListener, proxy: Proxy, shutdown: Arc<Notify>) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.notified() => {
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
        async move {
            Ok::<_, Infallible>(proxy.dispatch_inbound(req, Some(authority)).await)
        }
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
        req: Request<Incoming>,
        mitm_authority: Option<Arc<str>>,
    ) -> Response<Full<Bytes>> {
        // CONNECT only ever arrives on the plaintext side.
        if req.method() == Method::CONNECT && mitm_authority.is_none() {
            return self.handle_connect(req);
        }
        match self.handle_forward(req, mitm_authority).await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "forward failed");
                error_response(StatusCode::BAD_GATEWAY, "upstream error")
            }
        }
    }

    fn handle_connect(&self, mut req: Request<Incoming>) -> Response<Full<Bytes>> {
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
            .body(Full::new(Bytes::new()))
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
    ) -> Result<Response<Full<Bytes>>> {
        let (target_url, host_header) = resolve_target(&req, mitm_authority.as_deref())?;
        let host = target_url
            .host_str()
            .ok_or_else(|| anyhow!("no host"))?
            .to_owned();
        let is_https = target_url.scheme() == "https";
        let port = target_url
            .port()
            .unwrap_or(if is_https { 443 } else { 80 });

        // Rewrite request: switch to origin-form URI, drop hop-by-hop, force identity encoding.
        let mut origin_form = target_url.path().to_owned();
        if let Some(q) = target_url.query() {
            origin_form.push('?');
            origin_form.push_str(q);
        }
        let new_uri: Uri = origin_form.parse().context("rebuild origin-form uri")?;
        *req.uri_mut() = new_uri;

        let headers = req.headers_mut();
        strip_hop_by_hop(headers);
        // Some clients send Proxy-Connection; hop-by-hop strip covers it. Reset Host.
        headers.insert(HOST, HeaderValue::try_from(host_header.as_str())?);
        // Force identity so we always see plaintext bytes for scanning.
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));

        // Open upstream connection (no pool for v1; one TCP per request).
        let response = upstream_request(&self.inner, &host, port, is_https, req).await?;

        // Buffer body subject to the cap, then scan.
        let (parts, body) = response.into_parts();
        let content_type = parts
            .headers
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let bytes = collect_body_capped(body, self.inner.config.max_body_bytes).await?;
        let body_len = bytes.len();

        let scan_url = target_url.to_string();
        let verdict = self
            .inner
            .scanner
            .scan(ScanRequest {
                url: scan_url.clone(),
                content_type: content_type.clone(),
                body: bytes.to_vec(),
            })
            .await
            .context("scanner")?;

        match verdict {
            Verdict::Allow => {
                tracing::info!(
                    url = %scan_url,
                    status = parts.status.as_u16(),
                    bytes = body_len,
                    "forward",
                );
                let mut builder = Response::builder().status(parts.status);
                for (k, v) in parts.headers.iter() {
                    if !is_hop_by_hop(k) {
                        builder = builder.header(k, v);
                    }
                }
                // Body length changed if Transfer-Encoding was stripped; set a fresh CL.
                Ok(builder
                    .header(CONTENT_LENGTH, body_len)
                    .body(Full::new(bytes))
                    .context("build response")?)
            }
            Verdict::Block(reason) => {
                tracing::warn!(
                    url = %scan_url,
                    bytes = body_len,
                    verdict = reason.label(),
                    "block",
                );
                Ok(blocked_response(&scan_url, &reason))
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
fn resolve_target(req: &Request<Incoming>, mitm_authority: Option<&str>) -> Result<(url::Url, String)> {
    if let Some(authority) = mitm_authority {
        let path = req
            .uri()
            .path_and_query()
            .map_or_else(|| "/".to_owned(), ToString::to_string);
        let url = url::Url::parse(&format!("https://{authority}{path}"))
            .context("build mitm url")?;
        // RFC 7230 §5.4: the Host header should match the request target.
        let host_header = url.host_str().map_or_else(
            || authority.to_owned(),
            |h| match url.port() {
                Some(p) => format!("{h}:{p}"),
                None => h.to_owned(),
            },
        );
        return Ok((url, host_header));
    }
    let uri = req.uri();
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| anyhow!("missing scheme in absolute URI"))?;
    if scheme != "http" {
        return Err(anyhow!(
            "plaintext proxy only accepts http://; got {scheme}",
        ));
    }
    let url = url::Url::parse(&uri.to_string()).context("parse absolute uri")?;
    let host_header = url
        .host_str()
        .map(|h| match url.port() {
            Some(p) => format!("{h}:{p}"),
            None => h.to_owned(),
        })
        .ok_or_else(|| anyhow!("absolute URI missing host"))?;
    Ok((url, host_header))
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

async fn collect_body_capped(body: Incoming, cap: u64) -> Result<Bytes> {
    use http_body_util::BodyExt;
    use hyper::body::Body;
    let mut body = body;
    let mut buf = Vec::with_capacity(
        usize::try_from(body.size_hint().lower().min(cap)).unwrap_or(0),
    );
    while let Some(frame) = body.frame().await {
        let frame = frame.context("read upstream frame")?;
        if let Ok(data) = frame.into_data() {
            if (buf.len() as u64).saturating_add(data.len() as u64) > cap {
                return Err(anyhow!(
                    "response body exceeds cap {cap} B; aborting forward",
                ));
            }
            buf.extend_from_slice(&data);
        }
    }
    Ok(Bytes::from(buf))
}

fn strip_hop_by_hop(headers: &mut hyper::HeaderMap) {
    let to_remove: Vec<HeaderName> = headers
        .keys()
        .filter(|k| HOP_BY_HOP.iter().any(|h| k.as_str().eq_ignore_ascii_case(h)))
        .cloned()
        .collect();
    for k in to_remove {
        headers.remove(k);
    }
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP
        .iter()
        .any(|h| name.as_str().eq_ignore_ascii_case(h))
}

fn error_response(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    // Header values are static ASCII; the only way this could fail is an
    // invalid status (impossible — typed input). On the off chance the builder
    // returns Err we fall back to a bodyless response with the requested code.
    let body = Full::new(Bytes::from(format!("{msg}\n")));
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body)
        .unwrap_or_else(|_| {
            let mut fallback = Response::new(Full::new(Bytes::new()));
            *fallback.status_mut() = status;
            fallback
        })
}

fn blocked_response(url: &str, reason: &BlockReason) -> Response<Full<Bytes>> {
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
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| error_response(StatusCode::FORBIDDEN, "blocked"))
}

#[allow(dead_code)] // referenced by future logging hooks
fn header_is_sensitive(name: &HeaderName) -> bool {
    SENSITIVE
        .iter()
        .any(|s| name.as_str().eq_ignore_ascii_case(s))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use hyper::header::HeaderMap;

    #[test]
    fn rejects_non_loopback_bind() {
        let scanner = Arc::new(crate::scanner::AllowAll) as Arc<dyn Scanner>;
        let cfg = Config {
            bind: ([0, 0, 0, 0], 0).into(),
            ..Config::default()
        };
        assert!(Proxy::new(scanner, cfg).is_err());
    }

    #[test]
    fn strip_hop_by_hop_removes_listed_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", "close".parse().unwrap());
        headers.insert("keep-alive", "timeout=5".parse().unwrap());
        headers.insert("content-type", "text/plain".parse().unwrap());
        strip_hop_by_hop(&mut headers);
        assert!(!headers.contains_key("connection"));
        assert!(!headers.contains_key("keep-alive"));
        assert!(headers.contains_key("content-type"));
    }

    #[test]
    fn hop_by_hop_check_is_case_insensitive() {
        assert!(is_hop_by_hop(&HeaderName::from_static("transfer-encoding")));
        assert!(is_hop_by_hop(&HeaderName::from_static("upgrade")));
        assert!(!is_hop_by_hop(&HeaderName::from_static("content-type")));
    }

    #[test]
    fn sensitive_detection() {
        assert!(header_is_sensitive(&HeaderName::from_static(
            "authorization"
        )));
        assert!(header_is_sensitive(&HeaderName::from_static("cookie")));
        assert!(!header_is_sensitive(&HeaderName::from_static(
            "content-type"
        )));
    }
}
