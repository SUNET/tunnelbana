//! Exercise real process signals and TLS handshakes without external services.
#![cfg(unix)]

use std::net::SocketAddr;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::net::TcpStream;
use tokio::process::{Child, ChildStdout, Command};
use tokio::time::{sleep, timeout};
use tokio_rustls::{client::TlsStream, TlsConnector};

/// Bound startup, signal acknowledgement, network I/O and process shutdown.
const DEADLINE: Duration = Duration::from_secs(15);

/// A real server child with logs used to observe asynchronous reload completion.
/// The child is killed on drop if an assertion prevents orderly shutdown.
struct Server {
    child: Child,
    logs: Lines<BufReader<ChildStdout>>,
    address: SocketAddr,
}

impl Server {
    /// Launch the Cargo-built binary with a minimal config and an ephemeral port.
    /// No identity plugins are needed to exercise the built-in health endpoint.
    fn start(dir: &Path, tls: bool) -> Self {
        let config = format!(
            "base_url = \"https://localhost\"\n\
             state_encryption_key = \"integration-test-secret-with-32-bytes\"\n\
             [logging]\nformat = \"json\"\n{}",
            if tls {
                "[tls]\ncert_path = \"cert.pem\"\nkey_path = \"key.pem\"\n"
            } else {
                ""
            },
        );
        let config_path = dir.join("proxy.toml");
        std::fs::write(&config_path, config).unwrap();
        // Ask the OS for a port so parallel test servers do not share a fixed
        // address, then release the socket for the child to bind itself.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let mut child = Command::new(env!("CARGO_BIN_EXE_tunnelbana"))
            .arg(config_path)
            .env("TUNNELBANA_BIND", address.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let logs = BufReader::new(child.stdout.take().unwrap()).lines();
        Self {
            child,
            logs,
            address,
        }
    }

    /// Deliver a Unix signal to the server child rather than the test process.
    fn signal(&self, signal: Signal) {
        kill(
            Pid::from_raw(self.child.id().unwrap().try_into().unwrap()),
            signal,
        )
        .unwrap();
    }

    /// Wait for a server acknowledgement instead of guessing when HUP completed.
    async fn log(&mut self, message: &str) {
        timeout(DEADLINE, async {
            loop {
                let line = self
                    .logs
                    .next_line()
                    .await
                    .unwrap()
                    .expect("server closed stdout");
                if line.contains(message) {
                    break;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("missing server log: {message}"));
    }

    /// Wait until TCP accepts connections, failing early if startup exits.
    /// TLS and HTTP correctness are checked by the requests that follow.
    async fn ready(&mut self) {
        timeout(DEADLINE, async {
            loop {
                assert!(
                    self.child.try_wait().unwrap().is_none(),
                    "server exited before ready"
                );
                if TcpStream::connect(self.address).await.is_ok() {
                    break;
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("server did not listen");
    }

    /// Verify Actix's SIGTERM handling still exits successfully and reap the child.
    async fn stop(mut self) {
        self.signal(Signal::SIGTERM);
        assert!(timeout(DEADLINE, self.child.wait())
            .await
            .unwrap()
            .unwrap()
            .success());
    }
}

/// Install a newly generated localhost pair and return the certificate to trust
/// and compare in subsequent handshakes.
fn pair(dir: &Path) -> CertificateDer<'static> {
    let pair = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(dir.join("cert.pem"), pair.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), pair.key_pair.serialize_pem()).unwrap();
    pair.cert.der().clone()
}

/// Open a fresh, hostname-verified TLS connection trusting only the supplied
/// test certificates, with session resumption disabled to observe renewal.
async fn connect(address: SocketAddr, roots: &[CertificateDer<'static>]) -> TlsStream<TcpStream> {
    let mut trust = rustls::RootCertStore::empty();
    for cert in roots {
        trust.add(cert.clone()).unwrap();
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(trust)
    .with_no_client_auth();
    // Every probe must perform a full handshake, not resume a previous session.
    config.resumption = rustls::client::Resumption::disabled();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    timeout(DEADLINE, async {
        TlsConnector::from(Arc::new(config))
            .connect(
                ServerName::try_from("localhost").unwrap(),
                TcpStream::connect(address).await.unwrap(),
            )
            .await
            .unwrap()
    })
    .await
    .unwrap()
}

/// Check /health on the exact supplied connection and consume one full response
/// so the same connection can be reused after a certificate reload.
async fn health(stream: &mut TlsStream<TcpStream>) {
    timeout(DEADLINE, async {
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        // Read the known small HTTP/1.1 response directly, avoiding a client
        // pool that could replace the connection being tested.
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(stream.read_u8().await.unwrap());
            assert!(headers.len() < 8192);
        }
        let headers = String::from_utf8(headers).unwrap().to_ascii_lowercase();
        assert!(headers.starts_with("http/1.1 200"), "{headers}");
        let length: usize = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .unwrap()
            .parse()
            .unwrap();
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"status": "ok"})
        );
    })
    .await
    .unwrap();
}

/// Renew a running server with real HUP signals, verify the new peer certificate
/// on fresh connections, and keep an established connection usable. Malformed,
/// mismatched and missing keys must retain the last working identity, and a
/// repaired key must allow a later successful reload without changing the PID.
#[tokio::test]
async fn certificate_renewal_survives_failures_and_preserves_connections() {
    let dir = tempfile::tempdir().unwrap();
    let first = pair(dir.path());
    let mut server = Server::start(dir.path(), true);
    server.ready().await;
    let pid = server.child.id();
    let mut existing = connect(server.address, std::slice::from_ref(&first)).await;
    health(&mut existing).await;
    assert_eq!(existing.get_ref().1.peer_certificates().unwrap()[0], first);

    let second = pair(dir.path());
    // HUP must not re-parse the main configuration or rebuild the proxy.
    std::fs::write(dir.path().join("proxy.toml"), "invalid TOML now").unwrap();
    server.signal(Signal::SIGHUP);
    server.log("TLS certificate reloaded").await;
    health(&mut existing).await;
    assert_eq!(existing.get_ref().1.peer_certificates().unwrap()[0], first);
    let mut fresh = connect(server.address, std::slice::from_ref(&second)).await;
    health(&mut fresh).await;
    assert_eq!(fresh.get_ref().1.peer_certificates().unwrap()[0], second);
    drop(fresh);

    // Break only the on-disk key: each failed attempt must leave the in-memory
    // certificate and signing key from the successful renewal usable together.
    let saved_key = std::fs::read(dir.path().join("key.pem")).unwrap();
    let bad_key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    for replacement in [
        b"invalid PEM".to_vec(),
        bad_key.key_pair.serialize_pem().into_bytes(),
    ] {
        std::fs::write(dir.path().join("key.pem"), replacement).unwrap();
        server.signal(Signal::SIGHUP);
        server.log("TLS certificate reload failed").await;
        let mut fresh = connect(server.address, std::slice::from_ref(&second)).await;
        health(&mut fresh).await;
        assert_eq!(fresh.get_ref().1.peer_certificates().unwrap()[0], second);
    }
    std::fs::remove_file(dir.path().join("key.pem")).unwrap();
    server.signal(Signal::SIGHUP);
    server.log("TLS certificate reload failed").await;
    let mut fresh = connect(server.address, std::slice::from_ref(&second)).await;
    health(&mut fresh).await;
    drop(fresh);
    // A failed reload must not terminate the HUP loop or prevent a later retry.
    std::fs::write(dir.path().join("key.pem"), saved_key).unwrap();
    server.signal(Signal::SIGHUP);
    server.log("TLS certificate reloaded").await;
    assert_eq!(server.child.id(), pid);
    assert!(server.child.try_wait().unwrap().is_none());
    drop(existing);
    server.stop().await;
}

/// Serve plain HTTP across repeated HUPs when TLS is absent, but exit before
/// listening when an explicit TLS configuration points to missing identity files.
#[tokio::test]
async fn plain_http_hup_and_invalid_tls_startup() {
    let dir = tempfile::tempdir().unwrap();
    let mut server = Server::start(dir.path(), false);
    server.ready().await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(DEADLINE)
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    let url = format!("http://{}/health", server.address);
    for _ in 0..2 {
        let response = client.get(&url).send().await.unwrap();
        assert!(response.status().is_success());
        assert_eq!(
            response.json::<serde_json::Value>().await.unwrap(),
            serde_json::json!({"status": "ok"})
        );
        server.signal(Signal::SIGHUP);
        server.log("SIGHUP ignored: TLS is not configured").await;
    }
    server.stop().await;

    let mut server = Server::start(dir.path(), true);
    let status = timeout(DEADLINE, server.child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(!status.success());
    assert!(TcpStream::connect(server.address).await.is_err());
}
