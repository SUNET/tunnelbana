//! Inbound TLS identity loading and atomic certificate renewal.

use std::io;
use std::path::Path;
#[cfg(any(unix, test))]
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use rustls::pki_types::PrivateKeyDer;
use rustls::server::{ClientHello, ParsedCertificate, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use tunnelbana_core::config::TlsConfig;

/// All worker configs share this resolver. A handshake clones one complete
/// identity under a short read lock; no filesystem work happens in `resolve`.
struct CertificateResolver(RwLock<Arc<CertifiedKey>>);

impl std::fmt::Debug for CertificateResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Rustls requires Debug, but diagnostics need not expose the identity.
        f.debug_struct("CertificateResolver")
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

impl CertificateResolver {
    /// Take an owned snapshot that remains valid after a later certificate swap.
    fn current(&self) -> Arc<CertifiedKey> {
        // Even a poisoned lock contains a complete Arc: replacement never
        // mutates certificate or key fields individually.
        Arc::clone(&self.0.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// Publish an already validated identity as one indivisible replacement.
    #[cfg(any(unix, test))]
    fn replace(&self, candidate: CertifiedKey) {
        let candidate = Arc::new(candidate);
        let old = {
            let mut guard = self.0.write().unwrap_or_else(|e| e.into_inner());
            std::mem::replace(&mut *guard, candidate)
        };
        // Release the old identity outside the lock.
        drop(old);
    }
}

/// Own the startup-selected file paths and the resolver shared by all workers.
/// Paths are retained only where renewal is supported or exercised by tests.
pub(crate) struct ReloadableTls {
    #[cfg(any(unix, test))]
    cert_path: PathBuf,
    #[cfg(any(unix, test))]
    key_path: PathBuf,
    resolver: Arc<CertificateResolver>,
}

impl ReloadableTls {
    /// Resolve file paths and load the first identity, failing before serving
    /// if either file is unreadable, malformed, or inconsistent with the other.
    pub(crate) fn new(config: &TlsConfig, config_path: &str) -> io::Result<Self> {
        let cwd = std::env::current_dir()?;
        // Make paths absolute without canonicalizing: renewal commonly replaces
        // a symlink, and every reload must follow its current target.
        let cert_path = cwd.join(super::resolve_sibling(config_path, &config.cert_path));
        let key_path = cwd.join(super::resolve_sibling(config_path, &config.key_path));
        let identity = load_identity(&cert_path, &key_path)?;
        Ok(Self {
            #[cfg(any(unix, test))]
            cert_path,
            #[cfg(any(unix, test))]
            key_path,
            resolver: Arc::new(CertificateResolver(RwLock::new(Arc::new(identity)))),
        })
    }

    /// Build server-only TLS authentication using the shared identity resolver.
    /// Actix supplies HTTP/1.1 and HTTP/2 ALPN when attaching this configuration.
    pub(crate) fn server_config(&self) -> io::Result<ServerConfig> {
        // Match the provider already used by our outbound reqwest client,
        // without installing or relying on a process-global default provider.
        Ok(
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(io::Error::other)?
                .with_no_client_auth()
                .with_cert_resolver(self.resolver.clone()),
        )
    }

    /// Reload both files without changing the live identity unless every check
    /// succeeds. Disk access and key parsing run outside the async executor.
    #[cfg(any(unix, test))]
    async fn reload(&self) -> io::Result<()> {
        let cert_path = self.cert_path.clone();
        let key_path = self.key_path.clone();
        let candidate = tokio::task::spawn_blocking(move || load_identity(&cert_path, &key_path))
            .await
            .map_err(|_| io::Error::other("TLS certificate loading task failed"))??;
        // Commit in the calling task, so cancelling a reload during shutdown
        // cannot leave a detached blocking task publishing a new identity.
        self.resolver.replace(candidate);
        Ok(())
    }
}

/// Attach a file path to a caller-supplied diagnostic without echoing PEM input.
fn invalid(path: &Path, message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{}: {message}", path.display()),
    )
}

/// Read the current file target, retaining the OS error kind and path context.
fn read(path: &Path) -> io::Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("reading TLS file {}: {e}", path.display()),
        )
    })
}

/// Parse a leaf-first chain and one private key into a validated candidate.
/// This checks certificate syntax and key matching; clients validate the chain's
/// trust, validity dates and hostname during their handshake.
fn load_identity(cert_path: &Path, key_path: &Path) -> io::Result<CertifiedKey> {
    let cert_pem = read(cert_path)?;
    let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        // PEM parser errors can contain input lines. Never log those lines.
        .map_err(|_| invalid(cert_path, "invalid certificate PEM"))?;
    if certs.is_empty() {
        return Err(invalid(cert_path, "no certificates found"));
    }
    // Validate every chain entry, not just the leaf checked by keys_match.
    for cert in &certs {
        ParsedCertificate::try_from(cert)
            .map_err(|_| invalid(cert_path, "invalid X.509 certificate"))?;
    }

    let key_pem = read(key_path)?;
    let mut key: Option<PrivateKeyDer<'static>> = None;
    // Scan the entire PEM instead of selecting the first key, so an ambiguous
    // bundle or malformed trailing section cannot silently pass loading.
    for item in rustls_pemfile::read_all(&mut key_pem.as_slice()) {
        let candidate = match item.map_err(|_| invalid(key_path, "invalid private-key PEM"))? {
            rustls_pemfile::Item::Pkcs1Key(k) => k.into(),
            rustls_pemfile::Item::Pkcs8Key(k) => k.into(),
            rustls_pemfile::Item::Sec1Key(k) => k.into(),
            _ => continue,
        };
        if key.replace(candidate).is_some() {
            return Err(invalid(key_path, "expected exactly one private key"));
        }
    }
    let key = key.ok_or_else(|| invalid(key_path, "no supported unencrypted private key found"))?;
    let identity = CertifiedKey::from_der(certs, key, &rustls::crypto::ring::default_provider())
        .map_err(|_| invalid(key_path, "invalid private key or certificate/key mismatch"))?;
    // from_der can accept a provider that cannot determine key consistency;
    // require a positive match before publishing a custom resolver identity.
    identity
        .keys_match()
        .map_err(|_| invalid(key_path, "cannot verify certificate/key match"))?;
    Ok(identity)
}

/// Process renewals serially. Unix may coalesce repeated HUPs; each delivered
/// signal reads both files afresh, and a rejected candidate never changes state.
#[cfg(unix)]
pub(crate) async fn reload_on_hup(
    mut hup: tokio::signal::unix::Signal,
    tls: Option<ReloadableTls>,
) {
    while hup.recv().await.is_some() {
        match &tls {
            Some(tls) => match tls.reload().await {
                Ok(()) => tracing::info!("TLS certificate reloaded"),
                Err(error) => {
                    tracing::error!(%error, "TLS certificate reload failed; retaining previous certificate")
                }
            },
            None => tracing::info!("SIGHUP ignored: TLS is not configured"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a fresh localhost identity and return its DER certificate for
    /// comparisons independent of the loader's representation.
    fn write_pair(dir: &Path) -> Vec<u8> {
        let pair = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        std::fs::write(dir.join("cert.pem"), pair.cert.pem()).unwrap();
        std::fs::write(dir.join("key.pem"), pair.key_pair.serialize_pem()).unwrap();
        pair.cert.der().to_vec()
    }

    /// Use config-relative paths matching the filenames created by write_pair.
    fn config() -> TlsConfig {
        TlsConfig {
            cert_path: "cert.pem".into(),
            key_path: "key.pem".into(),
        }
    }

    /// Publish a valid replacement while preserving existing Arc snapshots,
    /// then retain that replacement after mismatched-key and missing-file errors.
    #[tokio::test]
    async fn reload_commits_complete_identity_and_preserves_old_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let first = write_pair(dir.path());
        let config_path = dir.path().join("proxy.toml");
        let tls = ReloadableTls::new(&config(), config_path.to_str().unwrap()).unwrap();
        // Model a handshake holding the old identity while a reload commits.
        let in_flight = tls.resolver.current();
        assert_eq!(in_flight.cert[0].as_ref(), first);
        let second = write_pair(dir.path());
        tls.reload().await.unwrap();
        assert_eq!(tls.resolver.current().cert[0].as_ref(), second);
        assert_eq!(in_flight.cert[0].as_ref(), first);

        let unrelated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        std::fs::write(
            dir.path().join("key.pem"),
            unrelated.key_pair.serialize_pem(),
        )
        .unwrap();
        assert!(tls.reload().await.is_err());
        assert_eq!(tls.resolver.current().cert[0].as_ref(), second);
        std::fs::remove_file(dir.path().join("cert.pem")).unwrap();
        assert!(tls.reload().await.is_err());
        assert_eq!(tls.resolver.current().cert[0].as_ref(), second);
    }

    /// Reject absent, malformed, invalid-DER and multiple-key inputs, ensuring
    /// that parser diagnostics never echo a marker embedded in private-key PEM.
    #[test]
    fn loader_rejects_invalid_material_without_echoing_input() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        for bad in [
            "",
            "not PEM",
            "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n",
        ] {
            write_pair(dir.path());
            std::fs::write(&cert, bad).unwrap();
            assert!(load_identity(&cert, &key).is_err());
        }
        for bad in [
            "",
            "not PEM",
            "-----BEGIN PRIVATE KEY-----\n!!!\n-----END PRIVATE KEY-----\n",
            "-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n",
            "-----BEGIN PRIVATE KEY-----secret-do-not-log",
        ] {
            write_pair(dir.path());
            std::fs::write(&key, bad).unwrap();
            let err = load_identity(&cert, &key).unwrap_err();
            assert!(!err.to_string().contains("secret-do-not-log"));
        }
        write_pair(dir.path());
        let pem = std::fs::read_to_string(&key).unwrap();
        std::fs::write(&key, pem.repeat(2)).unwrap();
        assert!(load_identity(&cert, &key).is_err());
        std::fs::remove_file(&key).unwrap();
        assert!(load_identity(&cert, &key).is_err());
    }

    /// Preserve certificate order and all chain entries while resolving absolute
    /// file paths independently of the main configuration's directory.
    #[test]
    fn loader_preserves_the_full_chain_and_accepts_absolute_paths() {
        let dir = tempfile::tempdir().unwrap();
        let leaf = write_pair(dir.path());
        // The extra certificate tests bundle preservation, not trust-chain
        // validation; it deliberately need not sign the leaf certificate.
        let other = rcgen::generate_simple_self_signed(vec!["issuer".into()]).unwrap();
        let cert = dir.path().join("cert.pem");
        let chain = std::fs::read_to_string(&cert).unwrap() + &other.cert.pem();
        std::fs::write(&cert, chain).unwrap();
        let cfg = TlsConfig {
            cert_path: cert.to_str().unwrap().into(),
            key_path: dir.path().join("key.pem").to_str().unwrap().into(),
        };
        let tls = ReloadableTls::new(&cfg, "/unrelated/proxy.toml").unwrap();
        let identity = tls.resolver.current();
        assert_eq!(identity.cert.len(), 2);
        assert_eq!(identity.cert[0].as_ref(), leaf);
        assert_eq!(identity.cert[1], *other.cert.der());
    }

    /// Follow a newly published directory symlink on reload instead of retaining
    /// the target that existed when the server first loaded its identity.
    #[cfg(unix)]
    #[tokio::test]
    async fn reload_follows_replaced_symlinks() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        write_pair(&a);
        let second = write_pair(&b);
        symlink("a", dir.path().join("live")).unwrap();
        let cfg = TlsConfig {
            cert_path: "live/cert.pem".into(),
            key_path: "live/key.pem".into(),
        };
        let tls =
            ReloadableTls::new(&cfg, dir.path().join("proxy.toml").to_str().unwrap()).unwrap();
        symlink("b", dir.path().join("next")).unwrap();
        // Publish both files together using the layout common to renewal tools.
        std::fs::rename(dir.path().join("next"), dir.path().join("live")).unwrap();
        tls.reload().await.unwrap();
        assert_eq!(tls.resolver.current().cert[0].as_ref(), second);
    }
}
