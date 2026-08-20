//! `custom_logging` — per-flow JSON audit records (SATOSA:
//! `CustomLoggingService`).

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use async_trait::async_trait;
use serde::Deserialize;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{BuildContext, MicroService};

#[derive(Debug, Deserialize)]
struct CustomLoggingConfig {
    /// File receiving one JSON object per completed flow.
    log_target: String,
    /// Internal attribute names whose values are included in the record.
    #[serde(default)]
    attrs: Vec<String>,
    /// SATOSA-compatible open behavior: follow symlinks and accept
    /// non-regular targets (e.g. a `log_target` symlinked to `/dev/stdout`
    /// in a container, or a FIFO feeding syslog). Default false: the target
    /// must be a regular file and symlinks are refused (O_NOFOLLOW).
    #[serde(default)]
    allow_insecure_log_target: bool,
}

/// Appends a JSON line per authentication response: timestamp, requester
/// (SP/RP), issuer (IdP/OP), frontend/backend names and the configured subset
/// of attributes. Logging failures are reported but never fail the flow.
pub struct CustomLogging {
    name: String,
    log_target: PathBuf,
    attrs: Vec<String>,
    allow_insecure_log_target: bool,
}

impl CustomLogging {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let cfg: CustomLoggingConfig = bx.parse_config()?;
        let log_target = PathBuf::from(&cfg.log_target);
        // Surface an unwritable target at startup, not mid-flow.
        open_log(&log_target, cfg.allow_insecure_log_target).map_err(|e| {
            Error::Config(format!(
                "custom_logging {}: cannot open log_target {}: {e}",
                bx.name, cfg.log_target
            ))
        })?;
        Ok(Box::new(CustomLogging {
            name: bx.name.clone(),
            log_target,
            attrs: cfg.attrs,
            allow_insecure_log_target: cfg.allow_insecure_log_target,
        }))
    }
}

#[async_trait]
impl MicroService for CustomLogging {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_response(
        &self,
        ctx: &mut Context,
        data: InternalData,
    ) -> Result<InternalData> {
        let timestamp = data
            .auth_info
            .timestamp
            .clone()
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        let attrs: serde_json::Map<String, serde_json::Value> = self
            .attrs
            .iter()
            .filter_map(|a| {
                data.attributes
                    .get(a)
                    .map(|v| (a.clone(), serde_json::json!(v)))
            })
            .collect();
        let record = serde_json::json!({
            "timestamp": timestamp,
            "sp": data.requester,
            "idp": data.auth_info.issuer,
            "frontend": ctx.target_frontend,
            "backend": ctx.target_backend,
            "attr": attrs,
        });

        let written = open_log(&self.log_target, self.allow_insecure_log_target)
            .and_then(|mut file| writeln!(file, "{record}"));
        if let Err(e) = written {
            tracing::error!(
                microservice = %self.name,
                target = %self.log_target.display(),
                error = %e,
                "failed to write audit record"
            );
        }
        Ok(data)
    }
}

/// Open an audit log for appending. By default this is hardened: on Unix,
/// `O_NOFOLLOW` refuses a symlinked target, `mode` applies owner-only
/// permissions when the file is created, and a pre-existing target must be
/// a regular file (it keeps its own permissions). With `allow_insecure`
/// (SATOSA-compatible behavior for container logging setups) symlinks are
/// followed and non-regular targets such as FIFOs are accepted.
fn open_log(path: &std::path::Path, allow_insecure: bool) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    if !allow_insecure {
        // O_NONBLOCK matters for correctness, not just latency: opening a FIFO
        // write-only without it blocks until a reader appears, so the
        // regular-file check below would never run and a planted FIFO would
        // hang the caller (boot, or a tokio worker per response) instead of
        // being rejected. O_NOFOLLOW does not cover this: a FIFO is not a
        // symlink.
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    if !allow_insecure {
        if !file.metadata()?.file_type().is_file() {
            return Err(std::io::Error::other(format!(
                "{} is not a regular file",
                path.display()
            )));
        }
        // The target is a regular file, for which O_NONBLOCK has no effect on
        // reads/writes; clear it anyway so the descriptor we hand out has the
        // same semantics as an ordinary append handle.
        clear_nonblock(&file)?;
    }
    Ok(file)
}

/// Drop `O_NONBLOCK` from an already-open descriptor.
#[cfg(unix)]
fn clear_nonblock(file: &File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    // SAFETY: `fd` is owned by `file` and stays open for the duration of both
    // calls; F_GETFL/F_SETFL take no pointer arguments.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{bx, ctx, response_from};
    use super::*;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn temp_log(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tunnelbana-custom-logging-{tag}-{}.jsonl",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn writes_one_json_record_per_response() {
        let path = temp_log("ok");
        let _ = std::fs::remove_file(&path);
        let svc = CustomLogging::build(&bx(
            "audit",
            serde_json::json!({
                "log_target": path.to_str().unwrap(),
                "attrs": ["mail", "absent"]
            }),
        ))
        .unwrap();

        let mut data = response_from("https://sp.example");
        data.auth_info.issuer = Some("https://idp.example".into());
        data.auth_info.timestamp = Some("2026-06-10T12:00:00Z".into());
        data.set_attr("mail", "anna@example.org");
        data.set_attr("secret", "do-not-log");
        let mut c = ctx();
        c.target_frontend = Some("OidcOP".into());
        c.target_backend = Some("Saml2".into());
        svc.process_response(&mut c, data).await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let record: serde_json::Value =
            serde_json::from_str(contents.lines().last().unwrap()).unwrap();
        assert_eq!(record["sp"], "https://sp.example");
        assert_eq!(record["idp"], "https://idp.example");
        assert_eq!(record["timestamp"], "2026-06-10T12:00:00Z");
        assert_eq!(record["frontend"], "OidcOP");
        assert_eq!(record["attr"]["mail"][0], "anna@example.org");
        // Only configured attributes are recorded.
        assert!(record["attr"].get("secret").is_none());
        assert!(record["attr"].get("absent").is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_unwritable_target_at_build_time() {
        assert!(CustomLogging::build(&bx(
            "audit",
            serde_json::json!({ "log_target": "/nonexistent-dir/audit.jsonl" })
        ))
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn audit_log_is_owner_only() {
        let path = temp_log("permissions");
        let _ = std::fs::remove_file(&path);
        CustomLogging::build(&bx(
            "audit",
            serde_json::json!({ "log_target": path.to_str().unwrap() }),
        ))
        .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_log_target() {
        let path = temp_log("symlink");
        let target = temp_log("symlink-target");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&target);
        std::fs::write(&target, "").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();

        assert!(CustomLogging::build(&bx(
            "audit",
            serde_json::json!({ "log_target": path.to_str().unwrap() })
        ))
        .is_err());
        // The symlink target was not written through.
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&target);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_fifo_log_target_without_blocking() {
        let path = temp_log("fifo");
        let _ = std::fs::remove_file(&path);
        let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        // SAFETY: `c_path` is a valid NUL-terminated string that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        // Run in a worker thread: without O_NONBLOCK the open blocks forever
        // waiting for a reader, so a regression must fail the test rather than
        // hang the whole suite.
        let (tx, rx) = std::sync::mpsc::channel();
        let probe = path.clone();
        std::thread::spawn(move || {
            let result = CustomLogging::build(&bx(
                "audit",
                serde_json::json!({ "log_target": probe.to_str().unwrap() }),
            ));
            let _ = tx.send(result.is_err());
        });

        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(is_err) => assert!(is_err, "a FIFO log_target must be rejected"),
            Err(_) => panic!("opening a FIFO log_target blocked; O_NONBLOCK is missing"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn allow_insecure_log_target_accepts_fifo() {
        let path = temp_log("fifo-insecure");
        let _ = std::fs::remove_file(&path);
        let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        // SAFETY: `c_path` is a valid NUL-terminated string that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        // Hold the read end open so the SATOSA-compatible blocking open can
        // complete, mirroring a container FIFO with a log shipper attached.
        // O_NONBLOCK on this side too: a read-only FIFO open blocks until a
        // writer appears, which is the very open we are about to make.
        let reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
            .unwrap();
        let built = CustomLogging::build(&bx(
            "audit",
            serde_json::json!({
                "log_target": path.to_str().unwrap(),
                "allow_insecure_log_target": true
            }),
        ));
        assert!(
            built.is_ok(),
            "opt-in insecure mode must still accept a FIFO"
        );
        drop(reader);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn pre_existing_log_keeps_its_permissions() {
        let path = temp_log("preexisting");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        CustomLogging::build(&bx(
            "audit",
            serde_json::json!({ "log_target": path.to_str().unwrap() }),
        ))
        .unwrap();
        // Permissions are set only at creation, not repaired on every open.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn allow_insecure_log_target_accepts_symlink() {
        let path = temp_log("symlink-allowed");
        let target = temp_log("symlink-allowed-target");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&target);
        std::fs::write(&target, "").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let svc = CustomLogging::build(&bx(
            "audit",
            serde_json::json!({
                "log_target": path.to_str().unwrap(),
                "allow_insecure_log_target": true
            }),
        ))
        .unwrap();
        let data = response_from("https://sp.example");
        svc.process_response(&mut ctx(), data).await.unwrap();

        // The record was written through the symlink (SATOSA behavior).
        let contents = std::fs::read_to_string(&target).unwrap();
        assert!(contents.contains("\"sp\":\"https://sp.example\""));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&target);
    }
}
