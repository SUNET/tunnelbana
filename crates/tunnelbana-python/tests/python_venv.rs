//! Virtual-environment adoption tests. These live in their own integration
//! test binary because CPython is process-global: the interpreter here is
//! initialized *with* a venv, which must not leak into the other test binary.

use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::plugin::{BuildContext, MicroService, NullHttpClient};
use tunnelbana_python::PythonRuntime;

const PROBE_CLASS: &str = r#"
class Probe:
    def __init__(self, name, base_url, config):
        pass

    def process_request(self, context, data):
        return data
"#;

/// The venv must be created by the same CPython version this binary links
/// against, or its `pyvenv.cfg` would point at a mismatched standard library.
/// `Py_GetVersion` is callable before initialization, so derive the versioned
/// executable name from the linked libpython itself.
fn base_interpreter() -> String {
    let version = unsafe { std::ffi::CStr::from_ptr(pyo3::ffi::Py_GetVersion()) };
    let version = version.to_string_lossy();
    let major_minor = version
        .split_whitespace()
        .next()
        .and_then(|v| v.rsplit_once('.'))
        .map(|(major_minor, _)| major_minor.to_string())
        .expect("libpython version");
    let versioned = format!("python{major_minor}");
    let found = Command::new(&versioned)
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success());
    if found {
        versioned
    } else {
        std::env::var("PYO3_PYTHON").unwrap_or_else(|_| "python3".into())
    }
}

fn build(
    runtime: &Arc<PythonRuntime>,
    name: &str,
    module: &str,
) -> tunnelbana_core::Result<Box<dyn MicroService>> {
    let bx = BuildContext {
        name: name.into(),
        base_url: "https://proxy.example".into(),
        config: json!({"module": module, "class": "Probe"}),
        attribute_mapper: Arc::new(AttributeMapper::default()),
        http_client: Arc::new(NullHttpClient),
        secret: "not-exposed-to-python".into(),
        previous_secrets: vec![],
    };
    runtime.build_microservice(&bx, &[])
}

fn site_packages(venv: &Path) -> PathBuf {
    std::fs::read_dir(venv.join("lib"))
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().join("site-packages"))
        .find(|path| path.is_dir())
        .expect("venv site-packages")
}

#[test]
fn venv_site_packages_and_pth_files_are_honored() {
    let tmp = Path::new(env!("CARGO_TARGET_TMPDIR")).join("python-venv-test");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    // `--without-pip` skips ensurepip; dependency installation is out of
    // scope here (deployments use `uv venv` + `uv pip install`).
    let venv = tmp.join("venv");
    let status = Command::new(base_interpreter())
        .args(["-m", "venv", "--without-pip"])
        .arg(&venv)
        .status()
        .unwrap();
    assert!(status.success(), "venv creation failed");

    // A module only reachable through the venv's site-packages...
    let site_packages = site_packages(&venv);
    std::fs::write(site_packages.join("venv_probe.py"), PROBE_CLASS).unwrap();

    // ...and one only reachable through a .pth path configuration file, which
    // the `site` module processes solely for real site directories.
    let pth_target = tmp.join("pth-target");
    std::fs::create_dir_all(&pth_target).unwrap();
    std::fs::write(pth_target.join("pth_probe.py"), PROBE_CLASS).unwrap();
    std::fs::write(
        site_packages.join("tunnelbana-test.pth"),
        pth_target.to_str().unwrap(),
    )
    .unwrap();

    // The operator module directory stays separate from the venv.
    let modules = tmp.join("modules");
    std::fs::create_dir_all(&modules).unwrap();
    std::fs::write(modules.join("operator_probe.py"), PROBE_CLASS).unwrap();

    let runtime =
        PythonRuntime::initialize(&modules, Some(&venv), 4, Duration::from_secs(2)).unwrap();
    assert!(build(&runtime, "operator", "operator_probe").is_ok());
    assert!(build(&runtime, "venv", "venv_probe").is_ok());
    assert!(build(&runtime, "pth", "pth_probe").is_ok());

    // A second initialization must agree on the virtual environment.
    let error = PythonRuntime::initialize(&modules, None::<&Path>, 4, Duration::from_secs(2))
        .err()
        .expect("a different venv configuration must be rejected");
    assert!(error.to_string().contains("different virtual environment"));
}

#[test]
fn invalid_venv_directories_are_rejected_before_interpreter_start() {
    let tmp = Path::new(env!("CARGO_TARGET_TMPDIR")).join("python-venv-invalid");
    let _ = std::fs::remove_dir_all(&tmp);
    let modules = tmp.join("modules");
    std::fs::create_dir_all(&modules).unwrap();
    // Not a directory at all.
    assert!(PythonRuntime::initialize(
        &modules,
        Some(tmp.join("missing")),
        4,
        Duration::from_secs(2)
    )
    .is_err());
    // A directory without pyvenv.cfg.
    let bare = tmp.join("bare");
    std::fs::create_dir_all(&bare).unwrap();
    assert!(PythonRuntime::initialize(&modules, Some(&bare), 4, Duration::from_secs(2)).is_err());
}
