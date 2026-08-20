//! Embedded, synchronous CPython micro-services.
//!
//! This crate is deliberately the sole PyO3 boundary in the workspace. Python
//! modules are trusted operator code, but their data exchange with the proxy is
//! still narrow, strictly validated, and applied atomically.

use pyo3::exceptions::PyAttributeError;
use pyo3::prelude::*;
use pyo3::types::{PyAnyMethods, PyDict, PyDictMethods, PyList, PyListMethods};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::Semaphore;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::internal::{AuthenticationInformation, InternalData, SubjectType};
use tunnelbana_core::plugin::{BuildContext, MicroService};
use tunnelbana_core::Context;

const TRACEBACK_LIMIT: usize = 4096;
const CONTEXT_KEYS: &[&str] = &[
    "path",
    "method",
    "query",
    "form",
    "requester",
    "target_backend",
    "target_frontend",
    "decorations",
];
const DATA_KEYS: &[&str] = &[
    "auth_info",
    "requester",
    "requester_name",
    "subject_id",
    "subject_type",
    "attributes",
    "force_authn",
    "is_passive",
];
const AUTH_INFO_KEYS: &[&str] = &["auth_class_ref", "timestamp", "issuer"];
/// Decoration keys that are first-writer-wins across the pipeline. Python may
/// publish them when absent but must not change or remove a value another
/// component already set (e.g. the discovery service's IdP choice).
const FIRST_WRITER_DECORATION_KEYS: &[&str] = &[
    tunnelbana_core::context::KEY_TARGET_ENTITYID,
    tunnelbana_core::context::KEY_TARGET_AUTHN_CONTEXT_CLASS_REF,
    tunnelbana_core::context::KEY_TARGET_ACCR_COMPARISON,
];
static MODULE_PATH: OnceLock<PathBuf> = OnceLock::new();
static VENV_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();
/// Serializes interpreter setup and the module-path claim. Without it, two
/// concurrent `initialize` calls with different paths could both pass the
/// `MODULE_PATH` check and both end up on `sys.path`.
static INIT_LOCK: Mutex<()> = Mutex::new(());

/// Process-wide controls for all embedded Python calls.
pub struct PythonRuntime {
    semaphore: Arc<Semaphore>,
    call_timeout: Duration,
}

impl PythonRuntime {
    /// Explicitly initialize CPython and add the configured operator module
    /// directory to `sys.path`. When `venv` is given, the interpreter adopts
    /// that virtual environment exactly like a venv-launched Python.
    pub fn initialize(
        module_path: impl AsRef<Path>,
        venv: Option<impl AsRef<Path>>,
        max_concurrent_calls: usize,
        call_timeout: Duration,
    ) -> Result<Arc<Self>> {
        let module_path = module_path.as_ref();
        if max_concurrent_calls == 0 {
            return Err(Error::Config(
                "python.max_concurrent_calls must be greater than zero".into(),
            ));
        }
        if max_concurrent_calls > Semaphore::MAX_PERMITS {
            return Err(Error::Config(
                "python.max_concurrent_calls exceeds the supported limit".into(),
            ));
        }
        if call_timeout.is_zero() {
            return Err(Error::Config(
                "python.call_timeout_seconds must be greater than zero".into(),
            ));
        }
        if tokio::time::Instant::now()
            .checked_add(call_timeout)
            .is_none()
        {
            return Err(Error::Config(
                "python.call_timeout_seconds exceeds the supported limit".into(),
            ));
        }
        let canonical = module_path.canonicalize().map_err(|_| {
            Error::Config("python.module_path is not an accessible directory".into())
        })?;
        if !canonical.is_dir() {
            return Err(Error::Config(
                "python.module_path is not an accessible directory".into(),
            ));
        }
        // Fail fast on a venv that CPython could not adopt: it must look like
        // a standard virtual environment created by `uv venv`/`python -m venv`
        // for the same CPython version this binary links against.
        let venv = match venv {
            Some(venv) => {
                let canonical = venv.as_ref().canonicalize().map_err(|_| {
                    Error::Config("python.venv is not an accessible directory".into())
                })?;
                if !canonical.join("pyvenv.cfg").is_file() {
                    return Err(Error::Config(
                        "python.venv does not contain a pyvenv.cfg".into(),
                    ));
                }
                if !canonical.join("bin/python").is_file() {
                    return Err(Error::Config(
                        "python.venv does not contain bin/python".into(),
                    ));
                }
                Some(canonical)
            }
            None => None,
        };
        let _guard = INIT_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = MODULE_PATH.get() {
            if existing != &canonical {
                return Err(Error::Config(
                    "CPython was already initialized with a different module path".into(),
                ));
            }
        }
        if let Some(existing) = VENV_PATH.get() {
            if existing != &venv {
                return Err(Error::Config(
                    "CPython was already initialized with a different virtual environment".into(),
                ));
            }
        }

        // Initialization is intentionally explicit: auto-initialize would make
        // interpreter startup an accidental side effect of the first request.
        initialize_isolated_cpython(venv.as_deref())?;

        Python::attach(|py| -> PyResult<()> {
            let sys = py.import("sys")?;
            let path = sys.getattr("path")?.cast_into::<PyList>()?;
            let path_text = canonical.to_string_lossy();
            if !path.contains(path_text.as_ref())? {
                // Add exactly the configured operator directory. We retain
                // CPython's standard-library paths and perform no discovery.
                path.insert(0, path_text.as_ref())?;
            }
            Ok(())
        })
        .map_err(|_| Error::Config("failed to configure embedded CPython imports".into()))?;
        let _ = MODULE_PATH.set(canonical);
        let _ = VENV_PATH.set(venv);

        Ok(Arc::new(Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent_calls)),
            call_timeout,
        }))
    }

    /// Build a configured Python micro-service. Suitable for a captured
    /// `Registry::register_microservice` closure.
    pub fn build_microservice(
        self: &Arc<Self>,
        bx: &BuildContext,
    ) -> Result<Box<dyn MicroService>> {
        PythonMicroService::build(self.clone(), bx)
            .map(|service| Box::new(service) as Box<dyn MicroService>)
    }

    #[doc(hidden)]
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

/// Start CPython with its *isolated* configuration instead of the default
/// environment-driven one. Isolated mode ignores interpreter environment
/// variables (`PYTHONPATH`, `PYTHONHOME`, ...), so import resolution cannot be
/// extended from outside the `[python]` configuration; it also excludes the
/// user site directory, leaves signal handling to the host process, and — with
/// `write_bytecode` disabled — never writes cache files into the operator
/// module directory, which is documented as read-only. The system standard
/// library and site-packages remain importable for operator dependencies.
///
/// When `venv` is given, `PyConfig.executable` is pointed at the venv's
/// interpreter so CPython's own path machinery adopts the environment exactly
/// like a venv-launched Python: `pyvenv.cfg` is honored (including
/// `include-system-site-packages`), `sys.prefix` moves into the venv, and the
/// venv's site-packages is processed by `site` — `.pth` files included. This
/// is file-based configuration; environment variables such as `VIRTUAL_ENV`
/// remain ignored.
fn initialize_isolated_cpython(venv: Option<&Path>) -> Result<()> {
    let failed = || Error::Config("failed to initialize embedded CPython".into());
    let venv_python = match venv {
        Some(venv) => {
            use std::os::unix::ffi::OsStrExt;
            let executable = venv.join("bin/python");
            Some(std::ffi::CString::new(executable.as_os_str().as_bytes()).map_err(|_| failed())?)
        }
        None => None,
    };
    // SAFETY: callers hold `INIT_LOCK`, so interpreter setup is not
    // concurrent. The config struct is initialized by
    // `PyConfig_InitIsolatedConfig` before any field access and cleared on
    // every path.
    unsafe {
        if pyo3::ffi::Py_IsInitialized() == 0 {
            let mut config = std::mem::MaybeUninit::<pyo3::ffi::PyConfig>::uninit();
            pyo3::ffi::PyConfig_InitIsolatedConfig(config.as_mut_ptr());
            let mut config = config.assume_init();
            config.write_bytecode = 0;
            // A conventional single-element sys.argv for operator modules.
            let mut argv = [c"tunnelbana".as_ptr()];
            let mut status = pyo3::ffi::PyConfig_SetBytesArgv(&mut config, 1, argv.as_mut_ptr());
            if let Some(executable) = &venv_python {
                if pyo3::ffi::PyStatus_Exception(status) == 0 {
                    let config_ptr: *mut pyo3::ffi::PyConfig = &mut config;
                    status = pyo3::ffi::PyConfig_SetBytesString(
                        config_ptr,
                        std::ptr::addr_of_mut!((*config_ptr).executable),
                        executable.as_ptr(),
                    );
                }
            }
            if pyo3::ffi::PyStatus_Exception(status) == 0 {
                status = pyo3::ffi::Py_InitializeFromConfig(&config);
            }
            pyo3::ffi::PyConfig_Clear(&mut config);
            if pyo3::ffi::PyStatus_Exception(status) != 0 {
                return Err(failed());
            }
            // Py_InitializeFromConfig leaves this thread attached with the
            // GIL held; release it so any thread can attach.
            pyo3::ffi::PyEval_SaveThread();
        }
    }
    // Let PyO3 record the already-initialized interpreter (no-op re-init).
    std::panic::catch_unwind(Python::initialize).map_err(|_| failed())?;
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PythonMicroServiceConfig {
    module: String,
    class: String,
    #[serde(default = "empty_settings")]
    settings: Value,
}

fn empty_settings() -> Value {
    Value::Object(serde_json::Map::new())
}

struct PythonMicroService {
    inner: Arc<PythonMicroServiceInner>,
}

struct PythonMicroServiceInner {
    name: String,
    module: String,
    class: String,
    instance: Py<PyAny>,
    has_request: bool,
    has_response: bool,
    runtime: Arc<PythonRuntime>,
}

impl PythonMicroService {
    fn build(runtime: Arc<PythonRuntime>, bx: &BuildContext) -> Result<Self> {
        let config: PythonMicroServiceConfig = bx.parse_config()?;
        if config.module.trim().is_empty() || config.class.trim().is_empty() {
            return Err(Error::Config(format!(
                "python microservice {} requires non-empty module and class",
                bx.name
            )));
        }
        if !config.settings.is_object() {
            return Err(Error::Config(format!(
                "python microservice {} settings must be a table",
                bx.name
            )));
        }

        let built = Python::attach(|py| -> PyResult<(Py<PyAny>, bool, bool)> {
            let module = py.import(config.module.as_str())?;
            let class = module.getattr(config.class.as_str())?;
            if !class.is_callable() {
                return Err(pyo3::exceptions::PyTypeError::new_err(
                    "configured class is not callable",
                ));
            }
            let settings = pythonize::pythonize(py, &config.settings)
                .map_err(|_| pyo3::exceptions::PyTypeError::new_err("invalid settings"))?;
            let instance = class.call1((bx.name.as_str(), bx.base_url.as_str(), settings))?;
            let inspect = py.import("inspect")?;
            let has_request = validate_method(py, &inspect, &instance, "process_request")?;
            let has_response = validate_method(py, &inspect, &instance, "process_response")?;
            if !has_request && !has_response {
                return Err(pyo3::exceptions::PyTypeError::new_err(
                    "at least one process method is required",
                ));
            }
            Ok((instance.unbind(), has_request, has_response))
        });

        let (instance, has_request, has_response) = built.map_err(|error| {
            Python::attach(|py| {
                log_python_error(
                    py,
                    &error,
                    &bx.name,
                    &config.module,
                    &config.class,
                    "startup",
                )
            });
            Error::Config(format!(
                "python microservice {} failed startup validation",
                bx.name
            ))
        })?;

        Ok(Self {
            inner: Arc::new(PythonMicroServiceInner {
                name: bx.name.clone(),
                module: config.module,
                class: config.class,
                instance,
                has_request,
                has_response,
                runtime,
            }),
        })
    }

    async fn execute(
        &self,
        phase: &'static str,
        ctx: &mut Context,
        data: InternalData,
    ) -> Result<InternalData> {
        let method_exists = match phase {
            "request" => self.inner.has_request,
            "response" => self.inner.has_response,
            _ => false,
        };
        if !method_exists {
            return Ok(data);
        }

        let original = ContextSnapshot::from_context(ctx);
        let call_context = original.clone();
        let call_data = InternalDataBoundary::from(data);
        let Some(deadline) =
            tokio::time::Instant::now().checked_add(self.inner.runtime.call_timeout)
        else {
            log_boundary_error(&self.inner, phase, "deadline could not be represented");
            return Err(Error::Internal(
                "python execution control unavailable".into(),
            ));
        };
        let permit = tokio::time::timeout_at(
            deadline,
            self.inner.runtime.semaphore.clone().acquire_owned(),
        )
        .await
        .map_err(|_| {
            log_boundary_error(
                &self.inner,
                phase,
                "deadline exceeded before Python call began",
            );
            sanitized_timeout()
        })?
        .map_err(|_| Error::Internal("python execution control unavailable".into()))?;

        let inner = self.inner.clone();
        // Python is synchronous and may block. It must never occupy an async
        // runtime worker, so both GIL acquisition and the call happen here.
        let task = tokio::task::spawn_blocking(move || {
            // Keep the owned permit inside the blocking task. If the async
            // deadline expires, dropping the JoinHandle detaches this unkillable
            // CPython call, but capacity stays consumed until Python exits.
            let _permit = permit;
            run_python_call(&inner, phase, call_context, call_data)
        });

        let output = tokio::time::timeout_at(deadline, task)
            .await
            .map_err(|_| {
                log_boundary_error(
                    &self.inner,
                    phase,
                    "deadline exceeded; detached Python call is still running",
                );
                sanitized_timeout()
            })?
            .map_err(|_| {
                log_boundary_error(&self.inner, phase, "blocking task failed");
                Error::Internal("python microservice execution failed".into())
            })??;

        // Strictly validate the complete output and read-only context before
        // touching the real Context. These assignments are the atomic commit.
        output.context.validate_read_only(&original).map_err(|_| {
            log_boundary_error(&self.inner, phase, "read-only context mutation");
            Error::Internal("python microservice returned invalid output".into())
        })?;
        output
            .context
            .validate_reserved_decorations(&original)
            .map_err(|_| {
                log_boundary_error(&self.inner, phase, "reserved decoration overwritten");
                Error::Internal("python microservice returned invalid output".into())
            })?;
        ctx.target_backend = output.context.target_backend;
        ctx.decorations = output.context.decorations;
        Ok(output.data.into())
    }
}

fn validate_method(
    py: Python<'_>,
    inspect: &Bound<'_, PyAny>,
    instance: &Bound<'_, PyAny>,
    name: &str,
) -> PyResult<bool> {
    let method = match instance.getattr(name) {
        Ok(method) => method,
        Err(error) if error.is_instance_of::<PyAttributeError>(py) => return Ok(false),
        Err(error) => return Err(error),
    };
    if !method.is_callable() {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "configured process method is not callable",
        ));
    }
    if inspect
        .getattr("iscoroutinefunction")?
        .call1((&method,))?
        .is_truthy()?
    {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "coroutine process methods are unsupported",
        ));
    }
    Ok(true)
}

struct CallOutput {
    context: ContextSnapshot,
    data: InternalDataBoundary,
}

fn run_python_call(
    inner: &PythonMicroServiceInner,
    phase: &'static str,
    context: ContextSnapshot,
    data: InternalDataBoundary,
) -> Result<CallOutput> {
    Python::attach(|py| {
        let result = (|| -> PyResult<CallOutput> {
            let py_context = pythonize::pythonize(py, &context)
                .map_err(|_| pyo3::exceptions::PyTypeError::new_err("invalid context"))?;
            let py_data = pythonize::pythonize(py, &data)
                .map_err(|_| pyo3::exceptions::PyTypeError::new_err("invalid data"))?;
            let method_name = if phase == "request" {
                "process_request"
            } else {
                "process_response"
            };
            let returned = inner
                .instance
                .bind(py)
                .getattr(method_name)?
                .call1((&py_context, &py_data))?;
            if py
                .import("inspect")?
                .getattr("isawaitable")?
                .call1((&returned,))?
                .is_truthy()?
            {
                return Err(pyo3::exceptions::PyTypeError::new_err(
                    "awaitable results are unsupported",
                ));
            }
            // Both mappings are deserialized in full with unknown/missing fields
            // rejected. No partially converted values escape this closure.
            require_exact_keys(&py_context, CONTEXT_KEYS)?;
            require_exact_keys(&returned, DATA_KEYS)?;
            let auth_info = returned
                .cast::<PyDict>()?
                .get_item("auth_info")?
                .ok_or_else(|| pyo3::exceptions::PyTypeError::new_err("invalid data result"))?;
            require_exact_keys(&auth_info, AUTH_INFO_KEYS)?;
            let context = pythonize::depythonize(&py_context)
                .map_err(|_| pyo3::exceptions::PyTypeError::new_err("invalid context result"))?;
            let data = pythonize::depythonize(&returned)
                .map_err(|_| pyo3::exceptions::PyTypeError::new_err("invalid data result"))?;
            Ok(CallOutput { context, data })
        })();

        result.map_err(|error| {
            log_python_error(py, &error, &inner.name, &inner.module, &inner.class, phase);
            Error::Internal("python microservice returned invalid output".into())
        })
    })
}

/// Serde deliberately treats absent `Option` fields as `None`. The Python
/// contract is stricter: every key must be present even when its value is
/// `None`, so validate the mapping keys before deserialization.
fn require_exact_keys(value: &Bound<'_, PyAny>, expected: &[&str]) -> PyResult<()> {
    let mapping = value.cast::<PyDict>().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err("Python result must be a plain dictionary")
    })?;
    if mapping.len() != expected.len() {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "Python result has missing or unknown fields",
        ));
    }
    for key in expected {
        if !mapping.contains(*key)? {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "Python result has missing or unknown fields",
            ));
        }
    }
    Ok(())
}

fn sanitized_timeout() -> Error {
    Error::Internal("python microservice call timed out".into())
}

fn log_python_error(
    py: Python<'_>,
    error: &PyErr,
    name: &str,
    module: &str,
    class: &str,
    phase: &str,
) {
    let traceback = sanitized_traceback(py, error);
    tracing::error!(
        microservice = name,
        module,
        class,
        phase,
        traceback = %traceback,
        "Python microservice failed"
    );
}

fn log_boundary_error(inner: &PythonMicroServiceInner, phase: &str, reason: &str) {
    tracing::error!(
        microservice = inner.name,
        module = inner.module,
        class = inner.class,
        phase,
        traceback = reason,
        "Python microservice failed"
    );
}

/// Render stack locations only: exception messages and source lines can echo
/// input/configuration values, so they are intentionally excluded.
fn sanitized_traceback(py: Python<'_>, error: &PyErr) -> String {
    let Some(traceback) = error.traceback(py) else {
        return "Python exception without traceback".into();
    };
    let rendered = (|| -> PyResult<String> {
        let summaries = py
            .import("traceback")?
            .getattr("extract_tb")?
            .call1((traceback,))?;
        let mut output = String::new();
        for summary in summaries.try_iter()? {
            let summary = summary?;
            let filename: String = summary.getattr("filename")?.extract()?;
            // Do not log the configured module path. The basename plus line
            // and function retains useful stack location without reflecting a
            // Python configuration value.
            let filename = Path::new(&filename)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("<python>");
            let line: usize = summary.getattr("lineno")?.extract()?;
            let function: String = summary.getattr("name")?.extract()?;
            use std::fmt::Write;
            let _ = writeln!(output, "{filename}:{line} in {function}");
        }
        Ok(output)
    })()
    .unwrap_or_else(|_| "Python traceback unavailable".into());
    rendered
        .chars()
        .flat_map(char::escape_default)
        .take(TRACEBACK_LIMIT)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextSnapshot {
    path: String,
    method: String,
    query: BTreeMap<String, String>,
    form: BTreeMap<String, String>,
    requester: Option<String>,
    target_backend: Option<String>,
    target_frontend: Option<String>,
    decorations: BTreeMap<String, Value>,
}

impl ContextSnapshot {
    fn from_context(ctx: &Context) -> Self {
        Self {
            path: ctx.request.path.clone(),
            method: ctx.request.method.clone(),
            query: ctx.request.query.clone(),
            form: ctx.request.form.clone(),
            requester: ctx.requester(),
            target_backend: ctx.target_backend.clone(),
            target_frontend: ctx.target_frontend.clone(),
            decorations: ctx.decorations.clone(),
        }
    }

    fn validate_read_only(&self, original: &Self) -> std::result::Result<(), ()> {
        if self.path != original.path
            || self.method != original.method
            || self.query != original.query
            || self.form != original.form
            || self.requester != original.requester
            || self.target_frontend != original.target_frontend
        {
            return Err(());
        }
        Ok(())
    }

    /// Enforce the pipeline's first-writer-wins convention for reserved
    /// routing decorations: once another component has published one, Python
    /// must return it unchanged.
    fn validate_reserved_decorations(&self, original: &Self) -> std::result::Result<(), ()> {
        for key in FIRST_WRITER_DECORATION_KEYS {
            if let Some(existing) = original.decorations.get(*key) {
                if self.decorations.get(*key) != Some(existing) {
                    return Err(());
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticationInformationBoundary {
    auth_class_ref: Option<String>,
    timestamp: Option<String>,
    issuer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InternalDataBoundary {
    auth_info: AuthenticationInformationBoundary,
    requester: Option<String>,
    requester_name: Vec<String>,
    subject_id: Option<String>,
    subject_type: SubjectType,
    attributes: BTreeMap<String, Vec<String>>,
    force_authn: bool,
    is_passive: bool,
}

impl From<InternalData> for InternalDataBoundary {
    fn from(value: InternalData) -> Self {
        Self {
            auth_info: AuthenticationInformationBoundary {
                auth_class_ref: value.auth_info.auth_class_ref,
                timestamp: value.auth_info.timestamp,
                issuer: value.auth_info.issuer,
            },
            requester: value.requester,
            requester_name: value.requester_name,
            subject_id: value.subject_id,
            subject_type: value.subject_type,
            attributes: value.attributes,
            force_authn: value.force_authn,
            is_passive: value.is_passive,
        }
    }
}

impl From<InternalDataBoundary> for InternalData {
    fn from(value: InternalDataBoundary) -> Self {
        Self {
            auth_info: AuthenticationInformation {
                auth_class_ref: value.auth_info.auth_class_ref,
                timestamp: value.auth_info.timestamp,
                issuer: value.auth_info.issuer,
            },
            requester: value.requester,
            requester_name: value.requester_name,
            subject_id: value.subject_id,
            subject_type: value.subject_type,
            attributes: value.attributes,
            force_authn: value.force_authn,
            is_passive: value.is_passive,
        }
    }
}

#[async_trait::async_trait]
impl MicroService for PythonMicroService {
    fn name(&self) -> &str {
        &self.inner.name
    }

    async fn process_request(&self, ctx: &mut Context, data: InternalData) -> Result<InternalData> {
        self.execute("request", ctx, data).await
    }

    async fn process_response(
        &self,
        ctx: &mut Context,
        data: InternalData,
    ) -> Result<InternalData> {
        self.execute("response", ctx, data).await
    }
}
