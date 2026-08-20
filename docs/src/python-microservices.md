# Writing embedded Python micro-services

Tunnelbana can run synchronous Python classes in the request and response
micro-service pipeline. Use this integration for small policy, routing, and
attribute transformations that should run in the Tunnelbana process. For the
built-in Rust alternatives and general pipeline ordering, see
[Micro-services](micro-services.md).

Python modules are trusted operator code. This integration is not a sandbox:
loaded code has the operating-system permissions of the Tunnelbana process and
can import other installed modules. Review it like application code, deploy it
read-only, restrict the service account, and do not log secrets or identity
data.

## Quick start

The configured module path is an import root. A minimal deployment can look
like this:

```text
deployment/
├── proxy.toml
└── python/
    └── services/
        ├── __init__.py
        └── affiliation.py
```

Create `python/services/affiliation.py`:

```python
class AffiliationNormalizer:
    def __init__(self, name: str, base_url: str, config: dict):
        self.allowed = frozenset(config["allowed"])

    def process_response(self, context: dict, data: dict) -> dict:
        values = data["attributes"].get("affiliation", [])
        data["attributes"]["affiliation"] = [
            value for value in values if value in self.allowed
        ]
        return data
```

Configure its import and settings in `proxy.toml`:

```toml
[python]
module_path = "python"
max_concurrent_calls = 16
call_timeout_seconds = 30

[[microservice]]
type = "python"
name = "normalize-affiliation"

[microservice.config]
module = "services.affiliation"
class = "AffiliationNormalizer"

[microservice.config.settings]
allowed = ["student", "staff"]
```

The path `python` is resolved relative to `proxy.toml`, so the import root in
this layout is `deployment/python`. Tunnelbana imports only the configured
`services.affiliation` module and looks up only `AffiliationNormalizer`.
Restart Tunnelbana after changing Python source or configuration; modules and
instances are not reloaded while the process is running.

At startup, Tunnelbana fails before serving traffic if the module cannot be
imported, the class cannot be found or constructed, or its process methods are
invalid.

## Where a Python micro-service runs

Python micro-services participate in the same ordered list as Rust
micro-services:

```mermaid
flowchart LR
    A[Frontend produces request InternalData] --> B[process_request methods in configured order]
    B --> C[Selected backend]
    C --> D[Backend produces response InternalData]
    D --> E[process_response methods in configured order]
    E --> F[Originating frontend]
```

`process_request` runs after a frontend has interpreted the downstream
authentication request and before Tunnelbana selects and calls the upstream
backend. `process_response` runs after the backend has interpreted the upstream
authentication response and before the originating frontend creates its
downstream response.

Every configured service is considered at both points. If its class does not
define the method for one direction, that direction is an identity operation.
Micro-services run in the order in which their `[[microservice]]` entries appear
in `proxy.toml` on both paths.

Python micro-services cannot register HTTP endpoints in this version.

## Class contract and lifecycle

A class has this contract:

```python
class Example:
    def __init__(self, name: str, base_url: str, config: dict):
        ...

    def process_request(self, context: dict, data: dict) -> dict:
        return data

    def process_response(self, context: dict, data: dict) -> dict:
        return data
```

The constructor receives:

| Argument | Meaning |
| --- | --- |
| `name` | The exact `microservice.name` from `proxy.toml`. |
| `base_url` | Tunnelbana's top-level `base_url`. |
| `config` | A plain dictionary containing only `[microservice.config.settings]`. It is `{}` when `settings` is omitted. |

Tunnelbana constructs the class once at startup and reuses that exact instance
for every request and response call. Store parsed, read-only settings on the
instance, but do not store a request's `context` or `data` for later use.
Mutable instance state is shared across calls. CPython's GIL normally
serializes Python bytecode, but native modules and blocking operations can
release the GIL, so shared state must still be concurrency-safe.

At least one of `process_request` and `process_response` must exist. Every
method that exists must be callable and must be an ordinary synchronous
function. `async def` methods are rejected at startup, and an awaitable
returned by a synchronous function is rejected at runtime. Do not call
`asyncio.run()` to work around this contract.

## Python values at the boundary

Both method arguments are fresh plain-Python copies. They contain strings,
booleans, lists, dictionaries, and `None`; no Rust objects or proxy handles are
present. These type definitions summarize the complete shapes:

```python
from typing import Literal, TypedDict

type JsonValue = (
    None
    | bool
    | int
    | float
    | str
    | list[JsonValue]
    | dict[str, JsonValue]
)


class AuthenticationInformation(TypedDict):
    auth_class_ref: str | None
    timestamp: str | None
    issuer: str | None


class InternalData(TypedDict):
    auth_info: AuthenticationInformation
    requester: str | None
    requester_name: list[str]
    subject_id: str | None
    subject_type: Literal["persistent", "transient", "public", "pairwise"]
    attributes: dict[str, list[str]]
    force_authn: bool
    is_passive: bool


class ContextSnapshot(TypedDict):
    path: str
    method: str
    query: dict[str, str]
    form: dict[str, str]
    requester: str | None
    target_backend: str | None
    target_frontend: str | None
    decorations: dict[str, JsonValue]
```

These declarations are documentation; a service does not need to copy or
import them to run.

### The `context` input

`context` describes the current proxy flow and request. It always has exactly
these keys:

| Key | Python type | Meaning | May Python change it? |
| --- | --- | --- | --- |
| `path` | `str` | Inbound HTTP path with the leading `/` removed. | No |
| `method` | `str` | Uppercase HTTP method, such as `GET` or `POST`. | No |
| `query` | `dict[str, str]` | Parsed query parameters. | No |
| `form` | `dict[str, str]` | Parsed `application/x-www-form-urlencoded` body fields; otherwise empty. | No |
| `requester` | `str \| None` | Downstream SP entity ID or OIDC client ID recovered from the flow state. | No |
| `target_backend` | `str \| None` | Name of the selected or proposed backend. | **Yes** |
| `target_frontend` | `str \| None` | Name of the frontend that originated the flow. | No |
| `decorations` | `dict[str, JsonValue]` | Non-persistent, flow-local values exchanged by pipeline components. | **Yes** |

Python may change only `target_backend` and `decorations`. It may add, replace,
or remove keys below `decorations`, provided every value remains JSON-compatible.
It may not add or remove top-level context keys. Changing `path`, `method`,
`query`, `form`, `requester`, or `target_frontend` makes the whole call fail,
even if the changed value would otherwise have a valid type.

Setting `target_backend` during `process_request` affects backend selection and
the value must be a configured backend name. Changing it during
`process_response` is permitted by the boundary but does not reroute the
upstream operation that has already completed. Decorations are not written to
Tunnelbana's encrypted state cookie; use them only within the current flow.

The restricted snapshot deliberately excludes the complete URI, headers,
cookies, request body, encrypted or persistent state, secrets, HTTP client
handles, and Rust object handles.

### The `data` input

`data` is Tunnelbana's protocol-neutral authentication record. Every key is
always present, including optional values represented by `None` and empty
collections:

| Key | Python type | Meaning and normal phase |
| --- | --- | --- |
| `auth_info` | `dict` | How and where authentication occurred. Usually empty/`None`-valued on the request path and populated on the response path. |
| `requester` | `str \| None` | Downstream SP entity ID or OIDC client ID. Available on the request path and restored on the response path. |
| `requester_name` | `list[str]` | Optional display names for the requester; commonly empty. |
| `subject_id` | `str \| None` | Authenticated subject identifier; normally populated on the response path. |
| `subject_type` | one of four strings | Identifier semantics: `persistent`, `transient`, `public`, or `pairwise`. |
| `attributes` | `dict[str, list[str]]` | Internal attribute name to zero or more string values. Usually most useful on the response path. |
| `force_authn` | `bool` | Requester requires fresh authentication; mainly a request-path field. |
| `is_passive` | `bool` | Requester forbids user interaction; mainly a request-path field. |

`auth_info` also always contains every key:

| Key | Python type | Meaning |
| --- | --- | --- |
| `auth_class_ref` | `str \| None` | SAML AuthnContextClassRef or OIDC `acr`. |
| `timestamp` | `str \| None` | Authentication time, represented as an RFC 3339 string when present. |
| `issuer` | `str \| None` | Upstream IdP or OP issuer. |

The phase descriptions indicate when a field is normally useful, not a
mutation restriction. Python may return new values for any `InternalData`
field as long as the complete result is valid.

## Returning output

A process method has two output channels:

1. Return one complete `InternalData` dictionary. Returning the input `data`
   after modifying it in place is the simplest approach, but returning a new
   complete dictionary is also valid.
2. Mutate `context["target_backend"]` or `context["decorations"]` in place when
   the service needs those effects. The context dictionary itself is not the
   method's return value.

The returned `InternalData` must be a plain dictionary with exactly the eight
documented top-level keys. Its `auth_info` must be a dictionary with exactly
the three documented keys. Missing keys, extra keys, scalar attribute values,
non-string attribute values, invalid subject types, or other wrong Python types
reject the result. Returning `None`, a coroutine, or an arbitrary object also
rejects it.

The context copy is checked just as strictly after the method returns. All
read-only values must equal their original values and all decorations must
convert to JSON. Tunnelbana validates the complete context and returned data
before applying anything to the real Rust context. If validation or Python
execution fails, `target_backend`, `decorations`, and `InternalData` are left
unchanged. This rollback does not include mutable state inside the reused
Python class instance or external side effects performed by Python.

On the request path, the returned data goes to the next micro-service and then
the selected backend. On the response path, it goes to the next micro-service
and then the originating frontend. A missing process method passes the data
through unchanged.

## Configuration reference

The global `[python]` table is required if any micro-service has
`type = "python"`:

| Key | Required | Default | Meaning |
| --- | --- | --- | --- |
| `module_path` | Yes | - | One accessible import directory, absolute or relative to `proxy.toml`. It must not be empty. |
| `max_concurrent_calls` | No | `16` | Maximum calls admitted across all Python micro-services. Must be greater than zero. |
| `call_timeout_seconds` | No | `30` | Total deadline for semaphore waiting plus execution. Must be greater than zero. |

Each Python `[[microservice]]` has this configuration:

| Key | Required | Meaning |
| --- | --- | --- |
| `module` | Yes | Dotted Python module import, relative to `module_path`, such as `services.affiliation`. |
| `class` | Yes | Callable class name in that module. |
| `settings` | No | TOML table converted to the constructor's `config` dictionary. |

The global Python table and the service-level table containing
`module`/`class`/`settings` reject unknown keys. Keys inside `settings` belong
to the Python class and may have any TOML value that converts to Python. If the
class requires settings, validate them in `__init__`; raising there makes
Tunnelbana fail fast during startup.

Tunnelbana adds the one configured module directory to the interpreter's
existing import paths. It does not scan it, discover classes, import all Python
files, or install packages. Imports performed by the configured trusted module
itself still behave like normal Python imports. Provision third-party
dependencies in the image or host before Tunnelbana starts; runtime `pip`
installation is not supported.

Micro-service names must be unique. Several configured Python services may use
the same module or class, but each entry receives its own class instance and
its own settings. All instances share the global concurrency limit and timeout.

## Example 1: normalize response attributes

This response-only service trims and lowercases affiliation values, removes
values not listed in settings, and de-duplicates the result without changing
its order:

```python
from typing import Any


class AffiliationNormalizer:
    def __init__(
        self, name: str, base_url: str, config: dict[str, Any]
    ) -> None:
        del name, base_url
        self.allowed = frozenset(
            str(value).strip().lower() for value in config["allowed"]
        )

    def process_response(
        self, context: dict[str, Any], data: dict[str, Any]
    ) -> dict[str, Any]:
        del context
        normalized = []
        for value in data["attributes"].get("affiliation", []):
            value = value.strip().lower()
            if value in self.allowed and value not in normalized:
                normalized.append(value)

        if normalized:
            data["attributes"]["affiliation"] = normalized
        else:
            data["attributes"].pop("affiliation", None)
        return data
```

```toml
[[microservice]]
type = "python"
name = "normalize-affiliation"

[microservice.config]
module = "services.affiliation"
class = "AffiliationNormalizer"

[microservice.config.settings]
allowed = ["student", "staff", "faculty"]
```

There is no `process_request`, so Tunnelbana treats this service as an identity
operation on the request path.

## Example 2: select a backend by requester

This request-only service routes known downstream SPs/RPs to configured
backends. The route table is controlled by the operator; it does not accept a
backend name directly from an untrusted query parameter.

```python
from typing import Any


class RequesterRouter:
    def __init__(
        self, name: str, base_url: str, config: dict[str, Any]
    ) -> None:
        del name, base_url
        self.routes = dict(config.get("routes", {}))
        self.default_backend = config.get("default_backend")

    def process_request(
        self, context: dict[str, Any], data: dict[str, Any]
    ) -> dict[str, Any]:
        requester = data["requester"] or context["requester"]
        backend = self.routes.get(requester, self.default_backend)
        if backend is not None:
            context["target_backend"] = backend
            context["decorations"]["routing_policy"] = "requester-map"
        return data
```

```toml
[[microservice]]
type = "python"
name = "route-by-requester"

[microservice.config]
module = "services.routing"
class = "RequesterRouter"

[microservice.config.settings]
default_backend = "DefaultUpstream"

[microservice.config.settings.routes]
"https://research.example/sp" = "ResearchUpstream"
"dashboard-client" = "WorkforceUpstream"
```

`ResearchUpstream`, `WorkforceUpstream`, and `DefaultUpstream` must be names of
configured `[[backend]]` entries. `routing_policy` is a JSON-compatible,
flow-local decoration that later components may inspect.

## Example 3: enforce a two-phase partner policy

A single instance may implement both directions. This example requires fresh,
interactive authentication for one requester, verifies that the response came
from the expected issuer, and releases only selected attributes:

```python
from typing import Any


class PartnerPolicy:
    def __init__(
        self, name: str, base_url: str, config: dict[str, Any]
    ) -> None:
        del name, base_url
        self.requester = config["requester"]
        self.expected_issuer = config["expected_issuer"]
        self.released_attributes = frozenset(config["released_attributes"])

    def applies(self, data: dict[str, Any]) -> bool:
        return data["requester"] == self.requester

    def process_request(
        self, context: dict[str, Any], data: dict[str, Any]
    ) -> dict[str, Any]:
        if self.applies(data):
            data["force_authn"] = True
            data["is_passive"] = False
            context["decorations"]["partner_policy"] = True
        return data

    def process_response(
        self, context: dict[str, Any], data: dict[str, Any]
    ) -> dict[str, Any]:
        del context
        if not self.applies(data):
            return data

        if data["auth_info"]["issuer"] != self.expected_issuer:
            raise ValueError("partner issuer policy failed")

        data["attributes"] = {
            key: values
            for key, values in data["attributes"].items()
            if key in self.released_attributes
        }
        return data
```

```toml
[[microservice]]
type = "python"
name = "partner-policy"

[microservice.config]
module = "services.partner_policy"
class = "PartnerPolicy"

[microservice.config.settings]
requester = "https://partner.example/sp"
expected_issuer = "https://trusted-idp.example"
released_attributes = ["mail", "givenname", "surname"]
```

If the issuer check raises, Tunnelbana aborts that pipeline call. The client
receives a sanitized proxy error; the Python exception text is not reflected
to it or copied into the server log.

## Execution limits, errors, and logging

```mermaid
flowchart LR
    A[Async proxy pipeline] --> B{Global semaphore}
    B -->|permit| C[Tokio blocking task]
    C --> D[Attach thread to CPython and acquire GIL]
    D --> E[Reusable configured class instance]
    E --> F[Strictly convert returned data and context]
    F -->|valid| G[Atomically apply allowed changes]
    F -->|invalid| H[Sanitized proxy error]
    B -->|deadline| H
    C -->|deadline; task continues| H
    C -. permit released only when call exits .-> B
```

Calls run on Tokio's blocking thread pool, not on async runtime workers. One
global semaphore enforces `max_concurrent_calls` across all Python services.
CPython's GIL may further serialize Python bytecode, but calls can overlap when
Python performs I/O or invokes native code that releases the GIL.

`call_timeout_seconds` covers both waiting for a semaphore permit and executing
the method. A blocking Python call cannot be killed safely. When execution
times out, the proxy stops waiting and reports an error, but the detached call
continues until Python returns and retains its semaphore permit until then.
Python code should therefore configure its own shorter timeouts for filesystem,
database, network, or subprocess operations. Enough permanently hung calls can
consume all Python capacity.

Client and protocol paths receive fixed sanitized failures. Server logs include
the micro-service name, module, class, phase, and a bounded traceback containing
stack locations. They omit exception messages and source lines because those
can contain input or configuration values. Tunnelbana never logs Python
settings, input data, returned data, secrets, headers, cookies, or request
bodies. Python code remains responsible for the safety of its own logging.

## Common mistakes

- Returning only the field that changed. Always return the complete eight-key
  `InternalData` dictionary; normally mutate and return the supplied `data`.
- Returning a scalar attribute such as `{"mail": "user@example.org"}`.
  Attribute values must always be lists, such as
  `{"mail": ["user@example.org"]}`.
- Deleting optional keys when their value is absent. Keep the key and use
  `None`, an empty list, or an empty dictionary as specified by the schema.
- Adding helper values at the top level of `context`. Put JSON-compatible
  flow-local helper values below `context["decorations"]` instead.
- Modifying `query`, `form`, `requester`, or another read-only context field.
  Tunnelbana detects the mutation and rejects all output from the call.
- Defining `async def process_request(...)` or returning an awaitable. Embedded
  Python methods are synchronous only.
- Keeping per-request values on `self`, relying on a fresh class instance, or
  assuming calls cannot overlap. One instance is reused for the process
  lifetime.
- Performing external I/O without its own timeout. Tunnelbana's timeout cannot
  stop the underlying Python call.
- Expecting source changes or newly installed files to be discovered at
  runtime. Imports and construction happen at startup; restart the process.

## Deployment requirements

Tunnelbana embeds CPython 3.13 and links dynamically to its shared library.
Building requires the CPython 3.13 development package; reproducible builds set
`PYO3_PYTHON=/usr/bin/python3.13`. Runtime images and hosts need Python 3.13 and
the matching `libpython3.13` shared library. The repository's root and
`deploy/satosa-idp` images provide these packages.

Deploy or mount the configured module directory with the application,
preferably read-only. Install any third-party dependencies when building the
image or provisioning the host. Tunnelbana never runs `pip` at startup.
