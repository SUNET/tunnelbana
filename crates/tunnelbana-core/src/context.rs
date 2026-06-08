//! The per-request context carried through the proxy flow.

use crate::http::HttpRequestData;
use crate::state::State;
use std::collections::BTreeMap;
use serde_json::Value;

/// State namespace used by the proxy core itself.
pub const STATE_KEY_BASE: &str = "TUNNELBANA_BASE";
/// Key within [`STATE_KEY_BASE`] holding the requester (SP/RP id).
pub const KEY_REQUESTER: &str = "requester";
/// Key within [`STATE_KEY_BASE`] holding the routing frontend name.
pub const KEY_TARGET_FRONTEND: &str = "target_frontend";

/// Carries the inbound request, routing decisions, mutable session state and
/// ad-hoc decorations between the frontend, micro-services and backend.
/// Mirrors SATOSA's `satosa.context.Context`.
pub struct Context {
    /// The parsed inbound HTTP request.
    pub request: HttpRequestData,
    /// The name of the backend selected to handle this flow.
    pub target_backend: Option<String>,
    /// The name of the frontend that originated this flow.
    pub target_frontend: Option<String>,
    /// Encrypted session state (round-tripped via the state cookie).
    pub state: State,
    /// Ad-hoc per-request data not persisted to the cookie.
    pub decorations: BTreeMap<String, Value>,
}

impl Context {
    pub fn new(request: HttpRequestData, state: State) -> Self {
        Self {
            request,
            target_backend: None,
            target_frontend: None,
            state,
            decorations: BTreeMap::new(),
        }
    }

    /// The request path, leading slash already stripped.
    pub fn path(&self) -> &str {
        &self.request.path
    }

    /// Store a non-persistent decoration.
    pub fn decorate(&mut self, key: impl Into<String>, value: Value) {
        self.decorations.insert(key.into(), value);
    }

    /// Fetch a decoration.
    pub fn decoration(&self, key: &str) -> Option<&Value> {
        self.decorations.get(key)
    }

    /// Record the requester in the base state namespace.
    pub fn set_requester(&mut self, requester: &str) {
        self.state.set_str(STATE_KEY_BASE, KEY_REQUESTER, requester);
    }

    /// Read the requester from the base state namespace.
    pub fn requester(&self) -> Option<String> {
        self.state.get_str(STATE_KEY_BASE, KEY_REQUESTER)
    }
}
