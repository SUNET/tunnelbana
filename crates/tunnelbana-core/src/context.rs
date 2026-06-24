//! The per-request context carried through the proxy flow.

use crate::http::HttpRequestData;
use crate::state::State;
use serde_json::Value;
use std::collections::BTreeMap;

/// State namespace used by the proxy core itself.
pub const STATE_KEY_BASE: &str = "TUNNELBANA_BASE";
/// Key within [`STATE_KEY_BASE`] holding the requester (SP/RP id).
pub const KEY_REQUESTER: &str = "requester";
/// Key within [`STATE_KEY_BASE`] holding the routing frontend name.
pub const KEY_TARGET_FRONTEND: &str = "target_frontend";
/// Key within [`STATE_KEY_BASE`] holding the resolved SAML NameID format URI,
/// published by the SAML frontend so a response-path micro-service (e.g.
/// `nameid`) can shape the subject without knowing the frontend's name.
pub const KEY_NAME_ID_FORMAT: &str = "name_id_format";
/// Decoration key carrying the target entity id (upstream IdP/OP) chosen by a
/// discovery service or hint micro-service (SATOSA: `KEY_TARGET_ENTITYID`).
pub const KEY_TARGET_ENTITYID: &str = "target_entity_id";
/// Decoration key holding an absolute URL the proxy redirects to instead of
/// rendering a protocol error, set by micro-services (e.g.
/// `primary_identifier`'s `on_error`).
pub const KEY_ERROR_REDIRECT: &str = "error_redirect";
/// Decoration key carrying the SP's requested AuthnContextClassRef URIs
/// (a JSON array of strings), published by the SAML frontend on the request
/// path for the `accr` micro-service (SATOSA: `KEY_AUTHN_CONTEXT_CLASS_REF`).
pub const KEY_REQUESTED_ACCR: &str = "requested_accr";
/// Decoration key carrying the SP's RequestedAuthnContext `Comparison`
/// attribute (string: `exact`/`minimum`/`maximum`/`better`).
pub const KEY_REQUESTED_ACCR_COMPARISON: &str = "requested_accr_comparison";
/// Decoration key carrying the AuthnContextClassRef URIs (a JSON array of
/// strings) a request-path micro-service wants forwarded into the outgoing
/// AuthnRequest. First writer wins, mirroring [`KEY_TARGET_ENTITYID`].
pub const KEY_TARGET_AUTHN_CONTEXT_CLASS_REF: &str = "target_authn_context_class_ref";
/// Decoration key carrying the `Comparison` attribute to forward alongside
/// [`KEY_TARGET_AUTHN_CONTEXT_CLASS_REF`].
pub const KEY_TARGET_ACCR_COMPARISON: &str = "target_accr_comparison";

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
