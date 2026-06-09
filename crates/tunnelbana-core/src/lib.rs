//! # tunnelbana-core
//!
//! The protocol-agnostic framework for the tunnelbana identity proxy: the
//! request [`context::Context`], the [`internal::InternalData`] model that
//! decouples frontends from backends, the encrypted [`state`] cookie, the
//! plugin [`plugin`] traits and registry, [`router`] and the [`proxy`]
//! orchestrator, plus config, attribute mapping, key loading and caching.

pub mod attributes;
pub mod cache;
pub mod config;
pub mod context;
pub mod internal;
pub mod plugin;
pub mod proxy;
pub mod router;
pub mod state;

// The generic primitives (error, http, keys, mac, util) were extracted into the
// standalone `grindvakt` crate so they can be reused outside this proxy. They
// are re-exported here unchanged, so the rest of the framework and downstream
// crates keep referring to `tunnelbana_core::{error, http, keys, mac, util}`.
pub use grindvakt::{error, http, keys, mac, util};

// Convenient re-exports.
pub use context::Context;
pub use grindvakt::error::{Error, Result};
pub use grindvakt::http::{HttpClient, HttpFetchResponse, HttpRequestData, Response};
pub use internal::{AuthenticationInformation, InternalData, SubjectType};
pub use plugin::{
    Backend, BackendAction, BuildContext, Frontend, FrontendAction, MicroService, Registry, Route,
};
pub use proxy::Proxy;
pub use state::{State, StateSealer};
