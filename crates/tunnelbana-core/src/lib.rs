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
pub mod error;
pub mod http;
pub mod internal;
pub mod keys;
pub mod plugin;
pub mod proxy;
pub mod router;
pub mod state;
pub mod util;

// Convenient re-exports.
pub use context::Context;
pub use error::{Error, Result};
pub use http::{HttpClient, HttpFetchResponse, HttpRequestData, Response};
pub use internal::{AuthenticationInformation, InternalData, SubjectType};
pub use plugin::{
    Backend, BackendAction, BuildContext, Frontend, FrontendAction, MicroService, Registry, Route,
};
pub use proxy::Proxy;
pub use state::{State, StateSealer};
