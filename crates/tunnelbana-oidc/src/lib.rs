//! # tunnelbana-oidc
//!
//! The OAuth 2.0 / OpenID Connect / OpenID Federation protocol library was
//! extracted into the standalone, runtime-agnostic [`grindvakt`] crate so it can
//! be reused by other projects. This crate is now a thin compatibility shim that
//! re-exports `grindvakt`'s protocol surface unchanged, so the tunnelbana
//! plugins and binary keep referring to `tunnelbana_oidc::*`.
//!
//! New code — inside or outside this workspace — can depend on [`grindvakt`]
//! directly.

#[doc(no_inline)]
pub use grindvakt::{
    client, dpop, federation, jwt, metadata, oauth_error, pkce, provider, request, rp, tokens,
};

pub use grindvakt::{
    AuthorizationRequest, Client, ClientStore, DpopConfig, DpopError, DpopProof,
    InMemoryClientStore, NoReplayStore, OAuthError, OAuthErrorCode, Provider, ProviderMetadata,
    ReplayStore, TokenCodec, TokenLifetimes, TokenResponse,
};
