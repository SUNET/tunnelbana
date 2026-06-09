//! # tunnelbana-oidc
//!
//! A reusable OAuth 2.0 / OpenID Connect (and, in [`federation`], OpenID
//! Federation 1.0) protocol library built on `jose-rs`. It is independent of
//! the proxy framework and of any web runtime: the OP engine ([`provider`]) and
//! the RP flow ([`rp`]) are pure logic, with outbound HTTP injected via
//! [`tunnelbana_core::HttpClient`].
//!
//! - OP (provider) side: [`provider::Provider`] — discovery, jwks, authorization,
//!   token (incl. `private_key_jwt`), userinfo, stateless JWT tokens.
//! - RP (client) side: [`rp`] — discovery, auth request, code exchange,
//!   id_token verification, userinfo.

// The `jose_rs::jwt::Claims` builder pattern (default + field assignment) is the
// ergonomic way to construct claims; silence the lint crate-wide.
#![allow(clippy::field_reassign_with_default)]
// `ClientAuth::PrivateKeyJwt` carries a SigningKey, which is intentionally
// larger than the secret-string variants.
#![allow(clippy::large_enum_variant)]

pub mod client;
pub mod dpop;
pub mod federation;
pub mod jwt;
pub mod metadata;
pub mod oauth_error;
pub mod pkce;
pub mod provider;
pub mod request;
pub mod rp;
pub mod tokens;

pub use client::{Client, ClientStore, InMemoryClientStore};
pub use dpop::{DpopConfig, DpopError, DpopProof, NoReplayStore, ReplayStore};
pub use metadata::ProviderMetadata;
pub use oauth_error::{OAuthError, OAuthErrorCode};
pub use provider::{Provider, TokenLifetimes, TokenResponse};
pub use request::AuthorizationRequest;
pub use tokens::TokenCodec;
