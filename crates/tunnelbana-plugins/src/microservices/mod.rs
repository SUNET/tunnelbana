//! Built-in micro-services.
//!
//! Response-path attribute shaping:
//! - `static_attributes` — inject fixed attributes.
//! - `filter_attributes` — keep only allow-listed attributes, globally or per
//!   requester (SATOSA: `AttributePolicy`).
//! - `filter_attribute_values` — drop attribute *values* not matching a regex,
//!   scoped per provider/requester (SATOSA: `FilterAttributeValues`).
//! - `rename_attributes` — rename internal attributes (SATOSA contrib:
//!   `RenameAttributes`).
//! - `attribute_processor` — per-attribute transform chains: `regex_sub`,
//!   `hash`, `scope`, `scope_extractor`, `scope_remover`, `gender` (SATOSA:
//!   `AttributeProcessor` + `processors/*`).
//! - `attribute_generation` — synthesize attributes from Tera templates over
//!   the existing attribute set (SATOSA: `AddSyntheticAttributes`, which uses
//!   Mustache).
//! - `hasher` — salted-hash the subject id and/or selected attributes per
//!   requester (SATOSA: `Hasher`).
//! - `primary_identifier` — construct a primary identifier from an ordered
//!   candidate list (SATOSA: `PrimaryIdentifier`).
//! - `attribute_authorization` — regex-based allow/deny authorization
//!   (SATOSA: `AttributeAuthorization`).
//! - `custom_logging` — append a per-flow JSON audit record to a file
//!   (SATOSA: `CustomLoggingService`).
//!
//! Request-path routing:
//! - `custom_routing` — pick the backend by requester and/or target issuer
//!   (SATOSA: `DecideBackendByRequester` / `DecideBackendByTargetIssuer`).
//! - `idp_hinting` — lift an IdP hint query parameter into the target-entity
//!   decoration (SATOSA: `IdpHinting`). List it *before* `custom_routing` in
//!   the config so the hint is visible to issuer-based routing rules.

mod authorization;
mod generation;
mod hasher;
mod logging;
mod policy;
mod primary_identifier;
mod processor;
mod routing;
mod values;

pub use authorization::AttributeAuthorization;
pub use generation::AttributeGeneration;
pub use hasher::Hasher;
pub use logging::CustomLogging;
pub use policy::{FilterAttributes, StaticAttributes};
pub use primary_identifier::PrimaryIdentifier;
pub use processor::AttributeProcessor;
pub use routing::{CustomRouting, IdpHinting};
pub use values::{FilterAttributeValues, RenameAttributes};

use std::collections::BTreeMap;

/// SATOSA's `get_dict_defaults`: exact key, else `""`, else `"default"`.
pub(crate) fn level<'a, T>(map: &'a BTreeMap<String, T>, key: &str) -> Option<&'a T> {
    map.get(key)
        .or_else(|| map.get(""))
        .or_else(|| map.get("default"))
}

#[cfg(test)]
pub(crate) mod testutil {
    use std::sync::Arc;
    use tunnelbana_core::attributes::AttributeMapper;
    use tunnelbana_core::context::Context;
    use tunnelbana_core::http::HttpRequestData;
    use tunnelbana_core::internal::InternalData;
    use tunnelbana_core::plugin::{BuildContext, NullHttpClient};
    use tunnelbana_core::state::State;

    pub fn bx(name: &str, config: serde_json::Value) -> BuildContext {
        BuildContext {
            name: name.to_string(),
            base_url: "https://x".into(),
            config,
            attribute_mapper: Arc::new(AttributeMapper::default()),
            http_client: Arc::new(NullHttpClient),
            secret: "s".into(),
            previous_secrets: Vec::new(),
        }
    }

    pub fn ctx() -> Context {
        Context::new(HttpRequestData::default(), State::new())
    }

    pub fn response_from(requester: &str) -> InternalData {
        InternalData {
            requester: Some(requester.into()),
            ..InternalData::default()
        }
    }
}
