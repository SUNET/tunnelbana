//! # tunnelbana-plugins
//!
//! Concrete frontends, backends and micro-services, plus [`register_all`] which
//! installs their constructors into a [`tunnelbana_core::plugin::Registry`].

pub mod client_loader;
pub mod dpop;
pub mod federation_backend;
pub mod federation_frontend;
pub mod keyload;
pub mod microservices;
pub mod oidc_backend;
pub mod oidc_frontend;
pub mod saml2_backend;
pub mod saml2_frontend;
pub(crate) mod saml_common;
pub mod saml_metadata;

use tunnelbana_core::plugin::Registry;

/// Register every built-in plugin's constructor under its config `type` name.
pub fn register_all(registry: &mut Registry) {
    registry.register_frontend("oidc", oidc_frontend::OidcFrontend::build);
    registry.register_frontend(
        "oidc_federation",
        federation_frontend::FederationFrontend::build,
    );
    registry.register_frontend("saml2", saml2_frontend::Saml2Frontend::build);
    registry.register_backend("oidc", oidc_backend::OidcBackend::build);
    registry.register_backend(
        "oidc_federation",
        federation_backend::FederationBackend::build,
    );
    registry.register_backend("saml2", saml2_backend::Saml2Backend::build);
    registry.register_microservice("static_attributes", microservices::StaticAttributes::build);
    registry.register_microservice("filter_attributes", microservices::FilterAttributes::build);
    registry.register_microservice("custom_routing", microservices::CustomRouting::build);
    registry.register_microservice(
        "attribute_processor",
        microservices::AttributeProcessor::build,
    );
    registry.register_microservice(
        "attribute_authorization",
        microservices::AttributeAuthorization::build,
    );
    registry.register_microservice(
        "filter_attribute_values",
        microservices::FilterAttributeValues::build,
    );
    registry.register_microservice("rename_attributes", microservices::RenameAttributes::build);
    registry.register_microservice(
        "attribute_generation",
        microservices::AttributeGeneration::build,
    );
    registry.register_microservice("hasher", microservices::Hasher::build);
    registry.register_microservice(
        "primary_identifier",
        microservices::PrimaryIdentifier::build,
    );
    registry.register_microservice("idp_hinting", microservices::IdpHinting::build);
    registry.register_microservice("custom_logging", microservices::CustomLogging::build);
}
