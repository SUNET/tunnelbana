//! Shared eduID step-up policy evaluation.
//!
//! The response micro-service and the ordinary SAML backend both participate
//! in an eduID-compatible flow: the micro-service captures requester policy,
//! while the backend applies the provider-specific AuthnContext override after
//! it has resolved trusted metadata.  Keeping the decisions here prevents the
//! two legs from acquiring subtly different precedence rules.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

pub(crate) const REFEDS_MFA: &str = "https://refeds.org/profile/mfa";

/// Runtime policy semantics for the step-up service.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StepupBehavior {
    /// Tunnelbana's fail-closed, role-specific policy semantics.
    #[default]
    Hardened,
    /// eduID `stepup.py` policy and `InternalData` output semantics.
    Eduid,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct LoaSettings {
    pub(crate) requested: Vec<String>,
    #[serde(default)]
    pub(crate) extra_accepted: Vec<String>,
    #[serde(default)]
    pub(crate) returned: Option<String>,
}

impl LoaSettings {
    pub(crate) fn accepts(&self, loa: Option<&str>) -> bool {
        loa.is_some_and(|loa| {
            self.requested.iter().any(|value| value == loa)
                || self.extra_accepted.iter().any(|value| value == loa)
        })
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct MfaConfig {
    #[serde(default)]
    pub(crate) by_entity_id: IndexMap<String, LoaSettings>,
    #[serde(default)]
    pub(crate) by_entity_category: IndexMap<String, LoaSettings>,
    #[serde(default)]
    pub(crate) by_assurance_certification: IndexMap<String, LoaSettings>,
}

/// Trusted metadata attributes associated with the active entity/SSO role.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct MetadataPolicyValues {
    #[serde(default)]
    pub(crate) entity_categories: Vec<String>,
    #[serde(default)]
    pub(crate) assurance_certifications: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicySubject {
    Requester,
    Provider,
}

/// Request-local handoff consumed by the selected SAML backend.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct InitialPolicyHandoff {
    pub(crate) behavior: StepupBehavior,
    pub(crate) requester_wants_mfa: bool,
    pub(crate) mfa: MfaConfig,
}

/// Resolve policy using either Tunnelbana's role-specific/config-order rules
/// or eduID's generic metadata-source-order rules.
pub(crate) fn resolve_policy<'a>(
    mfa: &'a MfaConfig,
    entity_id: Option<&str>,
    metadata: &MetadataPolicyValues,
    behavior: StepupBehavior,
    subject: PolicySubject,
) -> Option<&'a LoaSettings> {
    let entity_id = entity_id?;
    if let Some(settings) = mfa.by_entity_id.get(entity_id) {
        return Some(settings);
    }

    match behavior {
        StepupBehavior::Eduid => metadata
            .entity_categories
            .iter()
            .find_map(|value| mfa.by_entity_category.get(value))
            .or_else(|| {
                metadata
                    .assurance_certifications
                    .iter()
                    .find_map(|value| mfa.by_assurance_certification.get(value))
            }),
        StepupBehavior::Hardened => {
            let (configured, presented) = match subject {
                PolicySubject::Requester => (&mfa.by_entity_category, &metadata.entity_categories),
                PolicySubject::Provider => (
                    &mfa.by_assurance_certification,
                    &metadata.assurance_certifications,
                ),
            };
            configured.iter().find_map(|(key, settings)| {
                presented
                    .iter()
                    .any(|candidate| candidate == key)
                    .then_some(settings)
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InitialLoaDecision {
    Satisfied(String),
    NeedsStepup,
    Rejected,
}

/// Decide whether the initial provider already satisfied the request.
pub(crate) fn initial_loa_decision(
    behavior: StepupBehavior,
    settings: Option<&LoaSettings>,
    requester_loas: &[String],
    asserted_loa: Option<&str>,
) -> InitialLoaDecision {
    let Some(settings) = settings else {
        return InitialLoaDecision::NeedsStepup;
    };

    match behavior {
        StepupBehavior::Hardened => {
            if settings.accepts(asserted_loa) {
                settings
                    .returned
                    .clone()
                    .or_else(|| requester_loas.first().cloned())
                    .or_else(|| asserted_loa.map(str::to_string))
                    .map(InitialLoaDecision::Satisfied)
                    .unwrap_or(InitialLoaDecision::NeedsStepup)
            } else {
                InitialLoaDecision::NeedsStepup
            }
        }
        StepupBehavior::Eduid => match settings.returned.as_ref() {
            Some(returned) if settings.accepts(asserted_loa) => {
                InitialLoaDecision::Satisfied(returned.clone())
            }
            Some(_) => InitialLoaDecision::Rejected,
            None => InitialLoaDecision::NeedsStepup,
        },
    }
}

/// Compute the downstream LoA after a successful second exchange.
pub(crate) fn completed_loa(
    behavior: StepupBehavior,
    settings: &LoaSettings,
    original_requester_loas: &[String],
    effective_requester_loas: &[String],
    asserted_loa: Option<&str>,
) -> Option<String> {
    match behavior {
        StepupBehavior::Hardened => settings
            .returned
            .clone()
            .or_else(|| original_requester_loas.first().cloned())
            .or_else(|| asserted_loa.map(str::to_string)),
        StepupBehavior::Eduid => effective_requester_loas
            .first()
            .cloned()
            .or_else(|| asserted_loa.map(str::to_string)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(name: &str) -> LoaSettings {
        LoaSettings {
            requested: vec![name.into()],
            extra_accepted: Vec::new(),
            returned: Some(format!("returned:{name}")),
        }
    }

    #[test]
    fn eduid_uses_metadata_order_after_exact_entity() {
        let mut mfa = MfaConfig::default();
        mfa.by_entity_category
            .insert("category-a".into(), settings("a"));
        mfa.by_entity_category
            .insert("category-b".into(), settings("b"));
        let metadata = MetadataPolicyValues {
            entity_categories: vec!["category-b".into(), "category-a".into()],
            assurance_certifications: Vec::new(),
        };

        let selected = resolve_policy(
            &mfa,
            Some("entity"),
            &metadata,
            StepupBehavior::Eduid,
            PolicySubject::Requester,
        )
        .unwrap();
        assert_eq!(selected.requested, ["b"]);
    }

    #[test]
    fn hardened_uses_config_order_and_role_specific_values() {
        let mut mfa = MfaConfig::default();
        mfa.by_entity_category
            .insert("category-a".into(), settings("a"));
        mfa.by_entity_category
            .insert("category-b".into(), settings("b"));
        mfa.by_assurance_certification
            .insert("certification".into(), settings("cert"));
        let metadata = MetadataPolicyValues {
            entity_categories: vec!["category-b".into(), "category-a".into()],
            assurance_certifications: vec!["certification".into()],
        };

        let selected = resolve_policy(
            &mfa,
            Some("entity"),
            &metadata,
            StepupBehavior::Hardened,
            PolicySubject::Requester,
        )
        .unwrap();
        assert_eq!(selected.requested, ["a"]);
    }

    #[test]
    fn eduid_requires_returned_before_initial_bypass() {
        let no_returned = LoaSettings {
            requested: vec!["loa3".into()],
            extra_accepted: vec!["loa3-alias".into()],
            returned: None,
        };
        assert_eq!(
            initial_loa_decision(
                StepupBehavior::Eduid,
                Some(&no_returned),
                &[REFEDS_MFA.into()],
                Some("loa3-alias"),
            ),
            InitialLoaDecision::NeedsStepup
        );

        let with_returned = LoaSettings {
            returned: Some(REFEDS_MFA.into()),
            ..no_returned
        };
        assert_eq!(
            initial_loa_decision(
                StepupBehavior::Eduid,
                Some(&with_returned),
                &[REFEDS_MFA.into()],
                Some("loa3-alias"),
            ),
            InitialLoaDecision::Satisfied(REFEDS_MFA.into())
        );
        assert_eq!(
            initial_loa_decision(
                StepupBehavior::Eduid,
                Some(&with_returned),
                &[REFEDS_MFA.into()],
                Some("loa2"),
            ),
            InitialLoaDecision::Rejected
        );
    }

    #[test]
    fn eduid_completion_ignores_returned() {
        let settings = LoaSettings {
            requested: vec!["provider-loa".into()],
            extra_accepted: Vec::new(),
            returned: Some("configured-returned".into()),
        };
        assert_eq!(
            completed_loa(
                StepupBehavior::Eduid,
                &settings,
                &["original".into()],
                &["effective".into()],
                Some("provider-loa"),
            ),
            Some("effective".into())
        );
    }
}
