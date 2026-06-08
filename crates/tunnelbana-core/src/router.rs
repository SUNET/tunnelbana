//! URL routing: matches an inbound path to a registered plugin endpoint.

use crate::plugin::Route;

/// Which kind of module owns an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleKind {
    Frontend,
    MicroService,
    Backend,
}

struct Endpoint {
    kind: ModuleKind,
    module: String,
    route_id: String,
    pattern: regex::Regex,
}

/// A resolved routing match.
pub struct Match {
    pub kind: ModuleKind,
    pub module: String,
    pub route_id: String,
}

/// Holds all registered endpoints and resolves paths against them.
#[derive(Default)]
pub struct Router {
    endpoints: Vec<Endpoint>,
}

impl Router {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a module's routes. Frontends should be added before
    /// micro-services, which should be added before backends, mirroring
    /// SATOSA's matching precedence.
    pub fn add(&mut self, kind: ModuleKind, module: &str, routes: &[Route]) {
        for r in routes {
            self.endpoints.push(Endpoint {
                kind,
                module: module.to_string(),
                route_id: r.id.clone(),
                pattern: r.pattern.clone(),
            });
        }
    }

    /// Resolve a path to the first matching endpoint.
    pub fn resolve(&self, path: &str) -> Option<Match> {
        self.endpoints.iter().find_map(|e| {
            if e.pattern.is_match(path) {
                Some(Match {
                    kind: e.kind,
                    module: e.module.clone(),
                    route_id: e.route_id.clone(),
                })
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_in_precedence_order() {
        let mut router = Router::new();
        router.add(
            ModuleKind::Frontend,
            "OIDC",
            &[Route::new("OIDC/authorization", "authorization")],
        );
        router.add(
            ModuleKind::Backend,
            "Saml2",
            &[Route::new("Saml2/acs/post", "acs_post")],
        );

        let m = router.resolve("OIDC/authorization").unwrap();
        assert_eq!(m.kind, ModuleKind::Frontend);
        assert_eq!(m.module, "OIDC");
        assert_eq!(m.route_id, "authorization");

        let m = router.resolve("Saml2/acs/post").unwrap();
        assert_eq!(m.kind, ModuleKind::Backend);

        assert!(router.resolve("nope").is_none());
    }
}
