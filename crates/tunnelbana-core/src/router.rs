//! URL routing: matches an inbound path to a registered plugin endpoint.
//!
//! Almost every registered route is a literal `{module}/{suffix}` path, so the
//! router keeps those in an exact-match hash map and resolves them with an O(1)
//! probe rather than scanning a list of regexes. The number of routes scales
//! with the number of frontends (5 each), which can reach eduGAIN size
//! (10-15k), so a per-request linear scan would be 5N regex matches — flat O(1)
//! lookup keeps routing cost independent of N. A small fallback list preserves
//! the ability to register a true-regex route (`Route::new`); none do today.

use std::collections::HashMap;

use crate::plugin::{Matcher, Route};

/// Which kind of module owns an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleKind {
    Frontend,
    MicroService,
    Backend,
}

/// The owning-module metadata returned by a successful match.
#[derive(Clone)]
struct EndpointData {
    kind: ModuleKind,
    module: String,
    route_id: String,
}

impl EndpointData {
    fn to_match(&self) -> Match {
        Match {
            kind: self.kind,
            module: self.module.clone(),
            route_id: self.route_id.clone(),
        }
    }
}

/// A true-regex endpoint (router fallback for non-literal `Route::new` patterns).
struct RegexEndpoint {
    pattern: regex::Regex,
    data: EndpointData,
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
    /// Literal exact paths. First registrant for a given path wins (see `add`).
    exact: HashMap<String, EndpointData>,
    /// True-regex endpoints, in insertion order (empty in production today).
    regexes: Vec<RegexEndpoint>,
}

impl Router {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a module's routes. Frontends should be added before
    /// micro-services, which should be added before backends, mirroring
    /// SATOSA's matching precedence.
    ///
    /// For a given exact path the **first** registrant wins: a later `add` for
    /// the same literal path is ignored. Because `Proxy::new` adds frontends
    /// before backends, a frontend and a backend that share a name (so both
    /// register e.g. `Saml2/metadata`) resolve to the frontend, matching the
    /// old first-match-wins linear scan.
    pub fn add(&mut self, kind: ModuleKind, module: &str, routes: &[Route]) {
        for r in routes {
            let data = EndpointData {
                kind,
                module: module.to_string(),
                route_id: r.id.clone(),
            };
            match &r.matcher {
                Matcher::Exact(path) => {
                    self.exact.entry(path.clone()).or_insert(data);
                }
                Matcher::Regex(re) => self.regexes.push(RegexEndpoint {
                    pattern: re.clone(),
                    data,
                }),
            }
        }
    }

    /// Resolve a path to a matching endpoint.
    ///
    /// An exact (literal) match is probed first (O(1)); only on a miss is the
    /// regex fallback list scanned. Consequently an exact match takes
    /// precedence over a regex route even if the regex was registered earlier
    /// — the only divergence from a pure global insertion-order scan, and one
    /// that cannot arise today since no plugin registers a regex route. A
    /// non-matching path is therefore also O(1) (a single hash probe plus the
    /// empty regex list), where the old linear scan was its worst case.
    pub fn resolve(&self, path: &str) -> Option<Match> {
        if let Some(data) = self.exact.get(path) {
            return Some(data.to_match());
        }
        self.regexes
            .iter()
            .find(|e| e.pattern.is_match(path))
            .map(|e| e.data.to_match())
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

    #[test]
    fn exact_hit_and_miss() {
        let mut router = Router::new();
        router.add(
            ModuleKind::Frontend,
            "oidc1",
            &[Route::exact("oidc1/token", "token")],
        );
        let m = router.resolve("oidc1/token").unwrap();
        assert_eq!(m.kind, ModuleKind::Frontend);
        assert_eq!(m.module, "oidc1");
        assert_eq!(m.route_id, "token");
        // Misses (including the empty path) resolve to None cheaply.
        assert!(router.resolve("oidc1/nope").is_none());
        assert!(router.resolve("").is_none());
    }

    #[test]
    fn empty_router_resolves_none() {
        assert!(Router::new().resolve("anything").is_none());
    }

    #[test]
    fn same_path_first_registrant_wins() {
        // A SAML2 frontend and backend can share the name "Saml2", so both
        // register `Saml2/metadata`. Proxy::new adds frontends first, so the
        // frontend must win — guards the `or_insert` semantics.
        let mut router = Router::new();
        router.add(
            ModuleKind::Frontend,
            "Saml2",
            &[Route::exact("Saml2/metadata", "metadata")],
        );
        router.add(
            ModuleKind::Backend,
            "Saml2",
            &[Route::exact("Saml2/metadata", "metadata")],
        );
        assert_eq!(
            router.resolve("Saml2/metadata").unwrap().kind,
            ModuleKind::Frontend
        );
    }

    #[test]
    fn regex_fallback_still_matches() {
        let mut router = Router::new();
        router.add(
            ModuleKind::Frontend,
            "Foo",
            &[
                Route::exact("Foo/token", "token"),
                Route::new("Foo/[0-9]+", "num"),
            ],
        );
        // Exact route resolves via the O(1) map.
        assert_eq!(router.resolve("Foo/token").unwrap().route_id, "token");
        // Regex fallback matches a family of paths.
        assert_eq!(router.resolve("Foo/42").unwrap().route_id, "num");
        assert!(router.resolve("Foo/x").is_none());
    }

    #[test]
    fn exact_beats_regex_regardless_of_order() {
        // Documents the one deliberate divergence from global insertion order:
        // an exact match always wins over a regex, even one registered first.
        let mut router = Router::new();
        router.add(ModuleKind::Backend, "A", &[Route::new("A/.*", "wild")]);
        router.add(ModuleKind::Frontend, "A", &[Route::exact("A/b", "exact")]);
        let m = router.resolve("A/b").unwrap();
        assert_eq!(m.route_id, "exact");
        assert_eq!(m.kind, ModuleKind::Frontend);
    }

    #[test]
    fn large_n_resolves_correctly() {
        // The eduGAIN-scale case: many literal routes, O(1) lookup, no scan.
        let mut router = Router::new();
        for i in 0..15_000u32 {
            router.add(
                ModuleKind::Frontend,
                "f",
                &[Route::exact(format!("oidc{i}/jwks"), "jwks")],
            );
        }
        assert_eq!(router.resolve("oidc0/jwks").unwrap().route_id, "jwks");
        assert_eq!(router.resolve("oidc14999/jwks").unwrap().route_id, "jwks");
        assert!(router.resolve("oidc99999/jwks").is_none());
        // All routes were literal, so nothing landed in the regex fallback.
        assert!(router.regexes.is_empty());
    }
}
