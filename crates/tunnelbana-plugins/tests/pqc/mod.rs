//! Shared real-key fixtures for all PQC signature algorithms in jose-rs 0.7.

/// Generate each supported pure/composite ML-DSA key with its JOSE algorithm.
/// Generating keys here exercises AKP import/export as well as signature use.
pub fn signing_keys() -> Vec<jose_rs::jwk::Jwk> {
    use kryptering::{CompositeMlDsaVariant as Composite, MlDsaVariant as Pure};

    let mut keys: Vec<_> = [Pure::MlDsa44, Pure::MlDsa65, Pure::MlDsa87]
        .into_iter()
        .map(|variant| jose_rs::jwk::generate_mldsa(variant).unwrap())
        .collect();
    keys.extend(
        [
            Composite::MlDsa44Es256,
            Composite::MlDsa65Es256,
            Composite::MlDsa87Es384,
            Composite::MlDsa44Ed25519,
            Composite::MlDsa65Ed25519,
            Composite::MlDsa87Ed448,
        ]
        .into_iter()
        .map(|variant| jose_rs::jwk::generate_composite_mldsa(variant).unwrap()),
    );
    for key in &mut keys {
        key.kid = Some("pqc-key".into());
    }
    keys
}
