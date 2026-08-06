//! Shared helper to assemble a frontend's client list from inline config plus
//! an optional external JSON roster file (`clients_file`).
//!
//! The file is a bare JSON array of [`Client`] objects. Its entries are appended
//! to the inline `clients`, and any duplicate `client_id` across the merged set
//! is a fail-fast configuration error — the underlying
//! [`InMemoryClientStore::with_clients`](tunnelbana_oidc::client::InMemoryClientStore::with_clients)
//! would otherwise silently keep only the last entry for a given id.
//!
//! Unlike serde's default, an **unknown field** in any entry (e.g. a
//! misspelled `redirect_uri` for `redirect_uris`) is rejected rather than
//! silently dropped, so a typo cannot quietly produce a half-configured
//! client. This applies to inline entries exactly as to file entries.
//! Unknown fields are detected via `serde_ignored` rather than
//! `#[serde(deny_unknown_fields)]` so the check stays in sync with `Client`
//! automatically as it gains fields (the type lives in `grindvakt`).

use std::collections::HashSet;

use tunnelbana_core::error::{Error, Result};
use tunnelbana_oidc::client::Client;

/// Merge inline clients (raw config values, checked for unknown fields) with
/// an optional JSON file (a bare `[Client, …]` array, read as-given relative
/// to the process working directory). Returns the merged list, or an error if
/// any entry is malformed or carries an unknown field, the file is
/// unreadable/malformed, or any `client_id` appears more than once across the
/// whole set.
pub fn load_clients(
    inline: Vec<serde_json::Value>,
    clients_file: Option<&str>,
) -> Result<Vec<Client>> {
    let mut clients = Vec::with_capacity(inline.len());
    for (i, value) in inline.into_iter().enumerate() {
        clients.push(
            parse_client_strict(value)
                .map_err(|e| Error::Config(format!("inline clients[{i}]: {e}")))?,
        );
    }
    if let Some(path) = clients_file {
        let json = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("reading clients_file {path}: {e}")))?;
        // Deserialize while recording any field not present on `Client`, so a
        // typo'd key is a hard error instead of a silently dropped value.
        let mut de = serde_json::Deserializer::from_str(&json);
        let mut unknown = Vec::new();
        let from_file: Vec<Client> =
            serde_ignored::deserialize(&mut de, |p| unknown.push(p.to_string()))
                .map_err(|e| Error::Config(format!("parsing clients_file {path}: {e}")))?;
        de.end()
            .map_err(|e| Error::Config(format!("parsing clients_file {path}: {e}")))?;
        if !unknown.is_empty() {
            return Err(Error::Config(format!(
                "clients_file {path}: unknown field(s): {}",
                unknown.join(", ")
            )));
        }
        clients.extend(from_file);
    }
    // Reject duplicate client_id: with_clients keys a HashMap by client_id and
    // silently last-wins, which would shadow a client's secret/redirect_uris.
    let mut seen = HashSet::new();
    for c in &clients {
        if !seen.insert(c.client_id.as_str()) {
            return Err(Error::Config(format!(
                "duplicate client_id '{}' across inline clients and clients_file",
                c.client_id
            )));
        }
    }
    Ok(clients)
}

/// Deserialize a single inline client entry, rejecting unknown fields exactly
/// like `clients_file` entries are.
fn parse_client_strict(value: serde_json::Value) -> Result<Client> {
    let mut unknown = Vec::new();
    let client: Client = serde_ignored::deserialize(value, |p| unknown.push(p.to_string()))
        .map_err(|e| Error::Config(format!("parsing client: {e}")))?;
    if !unknown.is_empty() {
        return Err(Error::Config(format!(
            "unknown field(s): {}",
            unknown.join(", ")
        )));
    }
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(id: &str) -> serde_json::Value {
        serde_json::json!({ "client_id": id })
    }

    /// Write `contents` to a unique temp file and return its path.
    fn temp_json(tag: &str, contents: &str) -> std::path::PathBuf {
        // Unique per test name; Math/Date randomness is unavailable here anyway.
        let path = std::env::temp_dir().join(format!("tb_clients_{tag}.json"));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn merges_inline_and_file() {
        let path = temp_json(
            "merge",
            r#"[{"client_id":"from-file","redirect_uris":["https://rp/cb"]}]"#,
        );
        let merged = load_clients(vec![client("inline")], Some(path.to_str().unwrap())).unwrap();
        let ids: Vec<&str> = merged.iter().map(|c| c.client_id.as_str()).collect();
        assert_eq!(ids, vec!["inline", "from-file"]);
    }

    #[test]
    fn no_file_returns_inline() {
        let merged = load_clients(vec![client("a"), client("b")], None).unwrap();
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn empty_set_is_allowed() {
        let merged = load_clients(vec![], None).unwrap();
        assert!(merged.is_empty());
    }

    #[test]
    fn duplicate_across_inline_and_file_is_error() {
        let path = temp_json("dup", r#"[{"client_id":"dup"}]"#);
        let err = load_clients(vec![client("dup")], Some(path.to_str().unwrap())).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("duplicate client_id"), "got: {msg}");
        assert!(msg.contains("dup"), "got: {msg}");
    }

    #[test]
    fn duplicate_inline_only_is_error() {
        let err = load_clients(vec![client("x"), client("x")], None).unwrap_err();
        assert!(err.to_string().contains("duplicate client_id"));
    }

    #[test]
    fn unknown_field_in_file_is_error() {
        // `redirect_uri` (singular) is a typo for `redirect_uris`; serde would
        // silently drop it, leaving an unusable client. We reject it instead.
        let path = temp_json(
            "unknown",
            r#"[{"client_id":"x","redirect_uri":"https://typo.example/cb"}]"#,
        );
        let err = load_clients(vec![], Some(path.to_str().unwrap())).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown field"), "got: {msg}");
        assert!(msg.contains("redirect_uri"), "got: {msg}");
    }

    #[test]
    fn unknown_field_in_inline_client_is_error() {
        // Inline entries get the same strictness as file entries: a typo'd key
        // must not silently yield a client with empty redirect_uris.
        let inline = vec![serde_json::json!({
            "client_id": "x",
            "redirect_uri": "https://typo.example/cb"
        })];
        let err = load_clients(inline, None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown field"), "got: {msg}");
        assert!(msg.contains("redirect_uri"), "got: {msg}");
        assert!(msg.contains("clients[0]"), "got: {msg}");
    }

    #[test]
    fn malformed_inline_client_is_error() {
        let inline = vec![serde_json::json!({ "redirect_uris": ["https://rp/cb"] })];
        let err = load_clients(inline, None).unwrap_err();
        assert!(err.to_string().contains("clients[0]"), "got: {err}");
    }

    #[test]
    fn missing_file_is_error() {
        let err = load_clients(vec![], Some("/no/such/clients.json")).unwrap_err();
        assert!(err.to_string().contains("reading clients_file"));
    }

    #[test]
    fn malformed_json_is_error() {
        let path = temp_json("bad", "{ not json ]");
        let err = load_clients(vec![], Some(path.to_str().unwrap())).unwrap_err();
        assert!(err.to_string().contains("parsing clients_file"));
    }

    #[test]
    fn trailing_garbage_is_error() {
        let path = temp_json("trailing", r#"[{"client_id":"x"}] not-json"#);
        let err = load_clients(vec![], Some(path.to_str().unwrap())).unwrap_err();
        assert!(err.to_string().contains("parsing clients_file"));
    }
}
