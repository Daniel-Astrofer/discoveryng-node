//! Interpretation of observed service metadata; HTTP success alone is not readiness.

use anyhow::{bail, Result};
use kerosene_contracts::{ADMIN_CONTRACT_VERSION, DISCOVERY_CONTRACT_VERSION};
use serde_json::{json, Value};

/// Compares advertised wire versions, without claiming release or financial compatibility.
pub fn compatibility_report(manifest: &Value, vault: Option<&Value>) -> Value {
    let node_version = manifest.get("contract_version").and_then(Value::as_str);
    let vault_version = vault
        .and_then(|v| v.get("contract_version"))
        .and_then(Value::as_str);
    let compatible = node_version == Some(DISCOVERY_CONTRACT_VERSION)
        && vault.is_none_or(|_| vault_version == Some(ADMIN_CONTRACT_VERSION));
    json!({
        "compatible": compatible,
        "scope": "advertised_wire_contract_versions",
        "node": {"expected": DISCOVERY_CONTRACT_VERSION, "observed": node_version},
        "vault": vault.map(|_| json!({"expected": ADMIN_CONTRACT_VERSION, "observed": vault_version})),
    })
}

/// Requires explicit readiness gates and an empty blocker list; missing fields fail closed.
pub fn doctor_report(live: Value, readiness: Value, vault: Option<Value>) -> Value {
    let node_ready = [
        "live",
        "local_ready",
        "member_ready",
        "quorum_ready",
        "financial_ready",
    ]
    .iter()
    .all(|key| readiness.get(key).and_then(Value::as_bool) == Some(true));
    let no_blockers = readiness
        .get("financial_blockers")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty);
    let vault_ready = vault.as_ref().is_none_or(|v| {
        v.get("local_ready").and_then(Value::as_bool) == Some(true)
            && v.get("financial_ready").and_then(Value::as_bool) == Some(true)
    });
    json!({
        "healthy": live.get("live").and_then(Value::as_bool) == Some(true)
            && node_ready && no_blockers && vault_ready,
        "scope": "configured_endpoints",
        "live": live, "readiness": readiness, "vault": vault,
    })
}

/// Causes a failing process status after the caller has printed the diagnostic evidence.
pub fn require_success(report: &Value, field: &str) -> Result<()> {
    if report.get(field).and_then(Value::as_bool) != Some(true) {
        bail!("diagnostic failed: {field}=false; inspect the report");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready() -> Value {
        json!({"live": true, "local_ready": true, "member_ready": true,
            "quorum_ready": true, "financial_ready": true, "financial_blockers": []})
    }

    #[test]
    fn each_node_gate_is_required() {
        assert_eq!(
            doctor_report(json!({"live": true}), ready(), None)["healthy"],
            true
        );
        for key in [
            "live",
            "local_ready",
            "member_ready",
            "quorum_ready",
            "financial_ready",
        ] {
            for value in [Some(json!(false)), Some(json!("true")), None] {
                let mut node = ready();
                match value {
                    Some(v) => {
                        node[key] = v;
                    }
                    None => {
                        node.as_object_mut().unwrap().remove(key);
                    }
                }
                assert_eq!(
                    doctor_report(json!({"live": true}), node, None)["healthy"],
                    false
                );
            }
        }
    }

    #[test]
    fn blockers_liveness_and_vault_are_required() {
        for blockers in [json!(["STALE"]), Value::Null, json!(false)] {
            let mut node = ready();
            node["financial_blockers"] = blockers;
            assert_eq!(
                doctor_report(json!({"live": true}), node, None)["healthy"],
                false
            );
        }
        assert_eq!(doctor_report(json!({}), ready(), None)["healthy"], false);
        for vault in [
            json!({}),
            json!({"local_ready": true, "financial_ready": false}),
        ] {
            assert_eq!(
                doctor_report(json!({"live": true}), ready(), Some(vault))["healthy"],
                false
            );
        }
        let vault = json!({"local_ready": true, "financial_ready": true});
        assert_eq!(
            doctor_report(json!({"live": true}), ready(), Some(vault))["healthy"],
            true
        );
    }

    #[test]
    fn versions_must_match_and_be_present() {
        let node = json!({"contract_version": DISCOVERY_CONTRACT_VERSION});
        let vault = json!({"contract_version": ADMIN_CONTRACT_VERSION});
        assert_eq!(
            compatibility_report(&node, Some(&vault))["compatible"],
            true
        );
        assert_eq!(compatibility_report(&node, None)["compatible"], true);
        for bad in [
            json!({}),
            json!({"contract_version": "unknown"}),
            json!({"contract_version": 1}),
        ] {
            assert_eq!(
                compatibility_report(&bad, Some(&vault))["compatible"],
                false
            );
            assert_eq!(compatibility_report(&node, Some(&bad))["compatible"], false);
        }
        assert!(require_success(&json!({"healthy": false}), "healthy").is_err());
        assert!(require_success(&json!({}), "compatible").is_err());
        assert!(require_success(&json!({"compatible": true}), "compatible").is_ok());
    }
}
