use std::fs;
use std::path::Path;

use anyhow::{bail, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Computes a file's SHA-256 digest and optionally compares it with an expected digest.
///
/// # Errors
/// Returns file-read errors or a mismatch error when `expected` differs.
pub fn artifact_verify(path: &Path, expected: Option<&str>) -> Result<Value> {
    let digest = hex::encode(Sha256::digest(fs::read(path)?));
    if expected.is_some_and(|value| !value.eq_ignore_ascii_case(&digest)) {
        bail!("artifact SHA-256 mismatch");
    }
    Ok(json!({"valid": true, "sha256": digest, "path": path}))
}
