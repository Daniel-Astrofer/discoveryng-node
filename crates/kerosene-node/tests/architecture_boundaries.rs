//! Structural guards for the node Clean Architecture boundaries.

use std::fs;
use std::path::{Path, PathBuf};

fn rust_sources(root: impl AsRef<Path>) -> Vec<PathBuf> {
    fn collect(path: &Path, files: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(path).expect("architecture directory") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                collect(&path, files);
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }

    let mut files = Vec::new();
    collect(root.as_ref(), &mut files);
    files
}

#[test]
fn required_architecture_directories_exist() {
    for directory in [
        "src/domain",
        "src/application",
        "src/api",
        "src/bootstrap",
        "../kerosene-ledger/src/domain",
        "../kerosene-ledger/src/application",
        "../kerosene-ledger/src/ports",
        "../kerosene-ledger/src/adapters",
        "../kerosene-ledger/src/consensus",
        "../kerosene-ledger/src/integrity",
    ] {
        assert!(
            Path::new(directory).is_dir(),
            "missing architecture directory: {directory}"
        );
    }
}

#[test]
fn capability_directories_are_real_modules() {
    for module in [
        "../kerosene-identity-core/src/domain/mod.rs",
        "../kerosene-membership/src/domain/mod.rs",
        "../kerosene-sync/src/domain/mod.rs",
        "../kerosene-discovery/src/adapters/mod.rs",
        "../kerosene-ledger/src/domain/mod.rs",
        "../kerosene-ledger/src/application/mod.rs",
        "../kerosene-ledger/src/ports/mod.rs",
        "../kerosene-ledger/src/adapters/mod.rs",
        "../kerosene-ledger/src/consensus/mod.rs",
        "../kerosene-ledger/src/integrity/mod.rs",
    ] {
        assert!(
            Path::new(module).is_file(),
            "missing module facade: {module}"
        );
    }
}

#[test]
fn crate_roots_do_not_rebuild_flat_modules_with_path_attributes() {
    for path in [
        "../kerosene-identity-core/src/lib.rs",
        "../kerosene-membership/src/lib.rs",
        "../kerosene-sync/src/lib.rs",
        "../kerosene-discovery/src/lib.rs",
        "../kerosene-ledger/src/lib.rs",
    ] {
        let source = fs::read_to_string(path).expect("crate root source");
        assert!(
            !source.contains("#[path"),
            "{path} must not reconstruct directory modules with #[path]"
        );
    }
}

#[test]
fn node_application_does_not_depend_on_http_or_runtime_wiring() {
    let forbidden = ["axum::", "axum_server", "std::env", "std::fs", "rustls::"];
    for path in rust_sources("src/application") {
        let source = fs::read_to_string(&path).expect("application source");
        for import in forbidden {
            assert!(
                !source.contains(import),
                "{} contains {import}",
                path.display()
            );
        }
    }
}

#[test]
fn node_domain_does_not_select_a_consensus_backend() {
    let source = fs::read_to_string("src/domain/consensus.rs").expect("consensus boundary");
    for forbidden in ["axum", "reqwest", "cometbft", "tokio", "std::net"] {
        assert!(
            !source.contains(forbidden),
            "consensus domain contains {forbidden}"
        );
    }
}
