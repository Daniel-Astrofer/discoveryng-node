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
        "domain",
        "application",
        "api",
        "bootstrap",
        "../ledger/domain",
        "../ledger/application",
        "../ledger/ports",
        "../ledger/adapters",
        "../ledger/consensus",
        "../ledger/integrity",
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
        "../identity/domain/mod.rs",
        "../membership/domain/mod.rs",
        "../sync/domain/mod.rs",
        "../discovery/adapters/mod.rs",
        "../ledger/domain/mod.rs",
        "../ledger/application/mod.rs",
        "../ledger/ports/mod.rs",
        "../ledger/adapters/mod.rs",
        "../ledger/consensus/mod.rs",
        "../ledger/integrity/mod.rs",
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
        "../identity/lib.rs",
        "../membership/lib.rs",
        "../sync/lib.rs",
        "../discovery/lib.rs",
        "../ledger/lib.rs",
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
    for path in rust_sources("application") {
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
    let source = fs::read_to_string("domain/consensus.rs").expect("consensus boundary");
    for forbidden in ["axum", "reqwest", "cometbft", "tokio", "std::net"] {
        assert!(
            !source.contains(forbidden),
            "consensus domain contains {forbidden}"
        );
    }
}
