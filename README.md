# Kerosene Node

Rust runtime for Kerosene identity, Tor-only peer discovery and authenticated
membership.

It does not hold FROST shares, sign financial transactions, implement Auth/KFE
business rules or deploy the platform. Those responsibilities belong to Vault,
Core and Deploy respectively.

The Bank and Vault discovery planes are independent. A single Core node or a
single Vault node can start locally without pretending to have quorum:

- `local_ready`: identity, mTLS listener and local state are available;
- `member_ready`: the local root key belongs to the verified roster;
- `quorum_ready`: enough currently live members of the same plane exist;
- `financial_ready`: an integration-facing readiness signal; it does not make
  Node the owner of ledger state or financial policy.

An isolated member reports `ACTIVE_LOCAL_WAITING_FOR_PEERS`. It stays
operational for local administration and discovery, but cannot exercise
financial authority.

## Workspace

```text
crates/
├── kerosene-identity-core  # persistent Ed25519 root identity
├── kerosene-discovery      # Tor/mTLS handshake and persistent peer store
├── kerosene-membership     # signed manifests and OLD -> JOINT -> NEW
├── kerosene-sync           # external synchronization boundary traits
└── kerosene-node           # HTTPS API and discovery runtime
└── kerosene-rsctl          # operator CLI; no embedded authority
```

Wire types come from a commit-pinned `kerosene-contracts` dependency.
CometBFT/ABCI consensus is outside Node's identity/discovery/membership
ownership and is tracked separately in
[issue #2](https://github.com/Daniel-Astrofer/kerosene-node/issues/2); this
repository does not substitute a fake consensus engine.

## Run

Production startup requires a v3 onion endpoint, Tor `socks5h`, a
`GenesisTrustBundleV1`, a server certificate/key and a CA used to require client
certificates. See [operations](docs/OPERATIONS.md) for the complete environment
contract and progressive bootstrap procedure.

```bash
cargo run --locked --features production -p kerosene-node
```

## Verify

```bash
cargo fmt --all -- --check
cargo check --workspace --features production
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Security assumptions and release gates are documented in
[THREAT_MODEL.md](docs/THREAT_MODEL.md) and
[PRODUCTION_GATES.md](docs/PRODUCTION_GATES.md).

Compact documentation:

- [English](docs/en/README.md)
- [Português](docs/pt-BR/README.md)
- [English quickstart](docs/en/QUICKSTART.md)
- [Início rápido em português](docs/pt-BR/QUICKSTART.md)

## Administrative CLI

`kerosene-rsctl` provides read-only health, peers, membership, quorum,
compatibility and artifact diagnostics. It also supports an offline
create/sign/verify/publish membership ceremony. Private identity files must be
mode `0600`; secrets are never accepted as inline command arguments.

Profiles are loaded from `~/.config/kerosene/profiles.toml`, or from the path in
`KEROSENE_PROFILES_FILE`. They contain endpoints and credential file references,
never tokens or private key contents. A local Vault Admin API can be reached
through `--unix-socket /run/kerosene/vault-admin.sock`; Unix socket mode cannot
be combined with mTLS or proxy flags. Network administration requires an
operator PEM with private file permissions, its CA and `socks5h://` for Onion
endpoints.

```bash
cargo run -p kerosene-rsctl -- node status \
  --endpoint https://example.onion:8800 --output json-pretty
cargo run -p kerosene-rsctl -- membership verify \
  --manifest signed.json --trust-bundle genesis.json
```
