# Agent guide — Kerosene Node

## Scope

Node owns deterministic identity, discovery, membership and readiness behavior.
Ledger/finality ownership remains governed by the proposed ADR until accepted.

## Documentation

- Start at `docs/README.md`.
- Use `architecture/`, `reference/`, `operations/`, `security/` and `decisions/`
  for their respective concerns.
- Do not describe ledger/finality ownership as settled before ADR-0001 is
  accepted across the platform.

## Safety and integration

- Keep consensus deterministic and independently testable.
- Treat identity, discovery, membership and readiness as distinct states.
- Pin CometBFT compatibility; use fake KFE/Vault adapters in CI.
- Protocol changes consume versioned `kerosene-contracts` artifacts.

## Verification

Run Rust format, check, clippy and tests. Never use production credentials.
