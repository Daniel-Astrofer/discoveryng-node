# Node repository layout

The Node repository is organized around deterministic core rules and explicit
runtime edges. Source files are placed by responsibility; public crate roots
are compatibility facades, not locations for implementation.

```text
crates/kerosene-identity-core/
  src/domain/identity.rs          network-bound root identity
crates/kerosene-membership/
  src/domain/membership.rs        roster and joint-consensus verification
crates/kerosene-sync/
  src/domain/lifecycle.rs         lifecycle and snapshot verification
crates/kerosene-discovery/
  src/adapters/discovery.rs       Tor/mTLS discovery and peer persistence
crates/kerosene-ledger/
  src/domain/                    deterministic financial state rules
  src/application/               reconciliation, replication and gates
  src/ports/                     storage and observer capabilities
  src/adapters/                  in-memory and Sled implementations
  src/consensus/                 certificates, chain and membership gates
  src/integrity/                 canonical state-root computation
crates/kerosene-node/
  src/domain/consensus.rs        consensus boundary, without a backend lock-in
  src/application/service.rs     lifecycle, readiness and membership workflows
  src/api/http.rs                HTTP request/response translation only
  src/bootstrap/runtime.rs       environment wiring, Tor loop and mTLS server
  src/main.rs                    minimal executable entry point
```

## Dependency rule

```text
binary → bootstrap → API / adapters → application → domain
```

Domain code must remain deterministic and independently testable. Runtime I/O,
environment variables, filesystem access, Tor, mTLS, HTTP and Sled persistence
belong to adapters or bootstrap. The API may translate a protocol request, but
must not perform lifecycle, membership or readiness transitions itself.

`peer-store/`, `ledger-data/`, private keys and environment files are ignored
runtime material. They must never be committed.
