# Repository boundary

This repository is the canonical source for Kerosene node identity, discovery
and authenticated membership.

Node consumes versioned protocols from `kerosene-contracts` and uses fake Core
and Vault adapters in CI. It must not read source files from the archived
monorepo or another service repository.

## Owned here

- persistent node identity and member identifiers;
- authenticated peer discovery and endpoint persistence;
- signed membership manifests, roster transitions and membership readiness;
- read-only operational visibility for those responsibilities.

## Owned elsewhere

- FROST shares, DKG, custody and signing: `kerosene-vault`;
- schemas and wire contracts: `kerosene-contracts`;
- Auth, financial ledger and business rules: application services;
- consensus/finality engines and their deployment: separate integration scope;
- manifests, secrets references and runtime orchestration: `kerosene-deploy`.

Synchronization and consensus adapters may exist at the edge of this
repository, but they do not make Node the owner of ledger state, financial
authority or consensus finality. CometBFT work remains deferred and is not part
of this boundary-organization change.
