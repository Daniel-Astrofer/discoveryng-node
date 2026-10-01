# ADR-0002: Separate ordered release governance

Status: proposed. This does not settle ADR-0001 ledger/finality ownership.

The new `kerosene-release-observer` module fetches real Bank evidence over
mTLS, checks pinned Ed25519 signatures and maintains a local durable signing
sequence. Neither those signatures nor a deploy threshold prove that a BFT
state machine ordered or committed a release. The existing generic consensus
port is not sufficient evidence: a height and block hash alone do not contain
a cryptographically verifiable commit certificate.

Propose a separately bounded governance state machine, independent of the
financial ledger: `(networkId, sequence, canonicalReleaseDigest,
canonicalReportDigest, rosterEpoch)`. It must reject duplicate or decreasing
sequences deterministically, bind policy and membership epoch, and commit
only through a configured consensus backend. Acceptance across the platform
and pinned CometBFT protocol compatibility are prerequisites to implementation.

A future certificate API must expose backend, network, height, round, block
and application hashes, roster/validator-set hash, signed voting power and
actual commit signatures; consumers must independently validate them against
trusted membership. It must be a new versioned contract with replay, fork,
roster-transition and restart vectors. It cannot retrofit quorum report
signatures into a commit certificate.

Until that backend and certificate verification exist, observer discovery and
signed read responses explicitly return `commitCertificate: "unavailable"`.
No governance commit route is exposed. Financial ledger code is unchanged.
