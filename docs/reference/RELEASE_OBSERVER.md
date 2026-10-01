# Bank release observer integration

Authoritative wire contract and exact Core Bank producer interface:
`contracts/docs/reference/release-observer-v1.md` in the sibling checkout.
Rust imports: `kerosene_contracts::release` (package 0.3.0).
The dependency is pinned to published Contracts Git revision
`d1de045527242596bbaf74000049a92d19324ccf` in the `Daniel-Astrofer/contracts`
repository. Node builds do not depend on a sibling checkout.

Set `KEROSENE_RELEASE_OBSERVER_CONFIG` to a JSON file:

```json
{
  "observerId": "bank-001",
  "networkId": "bank-main",
  "signingKeyDerPath": "/run/credentials/observer.pk8.der",
  "statePath": "/var/lib/kerosene/release-observer",
  "banks": [{
    "observerId": "bank-001",
    "endpoint": "https://bank.internal",
    "publicKeyDerBase64": "<trusted Bank Ed25519 SPKI DER base64>"
  }]
}
```

The Node signer key is dedicated Ed25519 PKCS8 DER and must already exist.
Put its public SPKI DER under `observerId` in deploy's externally trusted
validator roster. Bank producer keys are separately pinned under `banks`;
never infer trust from a response's included key. Each report observation
needs a configured Bank source. Credentials must be regular files with no
group/other permissions. Reuse `KEROSENE_TLS_CLIENT_IDENTITY_PEM`,
`KEROSENE_TLS_CLIENT_CA_PATH`, and the required `socks5h` proxy for outbound
Bank mTLS. Production ingress reuses Node's mandatory mTLS listener. An
observer configured on the Vault plane or another network fails startup.

The cached GET is unsigned and wraps signed observations. Run verify first
with the complete release lock and unsigned v2 candidate report. All proposed
compatible observations are independently checked against fresh, real Bank
reads; signed synthetic sources are rejected. Use the same unsigned report
for every quorum signer and merge only their signature arrays. Individual
read signatures never satisfy that aggregate threshold.

Preserve `statePath` across restarts and protect it as authority state. Use an
absolute real directory with POSIX mode 0700 and no symlink components; unsafe
existing permissions are rejected rather than silently repaired. The
high-water mark is flushed before signature exposure. A reserved sequence
cannot be retried, even if the response was lost. Only one verified target's
reads are cached, bounding retained evidence. It is valid to refresh read
evidence without signing the sequence again. Never roll back the high-water
mark or reuse a state directory for another trust configuration.

Authenticated `incompatible` and `unknown` Bank reads can be queried and cached
to expose operator blockers. Such local observations cannot authorize aggregate
report signing and do not consume a signing sequence. Proposed read status is
still compared with fresh independently signed Bank evidence, never trusted as
an operator assertion.

Observer compatibility signatures do not supply a commit certificate; this
is explicitly unavailable. See proposed ADR-0002 for ordered governance.
Bank producer implementation in Core must land before enabling this runtime;
there is no local compatibility fallback.
