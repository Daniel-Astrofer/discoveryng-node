# Disposable Node/Core release-read qualification

The observer consumes Contracts 0.3.0 from its immutable published Git revision.
The `core_bank_probe` example exercises the actual `BankTransport` and
`ReleaseObserver` paths against Core's actual Bank producer, not a fake Bank
adapter. It permits only a loopback endpoint, uses a newly generated disposable
Node signing identity/private state directory, and proposes only an `unknown`
observation. It cannot authorize an aggregate compatible report or produce BFT
release authority. Do not use production credentials in this lab.

Build from this Node branch:

```sh
cargo build --locked -p kerosene-release-observer --example core_bank_probe
cargo clippy --locked -p kerosene-release-observer --lib --tests --examples -- -D warnings
```

Then, from the corresponding Core branch, run its explicit integration task:

```sh
KEROSENE_NODE_BANK_PROBE=/absolute/path/to/node/target/debug/examples/core_bank_probe \
  ./gradlew --no-daemon -p verification nodeCoreWireTest test
```

Core's test generates disposable server/client certificates and a separate Bank
Ed25519 key, starts an embedded Tomcat with mandatory client authentication on
loopback/ephemeral port, pins the allowed Node client's SPKI, and invokes the
compiled probe. The Node production path generates a random challenge, validates
the target/status/sequence bindings and the pinned Bank signature, caches the
signed negative read, and refuses aggregate signing with `Incompatible`.

The probe configuration and client identity are local temporary test files;
private PEM/config files use owner-only permissions. No credential is printed,
committed or installed. The server closes after the test and disposable observer
state is removed by its temporary-directory owner. Only public diagnostic
success/failure text is returned. This task is separate from Core's default
tests and fails when its explicitly built probe is absent; it is not silently
skipped or treated as complete release qualification.

This proves interoperability and negative-signing behavior. It does **not** prove
new-release compatibility, Vault independent rebuild, financial maintenance,
ordered consensus, complete Cell installation/update or real CSI recovery.
