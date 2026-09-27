# Dark DBC SP1 v5 guest feasibility spike

This is an experimental SP1 v5 guest, not a production proof system or Solana
program. The `relation` crate is `no_std` and is shared by the guest and the
root host tests.

The guest's private witness is a bid amount, bid randomness, claim secret, and
two canonical Pedersen openings. Its public statement contains the program,
auction, bidder, bid commitment, token mint, confidential vault, transfer
context digest, auditor key, and exact serialized low/high ciphertext pair.
It checks:

- a test-only SHA-256 bid-commitment schema over the program, auction, bidder,
  amount, bid randomness, and claim secret;
- `C = amount_component*G + opening*H` and `D = opening*auditor_key` for each
  serialized Ristretto ciphertext component; and
- `amount = low + (high << 16)` by deriving the two components from the bounded
  amount.

The public-values payload is a fixed 384-byte statement; it does not include
the amount, openings, randomness, or claim secret. The guest cannot establish
that account/context bytes are authentic. A future on-chain program must
compare every public field to the Token-2022 operation it accepted, including
the exact proof-context state and ciphertext pair.

The SHA-256 commitment schema and fixed fixture values are for feasibility
testing only. They do not select a production commitment, implement a client
wallet, or prove a complete funded-bid/claim relation. This does not validate
the Token-2022 processor, a DKG, confidential-vault custody, a Solana verifier,
transaction size, or compute budget.

## Local commands

The guest and build tooling use `cargo-prove`, `sp1-zkvm`, and `sp1-build`
5.0.0; the local host harness uses `sp1-core-executor`, `sp1-core-machine`,
and `sp1-stark` 5.2.4 with Rust 1.90. It calls the SP1 core executor directly,
without compiling the proof-orchestration SDK. Compatibility with a particular
Solana verifier has not been established:

```sh
cd dark-dbc-proof-spike/program
PATH="$HOME/.sp1/bin:$PATH" cargo prove build
```

The host runner builds the guest, locally executes one valid fixture through
the SP1 core executor, checks that the public values equal the expected
statement, then expects a mutated amount to fail guest execution:

```sh
cd dark-dbc-proof-spike
cargo run --release -p dark-dbc-funding-script
```

The runner calls `Executor::run_fast`; it does not generate a proof or contact
a remote prover. A successful guest build or local execution is feasibility
evidence, not an on-chain verification result.

The tested run produced the expected 384 public bytes and reported 16,789,467
guest instructions for the valid fixture. The mutated-amount fixture failed
inside the guest as expected. This instruction count is not a Solana compute
unit measurement.