# Launch Shield per-bid SP1 proof

This isolated workspace proves one commit-reveal bid relation for the
Meteora Dynamic Bonding Curve opening batch. The statement contains, in exact
order, `program_id`, `auction_id`, `bidder`, `bid_commitment`, `quote_mint`,
`quote_escrow`, and `max_bid_amount`. The first six fields are 32-byte byte
arrays; the final field is a little-endian `u64`, for exactly 200 public
bytes. The witness is the private `amount` followed by a 32-byte `salt`.

The v1 commitment is exactly
`SHA256(b"meteora-launch-shield:sealed-bid:v1" || program_id[32] ||
auction_id[32] || bidder[32] || amount.to_le_bytes()[8] || salt[32])`.
The guest asserts
`1 <= amount <= max_bid_amount`, recomputes this commitment, and commits only
the fixed public serialization. This is a relation and local executor
feasibility harness, not a generated or verified Groth16 proof.

From this directory:

```text
cargo test --workspace
cargo run -p launch-shield-proof-runner
```

The runner uses SP1 5.0.0 for the guest and the existing pinned 5.2.4 local
core-executor crates, matching the toolchain already used by this repository.

To derive the actual on-chain SP1 vkey hash from the built guest ELF using the
SP1 5.0.0 CPU setup path, run:

```text
cargo run -p launch-shield-proof-runner --features sp1-prover --bin launch-shield-vkey
```

The same optional CPU prover can produce a locally verified Groth16 bid proof:

```text
cargo run -p launch-shield-proof-runner --features sp1-prover --bin launch-shield-prove
```

It reads eight newline-separated values from stdin in this order: program ID,
auction ID, bidder, quote mint, quote vault (each 32-byte hex), maximum amount,
private amount (decimal), and private salt (32-byte hex). The output contains
the commitment, 260-byte on-chain proof, 200-byte public statement, and vkey
hash. The amount and salt are not printed. Keep them client-side and do not
place them in shell arguments, logs, or public files.

This is intentionally opt-in because the SDK/prover dependency graph is much
larger than the relation and local-execution tests. Do not substitute a
fixture or guessed hash for the command's output.