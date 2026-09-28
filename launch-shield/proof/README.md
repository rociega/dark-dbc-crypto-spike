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
the fixed public serialization. This relation remains unchanged in the SP1 v6
migration.

From this directory:

```text
cargo test --workspace
cargo run -p launch-shield-proof-runner --features sp1-executor
```

The guest, executor, SDK, and build tooling are pinned to SP1 6.8.1 (circuit
version 6.1.0). The on-chain verifier uses the matching official 492-byte
Groth16 key artifact.

To derive the on-chain SP1 vkey hash from the built guest ELF, run:

```text
cargo run -p launch-shield-proof-runner --features sp1-prover --bin launch-shield-vkey
```

The optional CPU prover can produce a locally verified Groth16 bid proof:

```text
cargo run -p launch-shield-proof-runner --features sp1-prover --bin launch-shield-prove
```

It reads eight newline-separated values from stdin in this order: program ID,
auction ID, bidder, quote mint, quote vault (each 32-byte hex), maximum amount,
private amount (decimal), and private salt (32-byte hex). The output contains
the commitment, 356-byte on-chain proof, 200-byte public statement, and vkey
hash. The proof is framed as a 4-byte verifier-key selector, 32-byte exit code,
32-byte verifier-key root, 32-byte nonce, and 256-byte Groth16 proof. The amount
and salt are not printed. Keep them client-side and do not place them in shell
arguments, logs, or public files.

This is intentionally opt-in because the SDK/prover dependency graph is much
larger than the relation and local-execution tests. Do not substitute a
fixture or guessed hash for the command's output.

As of 2026-09-28, guest execution is validated, but vkey derivation and proof
generation are not. The full `sp1-prover` build is blocked because the SP1 6.8.1
native FFI pins `golang.org/x/crypto v0.45.0`, which the package firewall
rejects for a critical advisory. A newer version was tested only in an isolated
FFI copy; the complete proof workspace was not validated with it, and the
project dependency pins remain unchanged.