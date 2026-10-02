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

As of 2026-09-30, the `succinct-1.96.0-64bit-v2` toolchain selected by
`cargo-prove` v6.8.1 produced
`0x00c251c2fcd8917e273d863fa9b2d15495d1992f4a5289c905b8be6fe9ddaca3`; the
`succinct-1.94.0-64bit` toolchain selected by v6.7.0 produced
`0x00df92ceaccde0ed7c057f1a3634516b1aa891539a951781c6a95141a87f8295`. Both
differ from the pinned release hash. The earlier pre-v2 1.96 archive lacks the
RISC-V target required for this guest.

The official SP1 v6.2.1 CLI source identifies the compiler archive tag
`succinct-1.93.0-64bit`. Only that compiler asset was taken from the older
release: the guest, SDK, and vkey CLI used for the matching reproduction all
remained at SP1 6.8.1. The Linux archive SHA-256 is
`99e68dd864dd7ee9688333346b428452c705d82a11098e51146389417e0c82c6`. With that
compiler (`rustc 1.93.0-dev`), the v6.8.1 guest was rebuilt using
`cargo prove build --locked`. The 125,200-byte ELF has SHA-256
`42ff19cc697dbe86803299b286eb84b5b74065edab32c83d68a4041b3fad70a4`. A
local-only SP1 6.8.1 CLI vkey check with `SP1_PROVER=light` returned the
pinned hash, `0x0087f6df27e09f077f54cfab0ef64d46bf1311df3dd721869ca7c13fc628c754`.
No proof was generated or submitted in this check.

The retained guest ELF is from the pre-migration SP1 5.0.0 build: it reports
`rustc version 1.85.0-dev`, and the official `cargo-prove` v5.0.0 source maps
to `succinct-1.85.0-v2`. However, a local-only SP1 6.8.1 light vkey check
against that exact ELF failed with `ELF has a segment that is below the
STACK_TOP`. This rules out reproducing the pin through that CLI path; the
original key-generating ELF was not retained. The local commit that pinned
`0x0087…` records the SP1 6.8.1 light
helper but no compiler version or key-generating ELF; the hub's earlier
preflight branch says no vkey or proof had yet been generated. Thus 1.93.0 is a
matching reproduction, but the original compiler and ELF remain unproven.

The official v6.7.0 CLI maps to `succinct-1.94.0-64bit`, and v6.8.0/v6.8.1
map to `succinct-1.96.0-64bit-v2`; both tested mappings produced different
hashes. Keep the verifier pin unchanged. The network runner stops before proof
submission when the locally derived key differs; a matching key alone does
not authorize proof submission.

Run the local-only network vkey check without submitting a proof:

```sh
env -u LD_AUDIT RUSTUP_TOOLCHAIN=stable cargo run --locked \
  --manifest-path launch-shield/proof/Cargo.toml \
  -p launch-shield-proof-runner --features sp1-network \
  --bin launch-shield-prove-network -- --check-vkey
```

The full `sp1-prover` build is blocked because the SP1 6.8.1 native FFI pins
`golang.org/x/crypto v0.45.0`, which the package firewall rejects for a critical
advisory. A newer version was tested only in an isolated FFI copy; the complete
proof workspace was not validated with it, and the project dependency pins
remain unchanged.