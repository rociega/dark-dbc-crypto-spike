# Launch Shield: DBC anti-sniping MVP

This is the active implementation target: a sealed-bid opening auction for a
Meteora Dynamic Bonding Curve (DBC) launch. It is not the later private-claims
mixer described in `DARK_DBC_REDESIGN.md`.

## Flow implemented in the program

- The creator creates an auction against a fixed DBC config and classic SPL
  quote mint. The DBC pool does not exist during bidding.
- Each bidder commits to a SHA-256 hash of the program, auction, bidder, hidden
  amount, and private 32-byte salt. Each commitment also carries an SP1
  Groth16 proof that the committed amount is in `1..=max_bid_amount`.
- Every bidder escrows the same public maximum quote amount plus a fixed SOL
  reveal bond. This keeps the amount private during commit while ensuring the
  locked amount covers every valid bid.
- During the reveal window, the bidder opens the commitment. The contract
  returns the unused quote escrow and the bond; the revealed amount joins the
  public aggregate.
- After the window, the creator settles once: top-level DBC pool initialization,
  the wrapper's preparation instruction, one top-level DBC `swap2` ExactIn, and
  the wrapper's finalization instruction are atomic in one transaction. The
  program records the received base-token amount and pays each revealed bidder
  `floor(amount_i * Y / Q)`.
- If settlement does not happen within 256 slots after the reveal deadline,
  anyone can cancel. Revealed bidders can then permissionlessly reclaim their
  amounts; unrevealed deposits and bonds remain forfeitable to the creator.

This is bonded commit-reveal, not permanent privacy: amounts become public when
revealed. It prevents an observer from seeing bid sizes during the opening
window; it does not hide bids from bidders themselves or hide the later reveal.

## DBC settlement constraint

The settlement preparation instruction intentionally does **not** include the
DBC pool account. Meteora's rate-limiter scan can treat an earlier non-DBC
instruction containing the pool account as a possible extra swap. The
preparation instruction instead verifies the initialization, following swap,
and finalization through the Instructions sysvar, while deriving the pool
address locally. It funds the creator's quote-token ATA immediately before the
single top-level DBC swap. The pool account is checked during finalization,
after the swap.

The instruction sequence is:

```text
DBC initialize_virtual_pool_with_spl_token (top-level)
Associated Token Account create for the program's base-token vault
Launch Shield prepare_settlement (does not list the DBC pool account)
DBC swap2 ExactIn (top-level; Instructions sysvar as one remaining account)
Launch Shield finalize_settlement
```

The source inspection used Meteora's public repository at commit
`3b540e94b5b20ba37733de6e25f58522a0cd8961`, including its `swap2` account
definition and release IDL. The parser requires the no-referral sentinel,
Anchor event-CPI accounts, and the single Instructions sysvar remaining account.
That is 15 account metas through the DBC program account (including the
optional-referral sentinel), followed by the Instructions sysvar as meta 16.
This is not proof that the deployed program matches that source. Before
deployment, pin and compare the deployed DBC build and regenerate the
instruction bindings from that matching source.

### Live DBC deployment preflight

Read-only RPC checks on 2026-09-27 found the DBC program executable on both
mainnet-beta and devnet. The program-data PDA is
`HUfnSSiJxgspQm6C1rkqv6L3XgVtn7AESApgCQpCXCYh` on both clusters, but the
deployed executable bytes differ:

| Cluster | Program deployment slot | Executable bytes | SHA-256 |
|---|---:|---:|---|
| mainnet-beta | 445503633 | 2,326,577 | `4c26a8a5da99f8ce932fa0300c46675b527090021fbb74214c9486bedda9f23b` |
| devnet | 503167099 | 1,983,568 | `f5ccbb01e37165d16108bda0259fb3acbfca29305e23098c3b248e50c22979f0` |

Hashes cover the executable bytes after the upgradeable-loader metadata. These
observations do not identify either binary's source revision; each target
cluster's DBC compatibility still needs an exact build/source match and runtime
settlement test.

## Program interface

Instruction data starts with one tag byte; integers are little-endian. State
and bid PDAs are derived from `auction`/`bid` seeds; the quote-vault authority
uses `vault`. The code is in `program/src/`.

| Tag | Instruction | Payload after tag |
|---:|---|---|
| 0 | `initialize_config` | 66 ASCII bytes: SP1 vkey hash `0x` + 64 hex digits |
| 1 | `initialize_auction` | auction ID `[32]`, then commit slots, reveal slots, max bid, SOL bond, minimum-output numerator, minimum-output denominator (`u64 LE` each) |
| 2 | `commit_bid` | commitment `[32]`, 260-byte SP1 Groth16 proof, 200-byte public statement |
| 3 | `reveal_bid` | amount (`u64 LE`), salt `[32]` |
| 4 | `forfeit_unrevealed` | empty |
| 5 | `prepare_settlement` | empty |
| 6 | `finalize_settlement` | empty |
| 7 | `claim` | empty |
| 8 | `cancel_unsettled` | empty |
| 9 | `refund_cancelled_bid` | empty |

The 200-byte proof statement is exactly
`program_id || auction_id || bidder || commitment || quote_mint || quote_vault
|| max_bid_amount_le`. Its schema and commitment domain are shared with the
guest in `proof/relation`.

Account order for the current processor (all program/sysvar accounts use their
canonical IDs):

- Tag 0: upgrade-authority signer, config PDA, this program's ProgramData
  account, System Program.
- Tag 1: creator signer, config PDA, auction PDA, quote mint, pre-created
  quote vault, DBC config, System Program.
- Tag 2: auction, config PDA, bid PDA, bidder signer, bidder quote account,
  quote vault, quote mint, vault authority PDA, SPL Token Program, System
  Program.
- Tag 3: auction, bid PDA, bidder signer, quote vault, bidder quote account,
  quote mint, vault authority PDA, SPL Token Program.
- Tag 4: auction, bid, creator, creator quote account, quote vault, quote mint,
  vault authority PDA, SPL Token Program.
- Tag 5: auction, quote vault, vault authority PDA, quote mint, creator signer,
  creator quote ATA, base mint, program base-output ATA, DBC config, DBC base
  vault, DBC quote vault, SPL Token Program, Instructions sysvar. Do **not**
  include the DBC pool account in this instruction.
- Tag 6: auction, creator signer, DBC pool, base mint, program base-output ATA,
  Instructions sysvar.
- Tag 7: auction, bid, bidder signer, program base-output ATA, bidder base-token
  destination, base mint, vault authority PDA, SPL Token Program.
- Tag 8: auction.
- Tag 9: auction, bid, bidder, bidder quote-token destination, quote vault, quote
  mint, vault authority PDA, SPL Token Program.

The quote vault must already be an initialized classic SPL token account whose
token authority is the auction's `vault` PDA. The base-output vault and creator
quote account are associated token accounts. All token accounts must use the
classic SPL Token program; Token-2022 mints are not accepted.
For `claim`, the destination must be an initialized classic SPL token account
for the same base mint and owned by the signing bidder.
Claims floor each bidder's pro-rata share independently. With the eight-bid
cap, up to seven base-token base units can remain as rounding dust in the
program vault; the MVP does not currently sweep that dust.

`initialize_config` is one-shot, requires the deployed program's upgrade
authority to sign, and stores the supplied verifier hash. The hash is not yet
generated or pinned in this workspace. Do not expose a deployment to users
until the intended SP1 vkey is independently produced, verified against the
guest ELF, and configured by the trusted deployer.

Program-owned config, auction, and bid PDAs handle third-party pre-funding.
When a target system account already has lamports, the program tops it up to
rent if needed, then uses signed `allocate`/`assign` instead of `create_account`,
which would fail for an already-funded address.

## Proof tooling

The optional SP1 host binaries are in `proof/script` and are intended to run as:

```sh
cargo run --manifest-path launch-shield/proof/Cargo.toml \
  -p launch-shield-proof-runner --features sp1-prover --bin launch-shield-vkey
cargo run --manifest-path launch-shield/proof/Cargo.toml \
  -p launch-shield-proof-runner --features sp1-prover --bin launch-shield-prove
```

These use SP1 5.0.0 and need its matching Succinct Rust toolchain installed
(`cargo prove install-toolchain` after installing the matching `cargo-prove`).
The prover reads the amount and salt only from stdin, verifies its generated
Groth16 proof locally, and emits the commitment, proof, public values, and vkey
hash. In this environment the guest ELF and metadata-only host check build, but
the full vkey command has not completed. A long `sp1-prover` build was
interrupted by a workspace restart; the observed cgroup OOM counters remained
zero. No vkey hash or Groth16 proof has been generated here, so treat both
commands as unverified until they complete. Do not put bid amounts or salts in
command-line arguments or shell history.

## Verification and remaining gates

Run native tests with a Rust toolchain on `PATH`:

```sh
cargo test --manifest-path launch-shield/program/Cargo.toml
cargo test --manifest-path launch-shield/proof/Cargo.toml -p launch-shield-proof-relation
```

The on-chain crate's 23 unit tests and the shared proof-relation crate's 8 tests
pass. Host-side tests also cover cancellation deadline/settlement guards,
claim eligibility, and cancelled-refund eligibility through the same pure
validation helpers used by the instruction handlers; they do not simulate
token CPIs or validator rollback. Settlement's same-pool swap guard scans only
the transaction's encoded top-level instruction count, rather than probing all
65,536 possible indices. Tests exercise serialized Instructions-sysvar layouts
for the valid five-instruction settlement sequence and for duplicate same-pool
swap rejection.
The SP1 guest ELF builds, and a metadata-only check of the host runner
succeeds with the matching toolchain. A fresh SBF release build of the current
program source completed for `sbfv1` with Solana CLI 1.18.26 and platform-tools
v1.52. The stripped `launch_shield_program.so` is 338,704 bytes (SHA-256
`57ec0b3df861778e9f1549ddd8bb15a484326033ae5a57f3f78beb048478aee8`). Its
`sp1-solana` and `groth16-solana` dependencies compile for SBF. This is a build
artifact only: a local validator smoke test could not complete because both
startup attempts were OOM-killed under the environment's 1.6-GiB memory cap
before RPC readiness, so validator loading and runtime behavior remain
unverified. No vkey or Groth16 proof has been generated or verified. No DBC
transaction simulation, deployed-version comparison, verifier compute
measurement, or production deployment has been completed.

The first usable release still needs a proof-producing client and generated
vkey; a pinned DBC deployment/IDL; SBF and transaction-size/compute validation;
and validator tests for escrow, settlement rollback, cancellation, and claims.
The current MVP only supports classic SPL quote tokens, reveals bid amounts
after close, and has an eight-bid cap.