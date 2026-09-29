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
- Integer flooring can leave up to `revealed_count - 1` base-token atomic units
  in the output vault. There is no sweep instruction, so that remainder stays
  locked; with the current 8-bid cap, the upper bound is 7 raw units, whose value
  depends on the base mint's decimals.
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

The source review used Meteora's public DBC 0.2.1 commit
`f552f20aa3c1c7631427c3827aeea7c58b902813`. Its `swap2` source file is
identical to the reviewed 0.2.0 revision. The SPL initializer keeps the same
account fields and order; its first six accounts are config, pool authority,
creator, base mint, quote mint, and pool. Release 0.2.1 adds initializer runtime
checks for quote-mint token badges and rejects deprecated rate-limiter and
Meteora DAMM migration settings. The repository does not include a DBC 0.2.1
release IDL, so this source review is not a regenerated 0.2.1 IDL binding.

The parser requires the no-referral sentinel, Anchor event-CPI accounts, and
the single Instructions sysvar remaining account. That is 15 account metas
through the DBC program account (including the optional-referral sentinel),
followed by the Instructions sysvar as meta 16. This source review does not
prove either deployed program matches that source. Before deployment, pin and
compare the target cluster's deployed DBC build and regenerate the instruction
bindings from that matching source. Use a DBC config accepted by the deployed
initializer; an incompatible config can make settlement fail atomically.

Auction creation currently checks that the DBC config account is owned by the
DBC program, but it does not decode that config or prevalidate its quote mint
and active settings. A bad or changed config can therefore make settlement
fail after bids are escrowed. On cancellation, only revealed bids are eligible
for refunds; unrevealed deposits and bonds remain forfeitable to the creator.
For a multi-creator production deployment, use a governed config allowlist or
version-aware preflight before accepting bids.

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
settlement test. A read-only Devnet check on 2026-09-29 also recorded upgrade
authority `DHLXnJdACTY83yKwnUkeoDjqi4QBbsYGa1v8tJL76ViX`. Its account is
System Program-owned and has no data; that does not identify its custodian or
demonstrate multisig governance.

To repeat the read-only Devnet fingerprint check, run
`python3 launch-shield/scripts/check_dbc_devnet.py`. It uses
`SOLANA_DEVNET_RPC_URL` when set, otherwise the public Devnet RPC, and compares
the ProgramData address, upgrade authority, upgrade slot, executable length,
and SHA-256 with the recorded snapshots. A fresh check on 2026-09-29 matched
all fields. A mismatch exits nonzero. A match confirms only that the deployed
bytes and authority match those snapshots; it does not establish source identity
or settlement compatibility.

## Program interface

Instruction data starts with one tag byte; integers are little-endian. State
and bid PDAs are derived from `auction`/`bid` seeds; the quote-vault authority
uses `vault`. The code is in `program/src/`.

| Tag | Instruction | Payload after tag |
|---:|---|---|
| 0 | `initialize_config` | 66 ASCII bytes: SP1 vkey hash `0x` + 64 hex digits |
| 1 | `initialize_auction` | auction ID `[32]`, then commit slots, reveal slots, max bid, SOL bond, minimum-output numerator, minimum-output denominator (`u64 LE` each) |
| 2 | `commit_bid` | commitment `[32]`, 356-byte SP1 6.8.1 Groth16 proof, 200-byte public statement |
| 3 | `reveal_bid` | amount (`u64 LE`), salt `[32]` |
| 4 | `forfeit_unrevealed` | empty |
| 5 | `prepare_settlement` | empty |
| 6 | `finalize_settlement` | empty |
| 7 | `claim` | empty |
| 8 | `cancel_unsettled` | empty |
| 9 | `refund_cancelled_bid` | empty |

The SP1 6.8.1 proof envelope is 356 bytes: a 4-byte verifier-key selector,
32-byte exit code, 32-byte SP1 v6 verifier-key root, 32-byte nonce, and the
256-byte Groth16 proof. The on-chain verifier pins SP1 circuit 6.1.0's
492-byte Groth16 key and checks its SHA-256 selector and the expected root.

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
authority to sign, and stores the supplied verifier hash. The vkey must be
generated from the SP1 6.8.1 guest ELF and matched to the deployed program
before configuring this one-shot value.

Program-owned config, auction, and bid PDAs handle third-party pre-funding.
When a target system account already has lamports, the program tops it up to
rent if needed, then uses signed `allocate`/`assign` instead of `create_account`,
which would fail for an already-funded address.

## Proof tooling

The optional SP1 6.8.1 host binaries are in `proof/script` and are intended to
run as:

```sh
cargo run --manifest-path launch-shield/proof/Cargo.toml \
  -p launch-shield-proof-runner --features sp1-prover --bin launch-shield-vkey
cargo run --manifest-path launch-shield/proof/Cargo.toml \
  -p launch-shield-proof-runner --features sp1-prover --bin launch-shield-prove
```

These use SP1 6.8.1 and circuit version 6.1.0. The prover reads amount and salt
from stdin; do not put bid values or salts in command-line arguments or shell
history. Proof generation, host-side verification, and the matching Solana
verifier are separate release gates; a successful guest build alone does not
establish on-chain compatibility.

## Verification and remaining gates

Run native tests with a Rust toolchain on `PATH`:

```sh
cargo test --manifest-path launch-shield/program/Cargo.toml
cargo test --manifest-path launch-shield/proof/Cargo.toml -p launch-shield-proof-relation
```

The on-chain crate's 28 unit tests and the shared proof-relation crate's 8 tests
pass. Host-side tests also cover cancellation deadline/settlement guards,
claim eligibility, and cancelled-refund eligibility through the same pure
validation helpers used by the instruction handlers; they do not simulate
token CPIs or validator rollback. Settlement's same-pool swap guard scans only
the transaction's encoded top-level instruction count, rather than probing all
65,536 possible indices. Tests exercise serialized Instructions-sysvar layouts
for the valid five-instruction settlement sequence and for duplicate same-pool
swap rejection. They also bind the initialization instruction to its expected
program/config/mints/pool, bind finalization to its immediately preceding swap,
and check that pro-rata rounding cannot allocate more than the output total.
The SP1 6.8.1 guest ELF and local `sp1-executor` runner compile with the matching
toolchain. The runner was exercised using synthetic data: a valid bid produced
the 200-byte public statement, while a mutated amount exited nonzero. This does
not generate or verify a Groth16 proof. The full `sp1-prover` build remains
blocked by the dependency firewall described below.

A prior SBF release build completed for `sbfv1` with Solana CLI 1.18.26 and
platform-tools v1.52. Its stripped `launch_shield_program.so` was 338,704
bytes (SHA-256
`57ec0b3df861778e9f1549ddd8bb15a484326033ae5a57f3f78beb048478aee8`). That
was a pre-migration build and does not validate the SP1 6.8.1 verifier.

A current-source SBF release build completed with Agave CLI 4.3.0 and
platform-tools v1.57. The stripped `launch_shield_program.so` is 321,064
bytes (SHA-256
`ab0e74f0e074f5c8c47b9898e0786a8fe091ad10497343f385dad3ce8bb01115`).
Agave's `--patch-binaries-for-nix true` path panics in this Replit image
because its generated Nix dependency bundle lacks `nix-support/dynamic-linker`;
the build passed with `--patch-binaries-for-nix false`. This validates SBF
compilation only.

The Agave 4.3.0 local validator cannot start in this environment: its `io_uring`
probe returns `Operation not permitted`, then startup panics because
`io_uring_supported()` is false. The program has not been loaded into a
validator here. Runtime behavior and Devnet settlement remain unverified. No
DBC transaction simulation, deployed-version source match, verifier compute
measurement, or production deployment has been completed.

The first usable release still needs a vkey and proof generated for the actual
guest; a pinned DBC deployment/IDL; transaction-size/compute validation; and
validator tests for escrow, settlement rollback, cancellation, and claims.
The current MVP only supports classic SPL quote tokens, reveals bid amounts
after close, and has an eight-bid cap.

### Security scan blocker (2026-09-28)

The previous SP1 5.x proof stack had a high-severity `p3-challenger`
advisory (`GHSA-vj64-rjf3-w3v7`). The migration target is SP1 6.8.1, whose
upstream dependency set includes the reported fixed `0.4.3-succinct` release.
Treat the advisory as unresolved until the regenerated proof stack, vkey, and
on-chain verifier pass the tests above. Security scans also reported old
vulnerable packages from preserved snapshots; verify the active lockfile rather
than relying on those historical findings.

The optional CPU prover also remains blocked: SP1 6.8.1's native FFI pins
`golang.org/x/crypto v0.45.0`, which the package firewall rejects for a critical
advisory. As of 2026-09-28, crates.io still lists SP1 SDK, zkVM, and build
version 6.8.1 as their latest stable releases, so no coordinated newer SP1
release is available. An isolated copy of the FFI built with v0.57.0, but the
complete `sp1-prover` workspace check did not finish, and no dependency
override was committed. Do not bypass the firewall or update this transitive
dependency in isolation; wait for a coordinated SP1 dependency update and
validate the verifier before generating a release vkey or proof.