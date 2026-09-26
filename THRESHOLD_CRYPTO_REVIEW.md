# Threshold-crypto implementation gate

**Review date:** 2026-09-26  
**Decision:** No candidate found in this targeted scan is a safe drop-in. Do not start DBC settlement integration on the strength of these candidates.

## Required property

The fixed-eight design relies on the Token-2022 confidential-transfer ElGamal key format. In the pinned SDK, the public key point is derived as H/s, not the usual additive form G*s. The system must create a 2-of-3 key without any trustee learning the complete secret, derive a compatible public key, and retain threshold shares that can decrypt only the public aggregate Q. The local masked-inversion test is a centrally simulated arithmetic transcript, not a DKG or a malicious-secure MPC protocol. See the [spike README](https://github.com/rociega/dark-dbc-crypto-spike/blob/main/README.md) and [host test](https://github.com/rociega/dark-dbc-crypto-spike/blob/main/src/lib.rs).

## Candidate scan

This is a targeted repository/README scan, not a claim that no suitable implementation exists anywhere.

Additional GitHub repository searches for Ristretto threshold DKG, distributed inversion MPC over Shamir shares, and malicious threshold encryption over Ristretto returned no repository hits. GitHub repository search is incomplete, so this is a search signal, not proof that no implementation exists.

| Candidate | What its repository documents | Why it does not pass this gate |
|---|---|---|
| [OpacityLabs/opacity-ferveo](https://github.com/OpacityLabs/opacity-ferveo/blob/dev/README.md) | Synchronous DKG and threshold decryption over BLS12-381; maintained for opacity-stack. Its README says it has not been independently audited and general-purpose use is not a goal. | Different curve and key representation from the Token-2022 ElGamal key. It is not a drop-in implementation of the required H/s distributed inversion. |
| [renegade-fi/ark-mpc](https://github.com/renegade-fi/ark-mpc/blob/main/README.md) | Malicious-secure SPDZ-style two-party MPC. The README example requires an external Beaver preprocessing source. | A generic two-party MPC framework, not a ready 2-of-3 DKG or reviewed distributed-inversion protocol for this key mapping. Preprocessing and protocol composition remain security-critical. |
| [HeyPromaRoy/Threshold-ELGamal](https://github.com/HeyPromaRoy/Threshold-ELGamal/blob/main/README.md) | Its README identifies it as an applied-cryptography course project, using 3072-bit safe-prime parameters and describing trusted-dealer or DKG-simulation setup. | Different group and key format; not evidence of a production-ready, malicious-secure, Token-2022-compatible protocol. |
| [randa-mu/dcipher](https://github.com/randa-mu/dcipher) | Threshold-cryptography project with BLS-oriented components; GitHub marks the repository archived. | Archived and not compatible with the required Token-2022 ElGamal point/encoding. |

No candidate above is being recommended as a dependency. The scan does not establish the audit status of ark-mpc or the academic project; their repository descriptions simply do not establish the exact protocol and assurance this project needs.

## Go/no-go criteria before settlement code

1. **Key generation:** Specify and independently review a malicious-secure 2-of-3 DKG for the exact scalar field and threat model, including verification shares, authenticated transcript binding, fresh randomness, and abort/complaint behavior.
2. **Distributed inversion:** Demonstrate that parties derive shares of 1/s and the exact Token-2022-compatible H/s public key without opening s or 1/s. Preserve the original shares of s for aggregate decryption. The current centralized arithmetic fixture does not meet this criterion.
3. **Token-2022 compatibility:** The lightweight harness at [token-2022-processor-test/src/lib.rs](token-2022-processor-test/src/lib.rs) passes 2/2. One test invokes the processor with in-memory accounts and a host `Rent::get` syscall stub, confirming the `InitializeMint2` route accepts and stores a fixed-test-scalar auditor key. The other inspects the CPI-compatible `inner_transfer` builder and confirms it carries the exact supplied ciphertext pair and proof-context accounts with zero offsets; it does not invoke the CPI. Neither test validates real runtime sysvar loading, account creation, a confidential transfer, or an accepted proof context, and neither models DKG. Run `cargo test --manifest-path token-2022-program-test/Cargo.toml` on a larger-memory runner; even a pass would prove only auditor-key initialization/storage, so a real confidential-transfer proof-context test would still be needed. The full ProgramTest remains unverified.
4. **Privacy and custody:** Prove the accepted private bid is linked to its ciphertext without revealing bidder identity; prove the program-owned vault and single DBC swap conserve assets; prove claims are unlinkable and redeemable to arbitrary destinations.
5. **On-chain verification:** Fix proof formats, transcript domains, trustee verification-key registry, and bounded public-aggregate recovery, then test the verifier against negative/adversarial vectors.

**Current decision:** Hold DBC settlement implementation until criteria 1-3 have a credible pass and criteria 4-5 have a reviewed construction. Keep the eight-note scope and do not relax the no-single-trustee assumption to meet the deadline.
