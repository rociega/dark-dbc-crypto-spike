# Dark DBC protocol arithmetic spike

This host-side crate tests only the fixed-eight integer allocation rule used
by the design document, including Token-2022's 48-bit transfer representation
and the MVP's stricter 32-bit per-bid cap for bounded aggregate decryption. It
is **not** the Anchor program, a ZK circuit, a
Token-2022 proof verifier, threshold-encryption implementation, or DBC
integration. It must not be used to custody funds or represented as a secure
auction implementation.

Run its tests with:

```sh
cargo test --manifest-path protocol-spike/Cargo.toml
```
