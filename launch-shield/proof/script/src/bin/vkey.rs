use sp1_sdk::{include_elf, HashableKey, Prover, ProverClient};

const GUEST_ELF: &[u8] = include_elf!("launch-shield-proof-guest");

fn main() {
    let client = ProverClient::builder().cpu().build();
    let (_proving_key, verifying_key) = client.setup(GUEST_ELF);
    println!("{}", verifying_key.bytes32());
}