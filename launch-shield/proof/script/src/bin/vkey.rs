use sp1_sdk::{
    blocking::{Prover, ProverClient},
    include_elf, HashableKey, ProvingKey,
};

const GUEST_ELF: sp1_sdk::Elf = include_elf!("launch-shield-proof-guest");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = ProverClient::builder().light().build();
    let proving_key = client.setup(GUEST_ELF.into())?;
    println!("{}", proving_key.verifying_key().bytes32());
    Ok(())
}