use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT},
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use dark_dbc_zk_relation::{bid_commitment, FundingStatement, FundingWitness};
use sha3::Sha3_512;
use sp1_build::include_elf;
use sp1_core_executor::{Executor, Program};
use sp1_core_machine::io::SP1Stdin;
use sp1_stark::SP1CoreOpts;

pub const FUNDING_GUEST_ELF: &[u8] = include_elf!("dark-dbc-funding-guest");

fn encrypt_component(pubkey: &RistrettoPoint, value: u64, opening: Scalar) -> [u8; 64] {
    let h = RistrettoPoint::hash_from_bytes::<Sha3_512>(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
    let commitment = (RISTRETTO_BASEPOINT_POINT * Scalar::from(value) + h * opening)
        .compress()
        .to_bytes();
    let handle = (pubkey * opening).compress().to_bytes();
    let mut ciphertext = [0u8; 64];
    ciphertext[..32].copy_from_slice(&commitment);
    ciphertext[32..].copy_from_slice(&handle);
    ciphertext
}

fn fixture(amount: u64) -> (FundingStatement, FundingWitness) {
    assert!(amount > 0 && amount <= (1u64 << 32) - 1);
    let secret = Scalar::from(123_456_789u64);
    let h = RistrettoPoint::hash_from_bytes::<Sha3_512>(RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
    let auditor_point = h * secret.invert();
    let auditor_pubkey = auditor_point.compress().to_bytes();
    let opening_low_scalar = Scalar::from(17u64);
    let opening_high_scalar = Scalar::from(91u64);
    let ciphertext_low = encrypt_component(&auditor_point, amount & 0xffff, opening_low_scalar);
    let ciphertext_high = encrypt_component(&auditor_point, amount >> 16, opening_high_scalar);
    let bid_randomness = [0x55; 32];
    let claim_secret = [0x66; 32];

    let mut statement = FundingStatement {
        program_id: [0x11; 32],
        auction_id: [0x22; 32],
        bidder: [0x33; 32],
        bid_commitment: [0; 32],
        token_mint: [0x44; 32],
        confidential_vault: [0x77; 32],
        transfer_context_hash: [0x88; 32],
        auditor_pubkey,
        ciphertext_low,
        ciphertext_high,
    };
    statement.bid_commitment = bid_commitment(
        &statement.program_id,
        &statement.auction_id,
        &statement.bidder,
        amount,
        &bid_randomness,
        &claim_secret,
    );

    let witness = FundingWitness {
        amount,
        bid_randomness,
        claim_secret,
        opening_low: opening_low_scalar.to_bytes(),
        opening_high: opening_high_scalar.to_bytes(),
    };
    (statement, witness)
}

fn write_stdin(stdin: &mut SP1Stdin, statement: &FundingStatement, witness: &FundingWitness) {
    let low_commitment: [u8; 32] = statement.ciphertext_low[..32].try_into().unwrap();
    let low_handle: [u8; 32] = statement.ciphertext_low[32..].try_into().unwrap();
    let high_commitment: [u8; 32] = statement.ciphertext_high[..32].try_into().unwrap();
    let high_handle: [u8; 32] = statement.ciphertext_high[32..].try_into().unwrap();
    stdin.write(&statement.program_id);
    stdin.write(&statement.auction_id);
    stdin.write(&statement.bidder);
    stdin.write(&statement.bid_commitment);
    stdin.write(&statement.token_mint);
    stdin.write(&statement.confidential_vault);
    stdin.write(&statement.transfer_context_hash);
    stdin.write(&statement.auditor_pubkey);
    stdin.write(&low_commitment);
    stdin.write(&low_handle);
    stdin.write(&high_commitment);
    stdin.write(&high_handle);
    stdin.write(&witness.amount);
    stdin.write(&witness.bid_randomness);
    stdin.write(&witness.claim_secret);
    stdin.write(&witness.opening_low);
    stdin.write(&witness.opening_high);
}

fn execute_local(stdin: &SP1Stdin) -> Result<(Vec<u8>, u64), Box<dyn std::error::Error>> {
    let program = Program::from(FUNDING_GUEST_ELF)?;
    let mut executor = Executor::new(program, SP1CoreOpts::default());
    executor.write_vecs(&stdin.buffer);
    executor.run_fast()?;

    Ok((
        executor.state.public_values_stream.clone(),
        executor.report.total_instruction_count(),
    ))
}

fn main() {
    let (statement, witness) = fixture(123_456_789);

    let mut stdin = SP1Stdin::new();
    write_stdin(&mut stdin, &statement, &witness);
    let (public_values, guest_instruction_count) =
        execute_local(&stdin).expect("valid SDK-compatible ciphertext fixture should execute");
    assert_eq!(public_values, statement.public_values());
    println!(
        "valid funding relation executed; public bytes={}, guest instructions={}",
        public_values.len(),
        guest_instruction_count
    );

    let mut invalid_stdin = SP1Stdin::new();
    write_stdin(
        &mut invalid_stdin,
        &statement,
        &FundingWitness {
            amount: witness.amount + 1,
            ..witness
        },
    );
    assert!(
        execute_local(&invalid_stdin).is_err(),
        "mutated amount must not execute successfully"
    );
    println!("mutated amount rejected by the guest");
}
