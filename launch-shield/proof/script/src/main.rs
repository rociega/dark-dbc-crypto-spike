use launch_shield_proof_relation::{bid_commitment, BidStatement, BidWitness};
use sp1_sdk::{
    blocking::{Prover, ProverClient, SP1Stdin},
    include_elf, Elf,
};

const GUEST_ELF: Elf = include_elf!("launch-shield-proof-guest");

fn fixture() -> (BidStatement, BidWitness) {
    let witness = BidWitness {
        amount: 37,
        salt: [0xabu8; 32],
    };
    let mut statement = BidStatement {
        program_id: [1; 32],
        auction_id: [2; 32],
        bidder: [3; 32],
        bid_commitment: [0; 32],
        quote_mint: [4; 32],
        quote_escrow: [5; 32],
        max_bid_amount: 100,
    };
    statement.bid_commitment = bid_commitment(&statement, witness.amount, &witness.salt);
    (statement, witness)
}

fn stdin_for(statement: &BidStatement, witness: &BidWitness) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(&statement.program_id);
    stdin.write(&statement.auction_id);
    stdin.write(&statement.bidder);
    stdin.write(&statement.bid_commitment);
    stdin.write(&statement.quote_mint);
    stdin.write(&statement.quote_escrow);
    stdin.write(&statement.max_bid_amount);
    stdin.write(&witness.amount);
    stdin.write(&witness.salt);
    stdin
}

fn execute(stdin: SP1Stdin) -> Result<(Vec<u8>, u64, u64), Box<dyn std::error::Error>> {
    let client = ProverClient::builder().light().build();
    let (public_values, report) = client.execute(GUEST_ELF, stdin).run()?;
    Ok((
        public_values.as_slice().to_vec(),
        report.total_instruction_count(),
        report.exit_code,
    ))
}

fn main() {
    let (statement, witness) = fixture();
    let valid = execute(stdin_for(&statement, &witness)).expect("valid bid must execute");
    assert_eq!(valid.2, 0, "valid bid must exit successfully");
    assert_eq!(valid.0, statement.public_values());
    println!(
        "valid bid relation executed; public bytes={}, guest instructions={}",
        valid.0.len(),
        valid.1
    );

    let mut invalid = witness;
    invalid.amount += 1;
    let invalid = execute(stdin_for(&statement, &invalid))
        .expect("mutated bid execution must report its exit code");
    assert!(
        invalid.2 != 0,
        "mutated amount must be rejected"
    );
    println!("mutated amount rejected by local SP1 executor");
}
