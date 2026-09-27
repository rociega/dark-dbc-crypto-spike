use launch_shield_proof_relation::{bid_commitment, BidStatement, BidWitness};
use sp1_build::include_elf;
use sp1_core_executor::{Executor, Program};
use sp1_core_machine::io::SP1Stdin;
use sp1_stark::SP1CoreOpts;

const GUEST_ELF: &[u8] = include_elf!("launch-shield-proof-guest");

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

fn execute(stdin: &SP1Stdin) -> Result<(Vec<u8>, u64), Box<dyn std::error::Error>> {
    let mut executor = Executor::new(Program::from(GUEST_ELF)?, SP1CoreOpts::default());
    executor.write_vecs(&stdin.buffer);
    executor.run_fast()?;
    Ok((
        executor.state.public_values_stream.clone(),
        executor.report.total_instruction_count(),
    ))
}

fn main() {
    let (statement, witness) = fixture();
    let valid = execute(&stdin_for(&statement, &witness)).expect("valid bid must execute");
    assert_eq!(valid.0, statement.public_values());
    println!(
        "valid bid relation executed; public bytes={}, guest instructions={}",
        valid.0.len(),
        valid.1
    );

    let mut invalid = witness;
    invalid.amount += 1;
    assert!(
        execute(&stdin_for(&statement, &invalid)).is_err(),
        "mutated amount must be rejected"
    );
    println!("mutated amount rejected by local SP1 executor");
}
