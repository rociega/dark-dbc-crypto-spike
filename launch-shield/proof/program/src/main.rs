#![no_main]

sp1_zkvm::entrypoint!(main);

use launch_shield_proof_relation::{verify_bid, BidStatement, BidWitness};

pub fn main() {
    let statement = BidStatement {
        program_id: sp1_zkvm::io::read(),
        auction_id: sp1_zkvm::io::read(),
        bidder: sp1_zkvm::io::read(),
        bid_commitment: sp1_zkvm::io::read(),
        quote_mint: sp1_zkvm::io::read(),
        quote_escrow: sp1_zkvm::io::read(),
        max_bid_amount: sp1_zkvm::io::read(),
    };
    let witness = BidWitness {
        amount: sp1_zkvm::io::read(),
        salt: sp1_zkvm::io::read(),
    };

    assert!(verify_bid(&statement, &witness));
    sp1_zkvm::io::commit_slice(&statement.public_values());
}
