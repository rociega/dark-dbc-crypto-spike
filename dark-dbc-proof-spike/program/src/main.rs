#![no_main]
sp1_zkvm::entrypoint!(main);

use dark_dbc_zk_relation::{verify_funding_relation, FundingStatement, FundingWitness};

pub fn main() {
    let program_id = sp1_zkvm::io::read::<[u8; 32]>();
    let auction_id = sp1_zkvm::io::read::<[u8; 32]>();
    let bidder = sp1_zkvm::io::read::<[u8; 32]>();
    let bid_commitment = sp1_zkvm::io::read::<[u8; 32]>();
    let token_mint = sp1_zkvm::io::read::<[u8; 32]>();
    let confidential_vault = sp1_zkvm::io::read::<[u8; 32]>();
    let transfer_context_hash = sp1_zkvm::io::read::<[u8; 32]>();
    let auditor_pubkey = sp1_zkvm::io::read::<[u8; 32]>();
    let low_commitment = sp1_zkvm::io::read::<[u8; 32]>();
    let low_handle = sp1_zkvm::io::read::<[u8; 32]>();
    let high_commitment = sp1_zkvm::io::read::<[u8; 32]>();
    let high_handle = sp1_zkvm::io::read::<[u8; 32]>();
    let amount = sp1_zkvm::io::read::<u64>();
    let bid_randomness = sp1_zkvm::io::read::<[u8; 32]>();
    let claim_secret = sp1_zkvm::io::read::<[u8; 32]>();
    let opening_low = sp1_zkvm::io::read::<[u8; 32]>();
    let opening_high = sp1_zkvm::io::read::<[u8; 32]>();

    let mut ciphertext_low = [0u8; 64];
    ciphertext_low[..32].copy_from_slice(&low_commitment);
    ciphertext_low[32..].copy_from_slice(&low_handle);
    let mut ciphertext_high = [0u8; 64];
    ciphertext_high[..32].copy_from_slice(&high_commitment);
    ciphertext_high[32..].copy_from_slice(&high_handle);

    let statement = FundingStatement {
        program_id,
        auction_id,
        bidder,
        bid_commitment,
        token_mint,
        confidential_vault,
        transfer_context_hash,
        auditor_pubkey,
        ciphertext_low,
        ciphertext_high,
    };
    let witness = FundingWitness {
        amount,
        bid_randomness,
        claim_secret,
        opening_low,
        opening_high,
    };

    assert!(verify_funding_relation(&statement, &witness));
    sp1_zkvm::io::commit_slice(&statement.public_values());
}
