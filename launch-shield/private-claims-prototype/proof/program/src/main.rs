#![no_main]

sp1_zkvm::entrypoint!(main);

use private_claims_proof_relation::{
    aggregate::{
        verify_aggregate_decryption_relation, verify_trustee_key_setup_relation,
        AggregateDecryptionStatement, AggregateDecryptionWitness, TrusteeKeySetupStatement,
    },
    threshold::{DleqProof, TrusteeDecryptionStep, TrusteeKeyTransformStep, TRUSTEE_COUNT},
    verify_claim_relation, verify_funding_relation, verify_redemption_relation, ClaimStatement,
    ClaimWitness, FundingStatement, FundingWitness, RedemptionStatement, RedemptionWitness,
    BID_MERKLE_DEPTH,
};

pub fn main() {
    match sp1_zkvm::io::read::<u8>() {
        0 => prove_funding(),
        1 => prove_claim(),
        2 => prove_redemption(),
        3 => prove_aggregate_decryption(),
        4 => prove_trustee_key_setup(),
        _ => panic!("unknown private-claims proof kind"),
    }
}

fn read_dleq_proof() -> DleqProof {
    DleqProof {
        commitment_base: sp1_zkvm::io::read::<[u8; 32]>(),
        commitment_input: sp1_zkvm::io::read::<[u8; 32]>(),
        response: sp1_zkvm::io::read::<[u8; 32]>(),
    }
}

fn read_key_setup_steps() -> [TrusteeKeyTransformStep; TRUSTEE_COUNT] {
    core::array::from_fn(|_| TrusteeKeyTransformStep {
        trustee_id: sp1_zkvm::io::read::<[u8; 32]>(),
        derived_public_key: sp1_zkvm::io::read::<[u8; 32]>(),
        proof: read_dleq_proof(),
    })
}

fn read_decryption_steps() -> [TrusteeDecryptionStep; TRUSTEE_COUNT] {
    core::array::from_fn(|_| TrusteeDecryptionStep {
        trustee_id: sp1_zkvm::io::read::<[u8; 32]>(),
        output_point: sp1_zkvm::io::read::<[u8; 32]>(),
        proof: read_dleq_proof(),
    })
}

fn read_ciphertext() -> [u8; 64] {
    let mut ciphertext = [0; 64];
    ciphertext[..32].copy_from_slice(&sp1_zkvm::io::read::<[u8; 32]>());
    ciphertext[32..].copy_from_slice(&sp1_zkvm::io::read::<[u8; 32]>());
    ciphertext
}

fn prove_aggregate_decryption() {
    let statement = AggregateDecryptionStatement {
        program_id: sp1_zkvm::io::read::<[u8; 32]>(),
        pool_account: sp1_zkvm::io::read::<[u8; 32]>(),
        auction_id: sp1_zkvm::io::read::<[u8; 32]>(),
        funded_bid_root: sp1_zkvm::io::read::<[u8; 32]>(),
        funding_mint: sp1_zkvm::io::read::<[u8; 32]>(),
        confidential_vault: sp1_zkvm::io::read::<[u8; 32]>(),
        auditor_pubkey: sp1_zkvm::io::read::<[u8; 32]>(),
        key_epoch: sp1_zkvm::io::read::<[u8; 32]>(),
        trustee_ids: core::array::from_fn(|_| sp1_zkvm::io::read::<[u8; 32]>()),
        verification_shares: core::array::from_fn(|_| sp1_zkvm::io::read::<[u8; 32]>()),
        funded_bid_count: sp1_zkvm::io::read::<u8>(),
        funded_bid_commitments: core::array::from_fn(|_| sp1_zkvm::io::read::<[u8; 32]>()),
        accepted_transfer_context_hashes: core::array::from_fn(|_| {
            sp1_zkvm::io::read::<[u8; 32]>()
        }),
        aggregate_ciphertext_low: read_ciphertext(),
        aggregate_ciphertext_high: read_ciphertext(),
        total_bid_amount: sp1_zkvm::io::read::<u64>(),
    };
    let witness = AggregateDecryptionWitness {
        key_setup_steps: read_key_setup_steps(),
        low_steps: read_decryption_steps(),
        high_steps: read_decryption_steps(),
        low_total: sp1_zkvm::io::read::<u64>(),
        high_total: sp1_zkvm::io::read::<u64>(),
    };

    assert!(verify_aggregate_decryption_relation(&statement, &witness));
    sp1_zkvm::io::commit_slice(&statement.public_values());
}

fn prove_trustee_key_setup() {
    let statement = TrusteeKeySetupStatement {
        program_id: sp1_zkvm::io::read::<[u8; 32]>(),
        funding_mint: sp1_zkvm::io::read::<[u8; 32]>(),
        auditor_pubkey: sp1_zkvm::io::read::<[u8; 32]>(),
        key_epoch: sp1_zkvm::io::read::<[u8; 32]>(),
        trustee_ids: core::array::from_fn(|_| sp1_zkvm::io::read::<[u8; 32]>()),
        verification_shares: core::array::from_fn(|_| sp1_zkvm::io::read::<[u8; 32]>()),
    };
    let steps = read_key_setup_steps();
    assert!(verify_trustee_key_setup_relation(&statement, &steps));
    sp1_zkvm::io::commit_slice(&statement.public_values());
}

fn prove_funding() {
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

fn prove_claim() {
    let statement = ClaimStatement {
        program_id: sp1_zkvm::io::read::<[u8; 32]>(),
        auction_id: sp1_zkvm::io::read::<[u8; 32]>(),
        funded_bid_root: sp1_zkvm::io::read::<[u8; 32]>(),
        output_mint: sp1_zkvm::io::read::<[u8; 32]>(),
        note_commitment: sp1_zkvm::io::read::<[u8; 32]>(),
        nullifier: sp1_zkvm::io::read::<[u8; 32]>(),
        total_bid_amount: sp1_zkvm::io::read::<u64>(),
        total_output_amount: sp1_zkvm::io::read::<u64>(),
    };
    let bidder = sp1_zkvm::io::read::<[u8; 32]>();
    let amount = sp1_zkvm::io::read::<u64>();
    let bid_randomness = sp1_zkvm::io::read::<[u8; 32]>();
    let claim_secret = sp1_zkvm::io::read::<[u8; 32]>();
    let bid_index = sp1_zkvm::io::read::<u8>();
    let mut bid_merkle_siblings = [[0u8; 32]; BID_MERKLE_DEPTH];
    for sibling in &mut bid_merkle_siblings {
        *sibling = sp1_zkvm::io::read::<[u8; 32]>();
    }
    let note_randomness = sp1_zkvm::io::read::<[u8; 32]>();

    let witness = ClaimWitness {
        bidder,
        amount,
        bid_randomness,
        claim_secret,
        bid_index,
        bid_merkle_siblings,
        note_randomness,
    };

    assert!(verify_claim_relation(&statement, &witness));
    sp1_zkvm::io::commit_slice(&statement.public_values());
}

fn prove_redemption() {
    let statement = RedemptionStatement {
        program_id: sp1_zkvm::io::read::<[u8; 32]>(),
        auction_id: sp1_zkvm::io::read::<[u8; 32]>(),
        claim_note_root: sp1_zkvm::io::read::<[u8; 32]>(),
        output_mint: sp1_zkvm::io::read::<[u8; 32]>(),
        destination: sp1_zkvm::io::read::<[u8; 32]>(),
        nullifier: sp1_zkvm::io::read::<[u8; 32]>(),
        amount: sp1_zkvm::io::read::<u64>(),
    };
    let witness = RedemptionWitness {
        bid_commitment: sp1_zkvm::io::read::<[u8; 32]>(),
        claim_secret: sp1_zkvm::io::read::<[u8; 32]>(),
        note_randomness: sp1_zkvm::io::read::<[u8; 32]>(),
        note_index: sp1_zkvm::io::read::<u8>(),
        note_merkle_siblings: [
            sp1_zkvm::io::read::<[u8; 32]>(),
            sp1_zkvm::io::read::<[u8; 32]>(),
            sp1_zkvm::io::read::<[u8; 32]>(),
        ],
    };

    assert!(verify_redemption_relation(&statement, &witness));
    sp1_zkvm::io::commit_slice(&statement.public_values());
}
