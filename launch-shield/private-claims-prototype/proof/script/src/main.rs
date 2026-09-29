use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT},
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use private_claims_proof_relation::{
    bid_commitment, claim_note_commitment, claim_note_merkle_path, claim_note_merkle_root,
    claim_nullifier, funded_bid_merkle_path, funded_bid_merkle_root, proof_context_account_hash,
    redemption_nullifier, verify_claim_relation, verify_redemption_relation,
    AcceptedTransferContext, ClaimStatement, ClaimWitness, FundingStatement, FundingWitness,
    RedemptionStatement, RedemptionWitness, MAX_BID_AMOUNT, MAX_FUNDED_BIDS,
};
use sha3::Sha3_512;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient, SP1Stdin},
    Elf, HashableKey, ProvingKey,
};
use std::{env, fs, path::Path};

const FUNDING_GUEST_ELF: Elf =
    Elf::Static(include_bytes!(env!("PRIVATE_CLAIMS_GUEST_ELF")));
const SP1_PROOF_LEN: usize = 356;

fn encrypt_component(pubkey: &RistrettoPoint, value: u64, opening: Scalar) -> [u8; 64] {
    let h = RistrettoPoint::hash_from_bytes::<Sha3_512>(
        RISTRETTO_BASEPOINT_COMPRESSED.as_bytes(),
    );
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
    assert!(amount > 0 && amount <= MAX_BID_AMOUNT);
    let secret = Scalar::from(123_456_789u64);
    let h = RistrettoPoint::hash_from_bytes::<Sha3_512>(
        RISTRETTO_BASEPOINT_COMPRESSED.as_bytes(),
    );
    let auditor_pubkey = h * secret.invert();
    let opening_low = Scalar::from(17u64);
    let opening_high = Scalar::from(91u64);
    let bid_randomness = [0x55; 32];
    let claim_secret = [0x66; 32];
    let program_id = [0x11; 32];
    let auction_id = [0x22; 32];
    let bidder = [0x33; 32];
    let token_mint = [0x44; 32];
    let confidential_vault = [0x77; 32];
    let confidential_vault_elgamal_pubkey = [0x99; 32];
    let ciphertext_low = encrypt_component(&auditor_pubkey, amount & 0xffff, opening_low);
    let ciphertext_high = encrypt_component(&auditor_pubkey, amount >> 16, opening_high);
    let mut auditor_ciphertexts = [0u8; 128];
    auditor_ciphertexts[..64].copy_from_slice(&ciphertext_low);
    auditor_ciphertexts[64..].copy_from_slice(&ciphertext_high);
    let new_source_decryptable_balance = [0u8; 36];
    let equality_context_key = [0xa1; 32];
    let equality_context_owner = [0xb1; 32];
    let equality_context_hash = proof_context_account_hash(
        &equality_context_key,
        &equality_context_owner,
        &[0x01, 0x02],
    );
    let ciphertext_validity_context_key = [0xa2; 32];
    let ciphertext_validity_context_owner = [0xb2; 32];
    let ciphertext_validity_context_hash = proof_context_account_hash(
        &ciphertext_validity_context_key,
        &ciphertext_validity_context_owner,
        &[0x03, 0x04],
    );
    let range_context_key = [0xa3; 32];
    let range_context_owner = [0xb3; 32];
    let range_context_hash = proof_context_account_hash(
        &range_context_key,
        &range_context_owner,
        &[0x05, 0x06],
    );
    let transfer_context_hash = AcceptedTransferContext {
        program_id: &program_id,
        pool_account: &[0x12; 32],
        source_account: &[0x13; 32],
        funding_mint: &token_mint,
        confidential_vault: &confidential_vault,
        authority: &bidder,
        auditor_pubkey: &auditor_pubkey.compress().to_bytes(),
        confidential_vault_elgamal_pubkey: &confidential_vault_elgamal_pubkey,
        new_source_decryptable_balance: &new_source_decryptable_balance,
        auditor_ciphertexts: &auditor_ciphertexts,
        equality_context_hash: &equality_context_hash,
        ciphertext_validity_context_hash: &ciphertext_validity_context_hash,
        range_context_hash: &range_context_hash,
    }
    .hash();

    let mut statement = FundingStatement {
        program_id,
        auction_id,
        bidder,
        bid_commitment: [0; 32],
        token_mint,
        confidential_vault,
        transfer_context_hash,
        auditor_pubkey: auditor_pubkey.compress().to_bytes(),
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
        opening_low: opening_low.to_bytes(),
        opening_high: opening_high.to_bytes(),
    };
    (statement, witness)
}

fn stdin_for(statement: &FundingStatement, witness: &FundingWitness) -> SP1Stdin {
    let low_commitment: [u8; 32] = statement.ciphertext_low[..32]
        .try_into()
        .expect("low commitment has 32 bytes");
    let low_handle: [u8; 32] = statement.ciphertext_low[32..]
        .try_into()
        .expect("low handle has 32 bytes");
    let high_commitment: [u8; 32] = statement.ciphertext_high[..32]
        .try_into()
        .expect("high commitment has 32 bytes");
    let high_handle: [u8; 32] = statement.ciphertext_high[32..]
        .try_into()
        .expect("high handle has 32 bytes");

    let mut stdin = SP1Stdin::new();
    stdin.write(&0u8);
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
    stdin
}

fn claim_fixture() -> (ClaimStatement, ClaimWitness) {
    let program_id = [0x11; 32];
    let auction_id = [0x22; 32];
    let output_mint = [0x44; 32];
    let amounts = [100, 120, 130, 140, 150, 160, 170, 180];
    let leaves: [[u8; 32]; MAX_FUNDED_BIDS] = std::array::from_fn(|index| {
        let bidder = [u8::try_from(index + 1).expect("bidder index fits"); 32];
        let bid_randomness = [0x50 + index as u8; 32];
        let claim_secret = [0x70 + index as u8; 32];
        bid_commitment(
            &program_id,
            &auction_id,
            &bidder,
            amounts[index],
            &bid_randomness,
            &claim_secret,
        )
    });
    let bid_index = 4u8;
    let index = usize::from(bid_index);
    let amount = amounts[index];
    let bid_randomness = [0x50 + bid_index; 32];
    let claim_secret = [0x70 + bid_index; 32];
    let nullifier = claim_nullifier(
        &program_id,
        &auction_id,
        &leaves[index],
        &claim_secret,
    );
    let note_randomness = [0x99; 32];
    let total_bid_amount = amounts.iter().sum();
    let total_output_amount = 1_000_000;
    let value = private_claims_proof_relation::claim_value(
        amount,
        total_bid_amount,
        total_output_amount,
    )
    .expect("fixture has a valid allocation");
    let statement = ClaimStatement {
        program_id,
        auction_id,
        funded_bid_root: funded_bid_merkle_root(&leaves),
        output_mint,
        note_commitment: claim_note_commitment(
            &program_id,
            &auction_id,
            &output_mint,
            value,
            &nullifier,
            &note_randomness,
        ),
        nullifier,
        total_bid_amount,
        total_output_amount,
    };
    let witness = ClaimWitness {
        bidder: [u8::try_from(index + 1).expect("bidder index fits"); 32],
        amount,
        bid_randomness,
        claim_secret,
        bid_index,
        bid_merkle_siblings: funded_bid_merkle_path(&leaves, bid_index)
            .expect("fixture index is in range"),
        note_randomness,
    };
    (statement, witness)
}

fn claim_stdin_for(statement: &ClaimStatement, witness: &ClaimWitness) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(&1u8);
    stdin.write(&statement.program_id);
    stdin.write(&statement.auction_id);
    stdin.write(&statement.funded_bid_root);
    stdin.write(&statement.output_mint);
    stdin.write(&statement.note_commitment);
    stdin.write(&statement.nullifier);
    stdin.write(&statement.total_bid_amount);
    stdin.write(&statement.total_output_amount);
    stdin.write(&witness.bidder);
    stdin.write(&witness.amount);
    stdin.write(&witness.bid_randomness);
    stdin.write(&witness.claim_secret);
    stdin.write(&witness.bid_index);
    for sibling in &witness.bid_merkle_siblings {
        stdin.write(sibling);
    }
    stdin.write(&witness.note_randomness);
    stdin
}

fn redemption_fixture() -> (RedemptionStatement, RedemptionWitness) {
    let (claim_statement, claim_witness) = claim_fixture();
    let bid_commitment = bid_commitment(
        &claim_statement.program_id,
        &claim_statement.auction_id,
        &claim_witness.bidder,
        claim_witness.amount,
        &claim_witness.bid_randomness,
        &claim_witness.claim_secret,
    );
    let claim_notes: [[u8; 32]; MAX_FUNDED_BIDS] = std::array::from_fn(|index| {
        if index == usize::from(claim_witness.bid_index) {
            claim_statement.note_commitment
        } else {
            [0xa0 + index as u8; 32]
        }
    });
    let statement = RedemptionStatement {
        program_id: claim_statement.program_id,
        auction_id: claim_statement.auction_id,
        claim_note_root: claim_note_merkle_root(&claim_notes),
        output_mint: claim_statement.output_mint,
        destination: [0x56; 32],
        nullifier: redemption_nullifier(
            &claim_statement.program_id,
            &claim_statement.auction_id,
            &bid_commitment,
            &claim_witness.claim_secret,
        ),
        amount: private_claims_proof_relation::claim_value(
            claim_witness.amount,
            claim_statement.total_bid_amount,
            claim_statement.total_output_amount,
        )
        .expect("fixture has a valid allocation"),
    };
    let witness = RedemptionWitness {
        bid_commitment,
        claim_secret: claim_witness.claim_secret,
        note_randomness: claim_witness.note_randomness,
        note_index: claim_witness.bid_index,
        note_merkle_siblings: claim_note_merkle_path(&claim_notes, claim_witness.bid_index)
            .expect("fixture index is in range"),
    };
    (statement, witness)
}

fn redemption_stdin_for(
    statement: &RedemptionStatement,
    witness: &RedemptionWitness,
) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(&2u8);
    stdin.write(&statement.program_id);
    stdin.write(&statement.auction_id);
    stdin.write(&statement.claim_note_root);
    stdin.write(&statement.output_mint);
    stdin.write(&statement.destination);
    stdin.write(&statement.nullifier);
    stdin.write(&statement.amount);
    stdin.write(&witness.bid_commitment);
    stdin.write(&witness.claim_secret);
    stdin.write(&witness.note_randomness);
    stdin.write(&witness.note_index);
    for sibling in &witness.note_merkle_siblings {
        stdin.write(sibling);
    }
    stdin
}

fn execute(stdin: SP1Stdin) -> Result<(Vec<u8>, u64, u64), Box<dyn std::error::Error>> {
    let client = ProverClient::builder().light().build();
    let (public_values, report) = client.execute(FUNDING_GUEST_ELF, stdin).run()?;
    Ok((
        public_values.as_slice().to_vec(),
        report.total_instruction_count(),
        report.exit_code,
    ))
}

fn guest_vkey_hash() -> String {
    let client = ProverClient::builder().light().build();
    let proving_key = client
        .setup(FUNDING_GUEST_ELF)
        .expect("SP1 guest key setup must succeed");
    let calculated = proving_key.verifying_key().bytes32();
    let checked_in = include_str!("../../../guest-vkey-hash.txt").trim();
    assert_eq!(
        calculated, checked_in,
        "guest ELF and on-chain verification-key hash are out of sync"
    );
    calculated
}

fn main() {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        None => run_fixtures(),
        Some("prove-claim") => {
            let output_dir = args
                .next()
                .expect("usage: private-claims-proof-runner prove-claim <output-directory>");
            assert!(args.next().is_none(), "unexpected extra arguments");
            #[cfg(feature = "local-prover")]
            generate_claim_proof(Path::new(&output_dir))
                .expect("local claim proof generation failed");
            #[cfg(not(feature = "local-prover"))]
            panic!("rebuild with --features local-prover to generate proofs");
        }
        Some("prove-funding") => {
            let output_dir = args
                .next()
                .expect("usage: private-claims-proof-runner prove-funding <output-directory>");
            assert!(args.next().is_none(), "unexpected extra arguments");
            #[cfg(feature = "local-prover")]
            generate_funding_proof(Path::new(&output_dir))
                .expect("local funding proof generation failed");
            #[cfg(not(feature = "local-prover"))]
            panic!("rebuild with --features local-prover to generate proofs");
        }
        Some("prove-redemption") => {
            let output_dir = args
                .next()
                .expect("usage: private-claims-proof-runner prove-redemption <output-directory>");
            assert!(args.next().is_none(), "unexpected extra arguments");
            #[cfg(feature = "local-prover")]
            generate_redemption_proof(Path::new(&output_dir))
                .expect("local redemption proof generation failed");
            #[cfg(not(feature = "local-prover"))]
            panic!("rebuild with --features local-prover to generate proofs");
        }
        Some(_) => panic!("usage: private-claims-proof-runner [prove-funding|prove-claim|prove-redemption <output-directory>]"),
    }
}

fn run_fixtures() {
    println!("SP1 guest verification-key hash: {}", guest_vkey_hash());

    let (statement, witness) = fixture(123_456_789);
    let valid = execute(stdin_for(&statement, &witness)).expect("valid fixture must execute");
    assert_eq!(valid.2, 0, "valid fixture must exit successfully");
    assert_eq!(valid.0, statement.public_values());
    println!(
        "synthetic funding relation executed locally; public bytes={}, guest instructions={}",
        valid.0.len(),
        valid.1
    );

    let invalid_amount = FundingWitness {
        amount: witness.amount + 1,
        ..witness
    };
    let invalid_amount = execute(stdin_for(&statement, &invalid_amount))
        .expect("mutated amount must report an execution result");
    assert_ne!(invalid_amount.2, 0, "mutated amount must be rejected");

    let mut invalid_ciphertext = statement;
    invalid_ciphertext.ciphertext_low[0] ^= 1;
    let invalid_ciphertext = execute(stdin_for(&invalid_ciphertext, &witness))
        .expect("mutated ciphertext must report an execution result");
    assert_ne!(
        invalid_ciphertext.2, 0,
        "mutated ciphertext must be rejected"
    );
    println!("mutated amount and ciphertext rejected by local SP1 executor");

    let (claim_statement, claim_witness) = claim_fixture();
    assert!(verify_claim_relation(&claim_statement, &claim_witness));
    let claim = execute(claim_stdin_for(&claim_statement, &claim_witness))
        .expect("valid claim fixture must execute");
    assert_eq!(claim.2, 0, "valid claim fixture must exit successfully");
    assert_eq!(claim.0, claim_statement.public_values());
    println!(
        "synthetic claim relation executed locally; public bytes={}, guest instructions={}",
        claim.0.len(),
        claim.1
    );

    let mut invalid_claim_witness = claim_witness;
    invalid_claim_witness.bid_merkle_siblings[0][0] ^= 1;
    assert!(!verify_claim_relation(
        &claim_statement,
        &invalid_claim_witness
    ));
    let invalid_claim = execute(claim_stdin_for(
        &claim_statement,
        &invalid_claim_witness,
    ))
    .expect("mutated claim path must report an execution result");
    assert_ne!(
        invalid_claim.2, 0,
        "mutated claim path must be rejected by local SP1 executor"
    );
    println!("mutated claim Merkle path rejected by local SP1 executor");

    let (redemption_statement, redemption_witness) = redemption_fixture();
    assert!(verify_redemption_relation(
        &redemption_statement,
        &redemption_witness
    ));
    let redemption = execute(redemption_stdin_for(
        &redemption_statement,
        &redemption_witness,
    ))
    .expect("valid redemption fixture must execute");
    assert_eq!(redemption.2, 0, "valid redemption must exit successfully");
    assert_eq!(redemption.0, redemption_statement.public_values());
    println!(
        "synthetic redemption relation executed locally; public bytes={}, guest instructions={}",
        redemption.0.len(),
        redemption.1
    );

    let claim_nullifier = claim_nullifier(
        &redemption_statement.program_id,
        &redemption_statement.auction_id,
        &redemption_witness.bid_commitment,
        &redemption_witness.claim_secret,
    );
    let reused_claim_nullifier = RedemptionStatement {
        nullifier: claim_nullifier,
        ..redemption_statement
    };
    assert!(!verify_redemption_relation(
        &reused_claim_nullifier,
        &redemption_witness
    ));
    let reused_claim_nullifier_execution = execute(redemption_stdin_for(
        &reused_claim_nullifier,
        &redemption_witness,
    ))
    .expect("reused claim nullifier must report an execution result");
    assert_ne!(
        reused_claim_nullifier_execution.2, 0,
        "claim nullifier must not be reusable as a redemption nullifier"
    );
    println!("claim nullifier rejected as a redemption nullifier");

    let mut invalid_redemption_witness = redemption_witness;
    invalid_redemption_witness.note_merkle_siblings[0][0] ^= 1;
    assert!(!verify_redemption_relation(
        &redemption_statement,
        &invalid_redemption_witness
    ));
    let invalid_redemption = execute(redemption_stdin_for(
        &redemption_statement,
        &invalid_redemption_witness,
    ))
    .expect("mutated redemption path must report an execution result");
    assert_ne!(
        invalid_redemption.2, 0,
        "mutated redemption path must be rejected by local SP1 executor"
    );
    println!("mutated redemption Merkle path rejected by local SP1 executor");
}

#[cfg(feature = "local-prover")]
fn generate_redemption_proof(output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let (statement, witness) = redemption_fixture();
    generate_local_proof(
        redemption_stdin_for(&statement, &witness),
        statement.public_values().to_vec(),
        output_dir,
        "redemption",
    )
}

#[cfg(feature = "local-prover")]
fn generate_funding_proof(output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let (statement, witness) = fixture(123_456_789);
    generate_local_proof(
        stdin_for(&statement, &witness),
        statement.public_values().to_vec(),
        output_dir,
        "funding",
    )
}

#[cfg(feature = "local-prover")]
fn generate_claim_proof(output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let (statement, witness) = claim_fixture();
    generate_local_proof(
        claim_stdin_for(&statement, &witness),
        statement.public_values().to_vec(),
        output_dir,
        "claim",
    )
}

#[cfg(feature = "local-prover")]
fn generate_local_proof(
    stdin: SP1Stdin,
    public_values: Vec<u8>,
    output_dir: &Path,
    proof_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = ProverClient::builder().cpu().build();
    let proving_key = client.setup(FUNDING_GUEST_ELF)?;
    let guest_hash = proving_key.verifying_key().bytes32();
    let checked_in_hash = include_str!("../../../guest-vkey-hash.txt").trim();
    if guest_hash != checked_in_hash {
        return Err("guest ELF and checked-in verifier hash do not match".into());
    }

    let proof = client
        .prove(&proving_key, stdin)
        .groth16()
        .run()?;

    if proof.public_values.as_slice() != public_values {
        return Err("SP1 proof public values differ from the supplied statement".into());
    }
    client.verify(&proof, proving_key.verifying_key(), None)?;

    let proof_bytes = proof.bytes();
    if proof_bytes.len() != SP1_PROOF_LEN {
        return Err(format!(
            "SP1 Groth16 proof encoded to {} bytes, expected {}",
            proof_bytes.len(),
            SP1_PROOF_LEN
        )
        .into());
    }
    private_claims_onchain::verify_sp1_v6_proof_bytes(
        &proof_bytes,
        &public_values,
        checked_in_hash,
    )
    .map_err(|_| "on-chain SP1 verifier rejected the generated proof")?;

    fs::create_dir_all(output_dir)?;
    fs::write(
        output_dir.join(format!("{proof_name}.proof")),
        &proof_bytes,
    )?;
    fs::write(
        output_dir.join(format!("{proof_name}.public-values")),
        &public_values,
    )?;
    println!(
        "generated and verified a synthetic {proof_name} Groth16 proof; proof_bytes={}, public_values_bytes={}, output_dir={}",
        proof_bytes.len(),
        public_values.len(),
        output_dir.display()
    );
    Ok(())
}