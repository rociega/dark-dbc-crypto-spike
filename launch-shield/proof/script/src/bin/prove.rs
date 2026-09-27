use std::{error::Error, io::Read};

use launch_shield_proof_relation::{bid_commitment, BidStatement};
use sp1_sdk::{include_elf, HashableKey, Prover, ProverClient, SP1Stdin};

const GUEST_ELF: &[u8] = include_elf!("launch-shield-proof-guest");

fn decode_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], Box<dyn Error>> {
    let value = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    let bytes = hex::decode(value)?;
    let bytes: [u8; N] = bytes.try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{label} must decode to exactly {N} bytes"),
        )
    })?;
    Ok(bytes)
}

fn main() -> Result<(), Box<dyn Error>> {
    eprintln!(
        "Provide these 8 newline-separated fields on stdin: program_id hex32, \
         auction_id hex32, bidder hex32, quote_mint hex32, quote_vault hex32, \
         max_bid_amount decimal, amount decimal, salt hex32."
    );
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let mut lines = input.lines();

    let program_id = decode_hex::<32>(
        lines.next().ok_or("missing program_id")?,
        "program_id",
    )?;
    let auction_id = decode_hex::<32>(
        lines.next().ok_or("missing auction_id")?,
        "auction_id",
    )?;
    let bidder = decode_hex::<32>(lines.next().ok_or("missing bidder")?, "bidder")?;
    let quote_mint =
        decode_hex::<32>(lines.next().ok_or("missing quote_mint")?, "quote_mint")?;
    let quote_escrow =
        decode_hex::<32>(lines.next().ok_or("missing quote_vault")?, "quote_vault")?;
    let max_bid_amount: u64 = lines
        .next()
        .ok_or("missing max_bid_amount")?
        .trim()
        .parse()?;
    let amount: u64 = lines.next().ok_or("missing amount")?.trim().parse()?;
    let salt = decode_hex::<32>(lines.next().ok_or("missing salt")?, "salt")?;
    if lines.next().is_some() {
        return Err("unexpected extra input fields".into());
    }
    if amount == 0 || amount > max_bid_amount {
        return Err("amount must be in 1..=max_bid_amount".into());
    }

    let mut statement = BidStatement {
        program_id,
        auction_id,
        bidder,
        bid_commitment: [0; 32],
        quote_mint,
        quote_escrow,
        max_bid_amount,
    };
    statement.bid_commitment = bid_commitment(&statement, amount, &salt);

    let mut stdin = SP1Stdin::new();
    stdin.write(&statement.program_id);
    stdin.write(&statement.auction_id);
    stdin.write(&statement.bidder);
    stdin.write(&statement.bid_commitment);
    stdin.write(&statement.quote_mint);
    stdin.write(&statement.quote_escrow);
    stdin.write(&statement.max_bid_amount);
    stdin.write(&amount);
    stdin.write(&salt);

    let client = ProverClient::builder().cpu().build();
    let (proving_key, verifying_key) = client.setup(GUEST_ELF);
    let proof = client
        .prove(&proving_key, &stdin)
        .groth16()
        .run()?;
    client.verify(&proof, &verifying_key)?;

    let proof_bytes = proof.bytes();
    let public_values = proof.public_values.as_slice();
    if proof_bytes.len() != 260 || public_values != statement.public_values() {
        return Err("generated proof does not match the on-chain encoding".into());
    }

    println!("commitment={}", hex::encode(statement.bid_commitment));
    println!("proof={}", hex::encode(proof_bytes));
    println!("public_values={}", hex::encode(public_values));
    println!("sp1_vkey_hash={}", verifying_key.bytes32());
    Ok(())
}