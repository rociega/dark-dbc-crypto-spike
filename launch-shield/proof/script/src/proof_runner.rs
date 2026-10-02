use std::{error::Error, io::Read};

use launch_shield_proof_relation::{bid_commitment, BidStatement};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient, SP1Stdin},
    include_elf, HashableKey, ProvingKey, SP1ProofWithPublicValues, SP1VerifyingKey,
};

const GUEST_ELF: sp1_sdk::Elf = include_elf!("launch-shield-proof-guest");
const SP1_V6_PROOF_LEN: usize = 356;
const EXPECTED_VKEY_HASH: &str =
    "0x0087f6df27e09f077f54cfab0ef64d46bf1311df3dd721869ca7c13fc628c754";

#[cfg(feature = "sp1-network")]
fn request_error_summary(code: &str, request_id: &[u8]) -> String {
    if request_id.len() == 32 {
        format!("{code} request_id=0x{}", hex::encode(request_id))
    } else {
        format!("{code} request_id_present=true")
    }
}

#[cfg(feature = "sp1-network")]
fn safe_network_error_summary(error: Option<&sp1_sdk::network::Error>) -> String {
    use sp1_sdk::network::Error as NetworkError;

    match error {
        Some(NetworkError::SimulationFailed) => "SP1_SIMULATION_FAILED".to_owned(),
        Some(NetworkError::RequestUnexecutable { request_id }) => {
            request_error_summary("SP1_REQUEST_UNEXECUTABLE", request_id)
        }
        Some(NetworkError::RequestUnfulfillable { request_id }) => {
            request_error_summary("SP1_REQUEST_UNFULFILLABLE", request_id)
        }
        Some(NetworkError::RequestReverted { request_id }) => {
            request_error_summary("SP1_REQUEST_REVERTED", request_id)
        }
        Some(NetworkError::RequestExpired { request_id }) => {
            request_error_summary("SP1_REQUEST_EXPIRED", request_id)
        }
        Some(NetworkError::RequestTimedOut { request_id }) => {
            request_error_summary("SP1_REQUEST_TIMED_OUT", request_id)
        }
        Some(NetworkError::RequestAuctionTimedOut { request_id }) => {
            request_error_summary("SP1_AUCTION_TIMED_OUT", request_id)
        }
        Some(NetworkError::RpcError(status)) => {
            format!("SP1_RPC_ERROR grpc_code={:?}", status.code())
        }
        Some(NetworkError::Other(_)) => "SP1_NETWORK_OTHER_ERROR".to_owned(),
        None => "SP1_ERROR_UNCLASSIFIED".to_owned(),
    }
}

#[cfg(feature = "sp1-network")]
fn safe_network_failure(stage: &str, error: Option<&sp1_sdk::network::Error>) -> std::io::Error {
    std::io::Error::other(format!(
        "SP1_FAILURE stage={stage} {}",
        safe_network_error_summary(error)
    ))
}

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

fn prepare_input() -> Result<(BidStatement, SP1Stdin), Box<dyn Error>> {
    eprintln!(
        "Provide these 8 newline-separated fields on stdin: program_id hex32, \
         auction_id hex32, bidder hex32, quote_mint hex32, quote_vault hex32, \
         max_bid_amount decimal, amount decimal, salt hex32."
    );
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let mut lines = input.lines();

    let program_id = decode_hex::<32>(lines.next().ok_or("missing program_id")?, "program_id")?;
    let auction_id = decode_hex::<32>(lines.next().ok_or("missing auction_id")?, "auction_id")?;
    let bidder = decode_hex::<32>(lines.next().ok_or("missing bidder")?, "bidder")?;
    let quote_mint = decode_hex::<32>(lines.next().ok_or("missing quote_mint")?, "quote_mint")?;
    let quote_escrow = decode_hex::<32>(lines.next().ok_or("missing quote_vault")?, "quote_vault")?;
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

    Ok((statement, stdin))
}

fn setup_and_check_vkey<P: Prover>(client: &P) -> Result<P::ProvingKey, Box<dyn Error>> {
    let proving_key = client
        .setup(GUEST_ELF.into())
        .map_err(|_| std::io::Error::other("SP1_SETUP_FAILED"))?;
    let vkey_hash = proving_key.verifying_key().bytes32();
    if vkey_hash != EXPECTED_VKEY_HASH {
        return Err(format!(
            "guest verifier key changed: expected {EXPECTED_VKEY_HASH}, got {vkey_hash}"
        )
        .into());
    }
    Ok(proving_key)
}

#[cfg(feature = "sp1-network")]
pub fn check_network_vkey() -> Result<(), Box<dyn Error>> {
    use sp1_sdk::network::NetworkMode;

    eprintln!("SP1_PROGRESS=network_client_build");
    let client = ProverClient::builder()
        .network_for(NetworkMode::Reserved)
        .private()
        .build();
    eprintln!("SP1_PROGRESS=guest_key_setup");
    let proving_key = client
        .setup(GUEST_ELF.into())
        .map_err(|_| std::io::Error::other("SP1_SETUP_FAILED"))?;
    let vkey_hash = proving_key.verifying_key().bytes32();
    println!("SP1_GUEST_VKEY_HASH={vkey_hash}");
    if vkey_hash != EXPECTED_VKEY_HASH {
        println!("SP1_GUEST_VKEY_MATCH=NO");
        return Err("SP1_GUEST_VKEY_MISMATCH".into());
    }
    println!("SP1_GUEST_VKEY_MATCH=OK");
    Ok(())
}

fn verify_and_print<P: Prover>(
    client: &P,
    proof: SP1ProofWithPublicValues,
    verifying_key: &SP1VerifyingKey,
    statement: &BidStatement,
) -> Result<(), Box<dyn Error>> {
    client
        .verify(&proof, verifying_key, None)
        .map_err(|_| std::io::Error::other("SP1_HOST_VERIFICATION_FAILED"))?;

    let proof_bytes = proof.bytes();
    let public_values = proof.public_values.as_slice();
    if proof_bytes.len() != SP1_V6_PROOF_LEN || public_values != statement.public_values() {
        return Err("generated proof does not match the on-chain encoding".into());
    }

    println!("commitment={}", hex::encode(statement.bid_commitment));
    println!("proof={}", hex::encode(proof_bytes));
    println!("public_values={}", hex::encode(public_values));
    println!("sp1_vkey_hash={}", verifying_key.bytes32());
    Ok(())
}

#[cfg(feature = "sp1-prover")]
pub fn run_cpu() -> Result<(), Box<dyn Error>> {
    let (statement, stdin) = prepare_input()?;
    let client = ProverClient::builder().cpu().build();
    let proving_key = setup_and_check_vkey(&client)?;
    let verifying_key = proving_key.verifying_key();
    let proof = client
        .prove(&proving_key, stdin)
        .groth16()
        .run()
        .map_err(|_| std::io::Error::other("SP1_CPU_PROOF_FAILED"))?;
    verify_and_print(&client, proof, verifying_key, &statement)
}

#[cfg(feature = "sp1-network")]
pub fn run_network() -> Result<(), Box<dyn Error>> {
    use sp1_sdk::network::{FulfillmentStrategy, NetworkMode};

    let (statement, stdin) = prepare_input()?;
    sp1_sdk::network::validation::validate_strategy_compatibility(
        NetworkMode::Reserved,
        FulfillmentStrategy::Reserved,
    )
    .map_err(|_| std::io::Error::other("SP1_STRATEGY_CONFIGURATION_INVALID"))?;
    eprintln!("SP1_PROGRESS=network_client_build");
    let client = ProverClient::builder()
        .network_for(NetworkMode::Reserved)
        .private()
        .build();
    eprintln!("SP1_PROGRESS=guest_key_setup");
    let proving_key = setup_and_check_vkey(&client)?;
    let verifying_key = proving_key.verifying_key();
    eprintln!("SP1_PROGRESS=private_reserved_request_submit");
    let request_id = client
        .prove(&proving_key, stdin)
        .strategy(FulfillmentStrategy::Reserved)
        .private_stdin(true)
        .groth16()
        .request()
        .map_err(|error| {
            safe_network_failure(
                "private_reserved_submit",
                error.downcast_ref::<sp1_sdk::network::Error>(),
            )
        })?;
    eprintln!("SP1_REQUEST_ID=0x{}", hex::encode(request_id.as_slice()));
    eprintln!("SP1_PROGRESS=waiting_for_private_reserved_proof");
    let proof = client.wait_proof(request_id, None, None).map_err(|error| {
        safe_network_failure(
            "private_reserved_wait",
            error.downcast_ref::<sp1_sdk::network::Error>(),
        )
    })?;
    eprintln!("SP1_PROGRESS=local_host_verification");
    verify_and_print(&client, proof, verifying_key, &statement)
}

#[cfg(all(test, feature = "sp1-network"))]
mod network_error_tests {
    use super::safe_network_error_summary;
    use sp1_sdk::network::Error as NetworkError;

    #[test]
    fn typed_request_errors_preserve_only_the_safe_request_id() {
        let request_id = vec![0xab; 32];
        let error = NetworkError::RequestTimedOut { request_id };

        let summary = safe_network_error_summary(Some(&error));

        assert_eq!(
            summary,
            format!("SP1_REQUEST_TIMED_OUT request_id=0x{}", "ab".repeat(32))
        );
    }

    #[test]
    fn unknown_error_messages_are_not_forwarded() {
        let summary = safe_network_error_summary(None);

        assert_eq!(summary, "SP1_ERROR_UNCLASSIFIED");
    }
}
