#[path = "../proof_runner.rs"]
mod proof_runner;

fn check_signer_format() -> Result<(), Box<dyn std::error::Error>> {
    let private_key = std::env::var("NETWORK_PRIVATE_KEY")
        .map_err(|_| std::io::Error::other("NETWORK_PRIVATE_KEY is missing"))?;
    sp1_sdk::network::signer::NetworkSigner::local(&private_key).map_err(|_| {
        std::io::Error::other(
            "NETWORK_PRIVATE_KEY is not valid EVM private-key hex; value withheld",
        )
    })?;
    println!("NETWORK_PRIVATE_KEY_FORMAT_OK");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    match args.next() {
        Some(arg) if arg == "--check-signer" => {
            if args.next().is_some() {
                return Err(std::io::Error::other(
                    "usage: launch-shield-prove-network [--check-signer|--check-vkey]",
                )
                .into());
            }
            check_signer_format()
        }
        Some(arg) if arg == "--check-vkey" => {
            if args.next().is_some() {
                return Err(std::io::Error::other(
                    "usage: launch-shield-prove-network [--check-signer|--check-vkey]",
                )
                .into());
            }
            proof_runner::check_network_vkey()
        }
        None => proof_runner::run_network(),
        _ => {
            Err(std::io::Error::other(
                "usage: launch-shield-prove-network [--check-signer|--check-vkey]",
            )
            .into())
        }
    }
}
