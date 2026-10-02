#[path = "../proof_runner.rs"]
mod proof_runner;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    proof_runner::run_cpu()
}
