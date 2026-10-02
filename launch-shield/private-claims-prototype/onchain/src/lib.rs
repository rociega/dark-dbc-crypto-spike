#![allow(unexpected_cfgs)]

use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, pubkey::Pubkey,
};

mod instruction;
pub mod dbc;
mod processor;
mod state;

pub use processor::derive_auction_id;

#[allow(dead_code)]
#[path = "../../../program/src/sp1_v6.rs"]
mod sp1_v6;

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    processor::process(program_id, accounts, instruction_data)
}

pub fn verify_sp1_v6_proof_bytes(
    proof: &[u8],
    public_values: &[u8],
    guest_vkey_hash: &str,
) -> Result<(), ()> {
    sp1_v6::verify_sp1_v6_proof(proof, public_values, guest_vkey_hash)
}
