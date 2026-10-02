#![allow(deprecated)]

use solana_program::{hash::hash, pubkey::Pubkey};
use solana_program_test::ProgramTest;
use solana_sdk::{
    instruction::Instruction,
    signature::Signer,
    transaction::Transaction,
};

const DBC_PROGRAM_ID: Pubkey =
    solana_program::pubkey!("dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN");
const DEVNET_DBC_SHA256: [u8; 32] = [
    0xf5, 0xcc, 0xbb, 0x01, 0xe3, 0x71, 0x65, 0xd1, 0x61, 0x08, 0xbd, 0xa0, 0x25, 0x9f, 0xb3, 0xac,
    0xbf, 0xca, 0x29, 0x30, 0x5e, 0x23, 0x09, 0x8c, 0x3b, 0x24, 0x8e, 0x50, 0xc2, 0x29, 0x79, 0xf0,
];

#[tokio::test]
#[ignore = "requires BPF_OUT_DIR containing dynamic_bonding_curve.so from the read-only Devnet fetch"]
async fn deployed_devnet_dbc_elf_reaches_anchor_instruction_dispatch() {
    let elf_path = std::path::Path::new(
        &std::env::var("BPF_OUT_DIR").expect("BPF_OUT_DIR must contain the verified DBC ELF"),
    )
    .join("dynamic_bonding_curve.so");
    let elf = std::fs::read(&elf_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", elf_path.display()));
    assert_eq!(
        hash(&elf).to_bytes(),
        DEVNET_DBC_SHA256,
        "BPF_OUT_DIR does not contain the recorded Devnet DBC executable"
    );

    let mut test = ProgramTest::default();
    test.add_program("dynamic_bonding_curve", DBC_PROGRAM_ID, None);
    let context = test.start_with_context().await;

    let instruction = Instruction {
        program_id: DBC_PROGRAM_ID,
        accounts: Vec::new(),
        data: Vec::new(),
    };
    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );
    let error = context
        .banks_client
        .process_transaction(transaction)
        .await
        .expect_err("empty Anchor instruction data must be rejected");
    assert!(
        format!("{error:?}").contains("Custom(101)"),
        "expected the deployed DBC program's Anchor dispatch error, got {error:?}"
    );
}