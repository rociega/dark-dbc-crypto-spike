use private_claims_onchain::process_instruction;
use private_claims_proof_relation::{
    aggregate::AGGREGATE_DECRYPTION_PUBLIC_VALUES_LEN, PUBLIC_VALUES_LEN,
};
use solana_program_test::{processor, ProgramTest};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Signer,
    transaction::Transaction,
};

const SP1_PROOF_LEN: usize = 356;

fn fail_closed_instruction_data() -> [Vec<u8>; 3] {
    let mut initialize = vec![0; 1 + 5 * 32 + 8];
    initialize[0] = 0;

    let mut fund_bid = vec![
        0;
        1 + std::mem::size_of::<
            spl_token_2022::extension::confidential_transfer::DecryptableBalance,
        >() + SP1_PROOF_LEN
            + PUBLIC_VALUES_LEN
    ];
    fund_bid[0] = 3;

    let mut settle = vec![0; 1 + SP1_PROOF_LEN + AGGREGATE_DECRYPTION_PUBLIC_VALUES_LEN];
    settle[0] = 5;

    [initialize, fund_bid, settle]
}

#[tokio::test]
async fn gated_instructions_leave_writable_account_unchanged() {
    let program_id = Pubkey::new_unique();
    let sentinel_key = Pubkey::new_unique();
    let sentinel = Account {
        lamports: 1_000_000,
        data: b"unchanged".to_vec(),
        owner: program_id,
        executable: false,
        rent_epoch: 0,
    };
    let mut program_test = ProgramTest::new(
        "private_claims_onchain",
        program_id,
        processor!(process_instruction),
    );
    program_test.add_account(sentinel_key, sentinel.clone());
    let context = program_test.start_with_context().await;

    for instruction_data in fail_closed_instruction_data() {
        let instruction = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(sentinel_key, false)],
            data: instruction_data,
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
            .expect_err("Initialize, FundBid, and Settle must remain fail-closed");
        assert!(
            format!("{error:?}").contains("Custom(3)"),
            "unexpected fail-closed error: {error:?}"
        );
        let after = context
            .banks_client
            .get_account(sentinel_key)
            .await
            .expect("account lookup succeeds")
            .expect("sentinel account remains present");
        assert_eq!(after.lamports, sentinel.lamports);
        assert_eq!(after.data, sentinel.data);
        assert_eq!(after.owner, sentinel.owner);
        assert_eq!(after.executable, sentinel.executable);
    }
}
