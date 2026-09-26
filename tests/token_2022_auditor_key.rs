use curve25519_dalek::scalar::Scalar;
use solana_program_test::{ProgramTest, processor, tokio};
use solana_sdk::{
    signature::{Keypair, Signer},
    system_instruction,
    transaction::Transaction,
};
use solana_zk_sdk::encryption::elgamal::{ElGamalPubkey, ElGamalSecretKey};
use solana_zk_sdk_token::encryption::{
    elgamal::ElGamalPubkey as TokenElGamalPubkey,
    pod::elgamal::PodElGamalPubkey as TokenPodElGamalPubkey,
};
use spl_token_2022::{
    extension::{
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
        confidential_transfer::{
            ConfidentialTransferMint, instruction as confidential_transfer_instruction,
        },
    },
    instruction as token_instruction,
    processor::Processor,
    state::Mint,
};

#[tokio::test]
async fn token_2022_program_initializes_mint_with_sdk_elgamal_pod_key() {
    // Test-only key from a known scalar; this does not model or validate a DKG.
    let secret = ElGamalSecretKey::from(Scalar::from(42_424_242u64));
    let sdk_pubkey = ElGamalPubkey::new(&secret);
    let serialized_pubkey = sdk_pubkey.get_point().compress().to_bytes();
    let token_pubkey = TokenElGamalPubkey::try_from(serialized_pubkey.as_slice())
        .expect("the Token-2022 SDK version must decode the current SDK key bytes");
    let auditor_key: TokenPodElGamalPubkey = token_pubkey.into();
    let token_program_id = spl_token_2022::id();

    let program_test = ProgramTest::new(
        "spl_token_2022",
        token_program_id,
        processor!(Processor::process),
    );
    let mut context = program_test.start_with_context().await;

    let mint = Keypair::new();
    let mint_extensions = [ExtensionType::ConfidentialTransferMint];
    let mint_len = ExtensionType::try_calculate_account_len::<Mint>(&mint_extensions).unwrap();
    let rent = context.banks_client.get_rent().await.unwrap();
    let create_mint = system_instruction::create_account(
        &context.payer.pubkey(),
        &mint.pubkey(),
        rent.minimum_balance(mint_len),
        mint_len as u64,
        &token_program_id,
    );
    let initialize_confidential_transfer = confidential_transfer_instruction::initialize_mint(
        &token_program_id,
        &mint.pubkey(),
        Some(context.payer.pubkey()),
        true,
        Some(auditor_key),
    )
    .unwrap();
    let initialize_base_mint = token_instruction::initialize_mint2(
        &token_program_id,
        &mint.pubkey(),
        &context.payer.pubkey(),
        None,
        6,
    )
    .unwrap();

    let transaction = Transaction::new_signed_with_payer(
        &[
            create_mint,
            initialize_confidential_transfer,
            initialize_base_mint,
        ],
        Some(&context.payer.pubkey()),
        &[&context.payer, &mint],
        context.last_blockhash,
    );
    context
        .banks_client
        .process_transaction(transaction)
        .await
        .expect("Token-2022 should accept and store the SDK Pod auditor key");

    let mint_account = context
        .banks_client
        .get_account(mint.pubkey())
        .await
        .unwrap()
        .expect("initialized mint account");
    let mint_state = StateWithExtensions::<Mint>::unpack(&mint_account.data).unwrap();
    let confidential_transfer_mint = mint_state
        .get_extension::<ConfidentialTransferMint>()
        .unwrap();
    assert!(
        confidential_transfer_mint
            .auditor_elgamal_pubkey
            .equals(&auditor_key),
        "mint must retain the exact SDK-derived Pod auditor key"
    );
}
