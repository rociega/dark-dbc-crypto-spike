use solana_program::{hash::hashv, pubkey::Pubkey};

pub const BID_PUBLIC_VALUES_LEN: usize = 200;
pub const BID_COMMITMENT_DOMAIN: &[u8] = b"meteora-launch-shield:sealed-bid:v1";

pub fn bid_commitment(
    program_id: &Pubkey,
    auction_id: &[u8; 32],
    bidder: &Pubkey,
    amount: u64,
    salt: &[u8; 32],
) -> [u8; 32] {
    hashv(&[
        BID_COMMITMENT_DOMAIN,
        program_id.as_ref(),
        auction_id,
        bidder.as_ref(),
        &amount.to_le_bytes(),
        salt,
    ])
    .to_bytes()
}

pub fn public_values(
    program_id: &Pubkey,
    auction_id: &[u8; 32],
    bidder: &Pubkey,
    commitment: &[u8; 32],
    quote_mint: &Pubkey,
    quote_vault: &Pubkey,
    max_bid_amount: u64,
) -> [u8; BID_PUBLIC_VALUES_LEN] {
    let mut output = [0u8; BID_PUBLIC_VALUES_LEN];
    let fields: [&[u8]; 6] = [
        program_id.as_ref(),
        auction_id,
        bidder.as_ref(),
        commitment,
        quote_mint.as_ref(),
        quote_vault.as_ref(),
    ];
    let mut offset = 0;
    for field in fields {
        output[offset..offset + 32].copy_from_slice(field);
        offset += 32;
    }
    output[offset..offset + 8].copy_from_slice(&max_bid_amount.to_le_bytes());
    output
}

pub fn parse_vkey_hash(value: &[u8; 66]) -> Result<&str, ()> {
    let text = core::str::from_utf8(value).map_err(|_| ())?;
    if text.len() != 66
        || !text.starts_with("0x")
        || !text.as_bytes()[2..]
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(());
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_binds_context_and_secret_witness() {
        let program = Pubkey::new_unique();
        let bidder = Pubkey::new_unique();
        let auction = [3; 32];
        let salt = [8; 32];
        let commitment = bid_commitment(&program, &auction, &bidder, 42, &salt);
        assert_eq!(
            commitment,
            bid_commitment(&program, &auction, &bidder, 42, &salt)
        );
        assert_ne!(
            commitment,
            bid_commitment(&program, &auction, &bidder, 43, &salt)
        );
        assert_ne!(
            commitment,
            bid_commitment(&program, &auction, &bidder, 42, &[9; 32])
        );
        assert_ne!(
            commitment,
            bid_commitment(&program, &[4; 32], &bidder, 42, &salt)
        );
    }

    #[test]
    fn public_values_have_the_fixed_200_byte_layout() {
        let program = Pubkey::new_unique();
        let auction = [1; 32];
        let bidder = Pubkey::new_unique();
        let commitment = [2; 32];
        let mint = Pubkey::new_unique();
        let vault = Pubkey::new_unique();
        let bytes = public_values(
            &program,
            &auction,
            &bidder,
            &commitment,
            &mint,
            &vault,
            0x0102_0304_0506_0708,
        );
        assert_eq!(&bytes[..32], program.as_ref());
        assert_eq!(&bytes[32..64], &auction);
        assert_eq!(&bytes[64..96], bidder.as_ref());
        assert_eq!(&bytes[96..128], &commitment);
        assert_eq!(&bytes[128..160], mint.as_ref());
        assert_eq!(&bytes[160..192], vault.as_ref());
        assert_eq!(&bytes[192..], &0x0102_0304_0506_0708u64.to_le_bytes());
    }

    #[test]
    fn onchain_serialization_matches_the_sp1_guest_relation() {
        use launch_shield_proof_relation::{bid_commitment as guest_commitment, BidStatement};

        let program = Pubkey::new_unique();
        let auction_id = [11; 32];
        let bidder = Pubkey::new_unique();
        let quote_mint = Pubkey::new_unique();
        let quote_vault = Pubkey::new_unique();
        let amount = 123_456;
        let salt = [0x5a; 32];

        let mut statement = BidStatement {
            program_id: program.to_bytes(),
            auction_id,
            bidder: bidder.to_bytes(),
            bid_commitment: [0; 32],
            quote_mint: quote_mint.to_bytes(),
            quote_escrow: quote_vault.to_bytes(),
            max_bid_amount: 500_000,
        };
        statement.bid_commitment = guest_commitment(&statement, amount, &salt);

        let onchain_commitment =
            bid_commitment(&program, &auction_id, &bidder, amount, &salt);
        assert_eq!(onchain_commitment, statement.bid_commitment);
        assert_eq!(
            public_values(
                &program,
                &auction_id,
                &bidder,
                &onchain_commitment,
                &quote_mint,
                &quote_vault,
                statement.max_bid_amount,
            ),
            statement.public_values()
        );
    }
}