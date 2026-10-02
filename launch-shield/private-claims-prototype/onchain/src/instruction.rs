use solana_program::program_error::ProgramError;

use private_claims_proof_relation::aggregate::{
    AGGREGATE_DECRYPTION_PUBLIC_VALUES_LEN, TRUSTEE_KEY_SETUP_PUBLIC_VALUES_LEN,
};

pub const SP1_PROOF_LEN: usize = 356;
pub const BID_PUBLIC_VALUES_LEN: usize = 200;
pub const CLAIM_PUBLIC_VALUES_LEN: usize = 208;
pub const FUNDING_PUBLIC_VALUES_LEN: usize = private_claims_proof_relation::PUBLIC_VALUES_LEN;
pub const DECRYPTABLE_BALANCE_LEN: usize =
    std::mem::size_of::<spl_token_2022::extension::confidential_transfer::DecryptableBalance>();

pub enum ClaimsInstruction<'a> {
    Initialize {
        nonce: [u8; 32],
        funding_mint: [u8; 32],
        confidential_vault: [u8; 32],
        output_mint: [u8; 32],
        vault: [u8; 32],
        total_output_amount: u64,
    },
    ConfigureTrustees {
        key_epoch: [u8; 32],
        trustee_ids: [[u8; 32]; 3],
        verification_shares: [[u8; 32]; 3],
        proof: &'a [u8],
        public_values: &'a [u8],
    },
    FundBid {
        new_source_decryptable_balance: &'a [u8],
        proof: &'a [u8],
        public_values: &'a [u8],
    },
    FinalizeFunding,
    Settle {
        proof: &'a [u8],
        public_values: &'a [u8],
    },
    RegisterClaim {
        proof: &'a [u8],
        public_values: &'a [u8],
    },
    Redeem {
        proof: &'a [u8],
        public_values: &'a [u8],
    },
}

impl<'a> ClaimsInstruction<'a> {
    pub fn unpack(input: &'a [u8]) -> Result<Self, ProgramError> {
        let (tag, body) = input
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;
        match tag {
            0 => {
                if body.len() != 32 * 5 + 8 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let mut offset = 0;
                let nonce = read_array(body, &mut offset)?;
                let funding_mint = read_array(body, &mut offset)?;
                let confidential_vault = read_array(body, &mut offset)?;
                let output_mint = read_array(body, &mut offset)?;
                let vault = read_array(body, &mut offset)?;
                let total_output_amount = read_u64(body, &mut offset)?;
                Ok(Self::Initialize {
                    nonce,
                    funding_mint,
                    confidential_vault,
                    output_mint,
                    vault,
                    total_output_amount,
                })
            }
            6 => {
                let expected_len =
                    32 + 3 * 32 + 3 * 32 + SP1_PROOF_LEN + TRUSTEE_KEY_SETUP_PUBLIC_VALUES_LEN;
                if body.len() != expected_len {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let mut offset = 0;
                let key_epoch = read_array(body, &mut offset)?;
                let mut trustee_ids = [[0; 32]; 3];
                for trustee_id in &mut trustee_ids {
                    *trustee_id = read_array(body, &mut offset)?;
                }
                let mut verification_shares = [[0; 32]; 3];
                for share in &mut verification_shares {
                    *share = read_array(body, &mut offset)?;
                }
                let proof_end = offset + SP1_PROOF_LEN;
                let proof = &body[offset..proof_end];
                let public_values = &body[proof_end..];
                Ok(Self::ConfigureTrustees {
                    key_epoch,
                    trustee_ids,
                    verification_shares,
                    proof,
                    public_values,
                })
            }
            3 => {
                let expected_len =
                    DECRYPTABLE_BALANCE_LEN + SP1_PROOF_LEN + FUNDING_PUBLIC_VALUES_LEN;
                if body.len() != expected_len {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let balance_end = DECRYPTABLE_BALANCE_LEN;
                let proof_end = balance_end + SP1_PROOF_LEN;
                Ok(Self::FundBid {
                    new_source_decryptable_balance: &body[..balance_end],
                    proof: &body[balance_end..proof_end],
                    public_values: &body[proof_end..],
                })
            }
            4 if body.is_empty() => Ok(Self::FinalizeFunding),
            5 => {
                if body.len() != SP1_PROOF_LEN + AGGREGATE_DECRYPTION_PUBLIC_VALUES_LEN {
                    return Err(ProgramError::InvalidInstructionData);
                }
                Ok(Self::Settle {
                    proof: &body[..SP1_PROOF_LEN],
                    public_values: &body[SP1_PROOF_LEN..],
                })
            }
            1 => {
                if body.len() != SP1_PROOF_LEN + CLAIM_PUBLIC_VALUES_LEN {
                    return Err(ProgramError::InvalidInstructionData);
                }
                Ok(Self::RegisterClaim {
                    proof: &body[..SP1_PROOF_LEN],
                    public_values: &body[SP1_PROOF_LEN..],
                })
            }
            2 => {
                if body.len() != SP1_PROOF_LEN + BID_PUBLIC_VALUES_LEN {
                    return Err(ProgramError::InvalidInstructionData);
                }
                Ok(Self::Redeem {
                    proof: &body[..SP1_PROOF_LEN],
                    public_values: &body[SP1_PROOF_LEN..],
                })
            }
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

fn read_array<const N: usize>(input: &[u8], offset: &mut usize) -> Result<[u8; N], ProgramError> {
    let end = offset
        .checked_add(N)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let bytes = input
        .get(*offset..end)
        .ok_or(ProgramError::InvalidInstructionData)?;
    *offset = end;
    bytes
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)
}

fn read_u64(input: &[u8], offset: &mut usize) -> Result<u64, ProgramError> {
    Ok(u64::from_le_bytes(read_array(input, offset)?))
}

#[cfg(test)]
mod tests {
    use super::{
        ClaimsInstruction, AGGREGATE_DECRYPTION_PUBLIC_VALUES_LEN, BID_PUBLIC_VALUES_LEN,
        CLAIM_PUBLIC_VALUES_LEN, DECRYPTABLE_BALANCE_LEN, FUNDING_PUBLIC_VALUES_LEN, SP1_PROOF_LEN,
        TRUSTEE_KEY_SETUP_PUBLIC_VALUES_LEN,
    };

    #[test]
    fn instruction_decoder_enforces_exact_payload_lengths() {
        let initialize = [vec![0], vec![0; 32 * 5 + 8]].concat();
        assert!(matches!(
            ClaimsInstruction::unpack(&initialize),
            Ok(ClaimsInstruction::Initialize { .. })
        ));

        let register = [vec![1], vec![0; SP1_PROOF_LEN + CLAIM_PUBLIC_VALUES_LEN]].concat();
        assert!(matches!(
            ClaimsInstruction::unpack(&register),
            Ok(ClaimsInstruction::RegisterClaim { .. })
        ));

        let redeem = [vec![2], vec![0; SP1_PROOF_LEN + BID_PUBLIC_VALUES_LEN]].concat();
        assert!(matches!(
            ClaimsInstruction::unpack(&redeem),
            Ok(ClaimsInstruction::Redeem { .. })
        ));

        let fund_bid = [
            vec![3],
            vec![0; DECRYPTABLE_BALANCE_LEN + SP1_PROOF_LEN + FUNDING_PUBLIC_VALUES_LEN],
        ]
        .concat();
        assert!(matches!(
            ClaimsInstruction::unpack(&fund_bid),
            Ok(ClaimsInstruction::FundBid { .. })
        ));
        assert!(matches!(
            ClaimsInstruction::unpack(&[4]),
            Ok(ClaimsInstruction::FinalizeFunding)
        ));
        let configure_trustees = [
            vec![6],
            vec![0; 32 + 3 * 32 + 3 * 32 + SP1_PROOF_LEN + TRUSTEE_KEY_SETUP_PUBLIC_VALUES_LEN],
        ]
        .concat();
        assert!(matches!(
            ClaimsInstruction::unpack(&configure_trustees),
            Ok(ClaimsInstruction::ConfigureTrustees { .. })
        ));
        assert!(matches!(
            ClaimsInstruction::unpack(
                &[
                    vec![5],
                    vec![0; SP1_PROOF_LEN + AGGREGATE_DECRYPTION_PUBLIC_VALUES_LEN]
                ]
                .concat()
            ),
            Ok(ClaimsInstruction::Settle { .. })
        ));
    }

    #[test]
    fn instruction_decoder_rejects_trailing_truncated_and_unknown_data() {
        assert!(ClaimsInstruction::unpack(&[]).is_err());
        assert!(ClaimsInstruction::unpack(&[3]).is_err());
        assert!(ClaimsInstruction::unpack(&[0; 144]).is_err());
        assert!(ClaimsInstruction::unpack(&[1; 564]).is_err());
        assert!(ClaimsInstruction::unpack(&[2; 556]).is_err());
        assert!(ClaimsInstruction::unpack(&[1; 566]).is_err());
        assert!(ClaimsInstruction::unpack(&[2; 558]).is_err());
    }
}
