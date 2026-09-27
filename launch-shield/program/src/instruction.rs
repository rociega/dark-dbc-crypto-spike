use solana_program::program_error::ProgramError;

pub const SP1_PROOF_LEN: usize = 260;
pub const BID_PUBLIC_VALUES_LEN: usize = 200;

pub enum ShieldInstruction {
    InitializeConfig {
        vkey_hash: [u8; 66],
    },
    InitializeAuction {
        auction_id: [u8; 32],
        commit_slots: u64,
        reveal_slots: u64,
        max_bid_amount: u64,
        bond_lamports: u64,
        min_output_numerator: u64,
        min_output_denominator: u64,
    },
    CommitBid {
        commitment: [u8; 32],
        proof: [u8; SP1_PROOF_LEN],
        public_values: [u8; BID_PUBLIC_VALUES_LEN],
    },
    RevealBid {
        amount: u64,
        salt: [u8; 32],
    },
    ForfeitUnrevealed,
    PrepareSettlement,
    FinalizeSettlement,
    Claim,
    CancelUnsettled,
    RefundCancelledBid,
}

pub fn unpack(data: &[u8]) -> Result<ShieldInstruction, ProgramError> {
    let (&tag, payload) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match tag {
        0 => Ok(ShieldInstruction::InitializeConfig {
            vkey_hash: exact_array(payload)?,
        }),
        1 => {
            if payload.len() != 32 + 6 * 8 {
                return Err(ProgramError::InvalidInstructionData);
            }
            Ok(ShieldInstruction::InitializeAuction {
                auction_id: array_at(payload, 0)?,
                commit_slots: u64_at(payload, 32)?,
                reveal_slots: u64_at(payload, 40)?,
                max_bid_amount: u64_at(payload, 48)?,
                bond_lamports: u64_at(payload, 56)?,
                min_output_numerator: u64_at(payload, 64)?,
                min_output_denominator: u64_at(payload, 72)?,
            })
        }
        2 => {
            if payload.len() != 32 + SP1_PROOF_LEN + BID_PUBLIC_VALUES_LEN {
                return Err(ProgramError::InvalidInstructionData);
            }
            let commitment = array_at(payload, 0)?;
            let proof_start = 32;
            let proof_end = proof_start + SP1_PROOF_LEN;
            let proof = payload[proof_start..proof_end]
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            let public_values = payload[proof_end..]
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            Ok(ShieldInstruction::CommitBid {
                commitment,
                proof,
                public_values,
            })
        }
        3 => {
            if payload.len() != 8 + 32 {
                return Err(ProgramError::InvalidInstructionData);
            }
            Ok(ShieldInstruction::RevealBid {
                amount: u64_at(payload, 0)?,
                salt: array_at(payload, 8)?,
            })
        }
        4 | 5 | 6 | 7 | 8 | 9 if payload.is_empty() => Ok(match tag {
            4 => ShieldInstruction::ForfeitUnrevealed,
            5 => ShieldInstruction::PrepareSettlement,
            6 => ShieldInstruction::FinalizeSettlement,
            7 => ShieldInstruction::Claim,
            8 => ShieldInstruction::CancelUnsettled,
            _ => ShieldInstruction::RefundCancelledBid,
        }),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn exact_array<const N: usize>(data: &[u8]) -> Result<[u8; N], ProgramError> {
    if data.len() != N {
        return Err(ProgramError::InvalidInstructionData);
    }
    data.try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)
}

fn array_at<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], ProgramError> {
    let end = offset
        .checked_add(N)
        .ok_or(ProgramError::InvalidInstructionData)?;
    data.get(offset..end)
        .ok_or(ProgramError::InvalidInstructionData)?
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)
}

fn u64_at(data: &[u8], offset: usize) -> Result<u64, ProgramError> {
    Ok(u64::from_le_bytes(array_at(data, offset)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_empty_lifecycle_instruction_tags() {
        let parsed = [
            ShieldInstruction::ForfeitUnrevealed,
            ShieldInstruction::PrepareSettlement,
            ShieldInstruction::FinalizeSettlement,
            ShieldInstruction::Claim,
            ShieldInstruction::CancelUnsettled,
            ShieldInstruction::RefundCancelledBid,
        ];
        for (offset, expected) in parsed.iter().enumerate() {
            let tag = u8::try_from(offset + 4).unwrap();
            let actual = unpack(&[tag]).unwrap();
            assert_eq!(
                std::mem::discriminant(&actual),
                std::mem::discriminant(expected)
            );
        }
        assert!(matches!(
            unpack(&[9, 0]),
            Err(ProgramError::InvalidInstructionData)
        ));
    }

    #[test]
    fn rejects_truncated_or_trailing_commit_payloads() {
        let expected_len = 1 + 32 + SP1_PROOF_LEN + BID_PUBLIC_VALUES_LEN;
        assert!(matches!(
            unpack(&vec![2; expected_len - 1]),
            Err(ProgramError::InvalidInstructionData)
        ));
        assert!(matches!(
            unpack(&vec![2; expected_len + 1]),
            Err(ProgramError::InvalidInstructionData)
        ));
    }
}