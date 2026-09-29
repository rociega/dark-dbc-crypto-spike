use solana_program::{
    hash::hashv,
    program_error::ProgramError,
};

pub const MAX_CLAIMS: usize = 8;
pub const MAX_FUNDED_BIDS: usize = private_claims_proof_relation::MAX_FUNDED_BIDS;
pub const CLAIM_POOL_DATA_LEN: usize = 1_590;

const STATE_VERSION: u8 = 3;
const NOTE_LEAF_DOMAIN: &[u8] = b"private-claims:note-leaf:test-v1";
const NOTE_NODE_DOMAIN: &[u8] = b"private-claims:note-node:test-v1";
const INVALID_STATE: ProgramError = ProgramError::InvalidAccountData;
const INVALID_TRANSITION: ProgramError = ProgramError::Custom(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimPool {
    pub authority: [u8; 32],
    pub auction_id: [u8; 32],
    pub funded_bid_root: [u8; 32],
    pub funding_mint: [u8; 32],
    pub confidential_vault: [u8; 32],
    pub auditor_pubkey: [u8; 32],
    pub confidential_vault_elgamal_pubkey: [u8; 32],
    pub output_mint: [u8; 32],
    pub vault: [u8; 32],
    pub total_bid_amount: u64,
    pub total_output_amount: u64,
    pub funded_bid_count: u8,
    pub funded_bid_commitments: [[u8; 32]; MAX_FUNDED_BIDS],
    pub accepted_transfer_context_hashes: [[u8; 32]; MAX_FUNDED_BIDS],
    pub funding_finalized: bool,
    pub settled: bool,
    pub note_count: u8,
    pub note_commitments: [[u8; 32]; MAX_CLAIMS],
    pub claim_nullifiers: [[u8; 32]; MAX_CLAIMS],
    pub spent_count: u8,
    pub spent_redemption_nullifiers: [[u8; 32]; MAX_CLAIMS],
}

impl ClaimPool {
    pub fn new(
        authority: [u8; 32],
        auction_id: [u8; 32],
        funding_mint: [u8; 32],
        confidential_vault: [u8; 32],
        auditor_pubkey: [u8; 32],
        confidential_vault_elgamal_pubkey: [u8; 32],
        output_mint: [u8; 32],
        vault: [u8; 32],
        total_bid_amount: u64,
        total_output_amount: u64,
    ) -> Self {
        let funded_bid_commitments = [[0; 32]; MAX_FUNDED_BIDS];
        Self {
            authority,
            auction_id,
            funded_bid_root: private_claims_proof_relation::funded_bid_merkle_root(
                &funded_bid_commitments,
            ),
            funding_mint,
            confidential_vault,
            auditor_pubkey,
            confidential_vault_elgamal_pubkey,
            output_mint,
            vault,
            total_bid_amount,
            total_output_amount,
            funded_bid_count: 0,
            funded_bid_commitments,
            accepted_transfer_context_hashes: [[0; 32]; MAX_FUNDED_BIDS],
            funding_finalized: false,
            settled: false,
            note_count: 0,
            note_commitments: [[0; 32]; MAX_CLAIMS],
            claim_nullifiers: [[0; 32]; MAX_CLAIMS],
            spent_count: 0,
            spent_redemption_nullifiers: [[0; 32]; MAX_CLAIMS],
        }
    }

    pub fn append_funded_bid(
        &mut self,
        bid_commitment: [u8; 32],
        transfer_context_hash: [u8; 32],
    ) -> Result<(), ProgramError> {
        let count = usize::from(self.funded_bid_count);
        if self.funding_finalized
            || count >= MAX_FUNDED_BIDS
            || bid_commitment == [0; 32]
            || transfer_context_hash == [0; 32]
            || self.funded_bid_commitments[..count].contains(&bid_commitment)
            || self.accepted_transfer_context_hashes[..count].contains(&transfer_context_hash)
        {
            return Err(INVALID_TRANSITION);
        }

        self.funded_bid_commitments[count] = bid_commitment;
        self.accepted_transfer_context_hashes[count] = transfer_context_hash;
        self.funded_bid_count += 1;
        self.funded_bid_root = self.computed_funded_bid_root();
        Ok(())
    }

    pub fn finalize_funding(&mut self) -> Result<(), ProgramError> {
        if self.funding_finalized || self.funded_bid_count == 0 {
            return Err(INVALID_TRANSITION);
        }
        self.funding_finalized = true;
        Ok(())
    }

    pub fn finalize_settlement(&mut self, actual_output_amount: u64) -> Result<(), ProgramError> {
        if !self.funding_finalized
            || self.settled
            || self.total_bid_amount == 0
            || actual_output_amount == 0
        {
            return Err(INVALID_TRANSITION);
        }
        self.total_output_amount = actual_output_amount;
        self.settled = true;
        Ok(())
    }

    fn computed_funded_bid_root(&self) -> [u8; 32] {
        private_claims_proof_relation::funded_bid_merkle_root(&self.funded_bid_commitments)
    }

    pub fn note_root(&self) -> [u8; 32] {
        let mut level: [[u8; 32]; MAX_CLAIMS] = std::array::from_fn(|index| {
            hashv(&[NOTE_LEAF_DOMAIN, &self.note_commitments[index]]).to_bytes()
        });
        let mut nodes = MAX_CLAIMS;
        while nodes > 1 {
            for index in 0..nodes / 2 {
                level[index] = hashv(&[
                    NOTE_NODE_DOMAIN,
                    &level[index * 2],
                    &level[index * 2 + 1],
                ])
                .to_bytes();
            }
            nodes /= 2;
        }
        level[0]
    }

    pub fn register_note(
        &mut self,
        note_commitment: [u8; 32],
        claim_nullifier: [u8; 32],
    ) -> Result<(), ProgramError> {
        let count = usize::from(self.note_count);
        if !self.funding_finalized
            || !self.settled
            || count >= MAX_CLAIMS
            || note_commitment == [0; 32]
            || claim_nullifier == [0; 32]
            || self.claim_nullifiers[..count].contains(&claim_nullifier)
        {
            return Err(INVALID_TRANSITION);
        }
        self.note_commitments[count] = note_commitment;
        self.claim_nullifiers[count] = claim_nullifier;
        self.note_count += 1;
        Ok(())
    }

    pub fn mark_redemption_spent(
        &mut self,
        redemption_nullifier: [u8; 32],
    ) -> Result<(), ProgramError> {
        let count = usize::from(self.spent_count);
        if !self.funding_finalized
            || !self.settled
            || count >= MAX_CLAIMS
            || redemption_nullifier == [0; 32]
            || self.spent_redemption_nullifiers[..count].contains(&redemption_nullifier)
        {
            return Err(INVALID_TRANSITION);
        }
        self.spent_redemption_nullifiers[count] = redemption_nullifier;
        self.spent_count += 1;
        Ok(())
    }

    pub fn pack(&self, output: &mut [u8]) -> Result<(), ProgramError> {
        if output.len() != CLAIM_POOL_DATA_LEN
            || usize::from(self.funded_bid_count) > MAX_FUNDED_BIDS
            || usize::from(self.note_count) > MAX_CLAIMS
            || usize::from(self.spent_count) > MAX_CLAIMS
            || self.funded_bid_root != self.computed_funded_bid_root()
            || (self.funding_finalized && self.funded_bid_count == 0)
            || (self.settled
                && (!self.funding_finalized
                    || self.total_bid_amount == 0
                    || self.total_output_amount == 0))
        {
            return Err(INVALID_STATE);
        }
        validate_funded_slots(
            &self.funded_bid_commitments,
            &self.accepted_transfer_context_hashes,
            self.funded_bid_count,
        )?;
        validate_slots(
            &self.note_commitments,
            &self.claim_nullifiers,
            self.note_count,
        )?;
        validate_spent_slots(&self.spent_redemption_nullifiers, self.spent_count)?;

        let mut offset = 0;
        output[offset] = STATE_VERSION;
        offset += 1;
        for field in [
            &self.authority,
            &self.auction_id,
            &self.funded_bid_root,
            &self.funding_mint,
            &self.confidential_vault,
            &self.auditor_pubkey,
            &self.confidential_vault_elgamal_pubkey,
            &self.output_mint,
            &self.vault,
        ] {
            write_bytes(output, &mut offset, field)?;
        }
        write_bytes(output, &mut offset, &self.total_bid_amount.to_le_bytes())?;
        write_bytes(output, &mut offset, &self.total_output_amount.to_le_bytes())?;
        output[offset] = self.funded_bid_count;
        offset += 1;
        for field in &self.funded_bid_commitments {
            write_bytes(output, &mut offset, field)?;
        }
        for field in &self.accepted_transfer_context_hashes {
            write_bytes(output, &mut offset, field)?;
        }
        output[offset] = u8::from(self.funding_finalized);
        offset += 1;
        output[offset] = u8::from(self.settled);
        offset += 1;
        output[offset] = self.note_count;
        offset += 1;
        for field in &self.note_commitments {
            write_bytes(output, &mut offset, field)?;
        }
        for field in &self.claim_nullifiers {
            write_bytes(output, &mut offset, field)?;
        }
        output[offset] = self.spent_count;
        offset += 1;
        for field in &self.spent_redemption_nullifiers {
            write_bytes(output, &mut offset, field)?;
        }
        if offset != output.len() {
            return Err(INVALID_STATE);
        }
        Ok(())
    }

    pub fn unpack(input: &[u8]) -> Result<Self, ProgramError> {
        if input.len() != CLAIM_POOL_DATA_LEN || input[0] != STATE_VERSION {
            return Err(INVALID_STATE);
        }
        let mut offset = 1;
        let authority = read_array(input, &mut offset)?;
        let auction_id = read_array(input, &mut offset)?;
        let funded_bid_root = read_array(input, &mut offset)?;
        let funding_mint = read_array(input, &mut offset)?;
        let confidential_vault = read_array(input, &mut offset)?;
        let auditor_pubkey = read_array(input, &mut offset)?;
        let confidential_vault_elgamal_pubkey = read_array(input, &mut offset)?;
        let output_mint = read_array(input, &mut offset)?;
        let vault = read_array(input, &mut offset)?;
        let total_bid_amount = u64::from_le_bytes(read_array(input, &mut offset)?);
        let total_output_amount = u64::from_le_bytes(read_array(input, &mut offset)?);
        let funded_bid_count = *input.get(offset).ok_or(INVALID_STATE)?;
        offset += 1;
        let mut funded_bid_commitments = [[0; 32]; MAX_FUNDED_BIDS];
        for item in &mut funded_bid_commitments {
            *item = read_array(input, &mut offset)?;
        }
        let mut accepted_transfer_context_hashes = [[0; 32]; MAX_FUNDED_BIDS];
        for item in &mut accepted_transfer_context_hashes {
            *item = read_array(input, &mut offset)?;
        }
        let funding_finalized_byte = *input.get(offset).ok_or(INVALID_STATE)?;
        if funding_finalized_byte > 1 {
            return Err(INVALID_STATE);
        }
        let funding_finalized = funding_finalized_byte == 1;
        offset += 1;
        let settled_byte = *input.get(offset).ok_or(INVALID_STATE)?;
        if settled_byte > 1 {
            return Err(INVALID_STATE);
        }
        let settled = settled_byte == 1;
        offset += 1;
        let note_count = *input.get(offset).ok_or(INVALID_STATE)?;
        offset += 1;
        let mut note_commitments = [[0; 32]; MAX_CLAIMS];
        for item in &mut note_commitments {
            *item = read_array(input, &mut offset)?;
        }
        let mut claim_nullifiers = [[0; 32]; MAX_CLAIMS];
        for item in &mut claim_nullifiers {
            *item = read_array(input, &mut offset)?;
        }
        let spent_count = *input.get(offset).ok_or(INVALID_STATE)?;
        offset += 1;
        let mut spent_redemption_nullifiers = [[0; 32]; MAX_CLAIMS];
        for item in &mut spent_redemption_nullifiers {
            *item = read_array(input, &mut offset)?;
        }
        if offset != input.len()
            || usize::from(funded_bid_count) > MAX_FUNDED_BIDS
            || usize::from(note_count) > MAX_CLAIMS
            || usize::from(spent_count) > MAX_CLAIMS
            || (funding_finalized && funded_bid_count == 0)
            || (settled
                && (!funding_finalized || total_bid_amount == 0 || total_output_amount == 0))
        {
            return Err(INVALID_STATE);
        }
        validate_funded_slots(
            &funded_bid_commitments,
            &accepted_transfer_context_hashes,
            funded_bid_count,
        )?;
        validate_slots(&note_commitments, &claim_nullifiers, note_count)?;
        validate_spent_slots(&spent_redemption_nullifiers, spent_count)?;

        let state = Self {
            authority,
            auction_id,
            funded_bid_root,
            funding_mint,
            confidential_vault,
            auditor_pubkey,
            confidential_vault_elgamal_pubkey,
            output_mint,
            vault,
            total_bid_amount,
            total_output_amount,
            funded_bid_count,
            funded_bid_commitments,
            accepted_transfer_context_hashes,
            funding_finalized,
            settled,
            note_count,
            note_commitments,
            claim_nullifiers,
            spent_count,
            spent_redemption_nullifiers,
        };
        if state.funded_bid_root != state.computed_funded_bid_root() {
            return Err(INVALID_STATE);
        }
        Ok(state)
    }
}

fn validate_funded_slots(
    commitments: &[[u8; 32]; MAX_FUNDED_BIDS],
    context_hashes: &[[u8; 32]; MAX_FUNDED_BIDS],
    count: u8,
) -> Result<(), ProgramError> {
    let count = usize::from(count);
    if commitments[..count].contains(&[0; 32])
        || context_hashes[..count].contains(&[0; 32])
        || commitments[count..].iter().any(|item| *item != [0; 32])
        || context_hashes[count..].iter().any(|item| *item != [0; 32])
    {
        return Err(INVALID_STATE);
    }
    for index in 0..count {
        if commitments[..index].contains(&commitments[index])
            || context_hashes[..index].contains(&context_hashes[index])
        {
            return Err(INVALID_STATE);
        }
    }
    Ok(())
}

fn validate_slots(
    notes: &[[u8; 32]; MAX_CLAIMS],
    nullifiers: &[[u8; 32]; MAX_CLAIMS],
    count: u8,
) -> Result<(), ProgramError> {
    let count = usize::from(count);
    if notes[..count].contains(&[0; 32])
        || nullifiers[..count].contains(&[0; 32])
        || notes[count..].iter().any(|item| *item != [0; 32])
        || nullifiers[count..].iter().any(|item| *item != [0; 32])
    {
        return Err(INVALID_STATE);
    }
    for index in 0..count {
        if nullifiers[..index].contains(&nullifiers[index]) {
            return Err(INVALID_STATE);
        }
    }
    Ok(())
}

fn validate_spent_slots(
    nullifiers: &[[u8; 32]; MAX_CLAIMS],
    count: u8,
) -> Result<(), ProgramError> {
    let count = usize::from(count);
    if nullifiers[..count].contains(&[0; 32])
        || nullifiers[count..].iter().any(|item| *item != [0; 32])
    {
        return Err(INVALID_STATE);
    }
    for index in 0..count {
        if nullifiers[..index].contains(&nullifiers[index]) {
            return Err(INVALID_STATE);
        }
    }
    Ok(())
}

fn write_bytes(
    output: &mut [u8],
    offset: &mut usize,
    bytes: &[u8],
) -> Result<(), ProgramError> {
    let end = offset.checked_add(bytes.len()).ok_or(INVALID_STATE)?;
    output
        .get_mut(*offset..end)
        .ok_or(INVALID_STATE)?
        .copy_from_slice(bytes);
    *offset = end;
    Ok(())
}

fn read_array<const N: usize>(input: &[u8], offset: &mut usize) -> Result<[u8; N], ProgramError> {
    let end = offset.checked_add(N).ok_or(INVALID_STATE)?;
    let value = input
        .get(*offset..end)
        .ok_or(INVALID_STATE)?
        .try_into()
        .map_err(|_| INVALID_STATE)?;
    *offset = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{ClaimPool, CLAIM_POOL_DATA_LEN, MAX_CLAIMS};
    use solana_program::program_error::ProgramError;

    fn pool() -> ClaimPool {
        let mut state = ClaimPool::new(
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            [5; 32],
            [6; 32],
            [7; 32],
            [8; 32],
            1_000,
            10_000,
        );
        state.append_funded_bid([9; 32], [10; 32]).unwrap();
        state.finalize_funding().unwrap();
        state.finalize_settlement(10_000).unwrap();
        state
    }

    #[test]
    fn state_round_trips_and_tracks_note_root() {
        let mut state = pool();
        let empty_root = state.note_root();
        state.register_note([6; 32], [7; 32]).unwrap();
        assert_ne!(state.note_root(), empty_root);

        let mut data = vec![0; CLAIM_POOL_DATA_LEN];
        state.pack(&mut data).unwrap();
        assert_eq!(ClaimPool::unpack(&data).unwrap(), state);
    }

    #[test]
    fn onchain_note_root_matches_the_guest_relation() {
        let mut state = pool();
        assert_eq!(
            state.note_root(),
            private_claims_proof_relation::claim_note_merkle_root(
                &state.note_commitments
            )
        );

        state.register_note([6; 32], [7; 32]).unwrap();
        assert_eq!(
            state.note_root(),
            private_claims_proof_relation::claim_note_merkle_root(
                &state.note_commitments
            )
        );

        for index in 1..MAX_CLAIMS {
            state
                .register_note(
                    [u8::try_from(index + 6).unwrap(); 32],
                    [u8::try_from(index + 20).unwrap(); 32],
                )
                .unwrap();
        }
        assert_eq!(
            state.note_root(),
            private_claims_proof_relation::claim_note_merkle_root(
                &state.note_commitments
            )
        );
    }

    #[test]
    fn claim_and_spent_nullifiers_reject_replays() {
        let mut state = pool();
        state.register_note([6; 32], [7; 32]).unwrap();
        assert_eq!(
            state.register_note([8; 32], [7; 32]),
            Err(ProgramError::Custom(1))
        );

        state.mark_redemption_spent([9; 32]).unwrap();
        assert_eq!(
            state.mark_redemption_spent([9; 32]),
            Err(ProgramError::Custom(1))
        );
    }

    #[test]
    fn claim_registry_is_bounded_to_the_fixed_merkle_tree() {
        let mut state = pool();
        for index in 0..MAX_CLAIMS {
            state
                .register_note(
                    [u8::try_from(index + 1).unwrap(); 32],
                    [u8::try_from(index + 20).unwrap(); 32],
                )
                .unwrap();
        }
        assert_eq!(
            state.register_note([99; 32], [100; 32]),
            Err(ProgramError::Custom(1))
        );
    }
}