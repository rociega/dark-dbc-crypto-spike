//! Host-side reference arithmetic for the fixed-eight Dark DBC allocation.
//!
//! This crate deliberately does not implement production commitments, proofs,
//! encryption, Token-2022 CPIs, or DBC settlement. Its claim-structure module
//! checks only fixed-depth Merkle-path and nullifier-state invariants; it does
//! not hide membership or prove note ownership. The production program must
//! prove the required relations in the selected ZK system and verify them
//! on-chain.

pub mod claim_structure;

pub const MAX_BIDS: usize = 8;
/// Token-2022 confidential transfer currently splits an amount into 16-bit
/// low and 32-bit high components.
pub const MAX_TOKEN_CONFIDENTIAL_AMOUNT: u64 = (1u64 << 48) - 1;
/// MVP bid cap keeps the fixed-eight aggregate below 2^35 for bounded
/// discrete-log recovery of the combined auditor ciphertext.
pub const MAX_MVP_BID_AMOUNT: u64 = (1u64 << 32) - 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AllocationError {
    EmptyBatch,
    TooManyBids,
    ZeroAmount,
    AmountOverLimit,
    ZeroMaxBidAmount,
    MaxBidLimitTooLarge,
    AggregateOverflow,
    ZeroAggregate,
    AllocationOverflow,
    ConservationFailure,
    InvalidAmountParts,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementAllocation {
    pub quote_total: u64,
    pub output_total: u64,
    pub per_bid_output: Vec<u64>,
    pub rounding_dust: u64,
}

/// Splits one valid Token-2022 confidential-transfer amount into its audited
/// 16-bit low and 32-bit high components.
pub fn split_confidential_amount(amount: u64) -> Result<(u16, u32), AllocationError> {
    if amount > MAX_TOKEN_CONFIDENTIAL_AMOUNT {
        return Err(AllocationError::AmountOverLimit);
    }
    let low = (amount & u64::from(u16::MAX)) as u16;
    let high = (amount >> 16) as u32;
    Ok((low, high))
}

/// Host-side arithmetic check for recombining low/high sums. Production
/// settlement combines each ciphertext pair before aggregation and publishes
/// only Q; the component sums are not intended to be public state.
pub fn reconstruct_aggregate_from_parts(
    low_sum: u64,
    high_sum: u64,
) -> Result<u64, AllocationError> {
    let max_low_sum = MAX_BIDS as u64 * u64::from(u16::MAX);
    let max_high_per_bid = MAX_MVP_BID_AMOUNT >> 16;
    let max_high_sum = MAX_BIDS as u64 * max_high_per_bid;
    if low_sum > max_low_sum || high_sum > max_high_sum {
        return Err(AllocationError::InvalidAmountParts);
    }
    let aggregate = u128::from(low_sum) + (u128::from(high_sum) << 16);
    u64::try_from(aggregate).map_err(|_| AllocationError::InvalidAmountParts)
}

/// Computes fixed-eight pro-rata output amounts with integer floor rounding.
///
/// This is a reference implementation of
/// `v_i = floor(a_i * Y / Q)`, where `Q = sum(a_i)`.
/// Amounts and output are base units. The caller must separately prove, in
/// zero knowledge, that the hidden amounts correspond to accepted bids.
pub fn allocate(
    amounts: &[u64],
    output_total: u64,
    max_bid_amount: u64,
) -> Result<SettlementAllocation, AllocationError> {
    if amounts.is_empty() {
        return Err(AllocationError::EmptyBatch);
    }
    if amounts.len() > MAX_BIDS {
        return Err(AllocationError::TooManyBids);
    }
    if max_bid_amount == 0 {
        return Err(AllocationError::ZeroMaxBidAmount);
    }
    if max_bid_amount > MAX_MVP_BID_AMOUNT
        || u128::from(max_bid_amount) * MAX_BIDS as u128 > u128::from(u64::MAX)
    {
        return Err(AllocationError::MaxBidLimitTooLarge);
    }

    let mut quote_total = 0u64;
    for &amount in amounts {
        if amount == 0 {
            return Err(AllocationError::ZeroAmount);
        }
        if amount > max_bid_amount {
            return Err(AllocationError::AmountOverLimit);
        }
        quote_total = quote_total
            .checked_add(amount)
            .ok_or(AllocationError::AggregateOverflow)?;
    }
    if quote_total == 0 {
        return Err(AllocationError::ZeroAggregate);
    }

    let q = u128::from(quote_total);
    let y = u128::from(output_total);
    let mut per_bid_output = Vec::with_capacity(amounts.len());
    let mut allocated_total = 0u128;
    for &amount in amounts {
        let product = u128::from(amount) * y;
        let value = product / q;
        let value_u64 = u64::try_from(value).map_err(|_| AllocationError::AllocationOverflow)?;
        allocated_total = allocated_total
            .checked_add(value)
            .ok_or(AllocationError::AllocationOverflow)?;
        per_bid_output.push(value_u64);
    }

    if allocated_total > y {
        return Err(AllocationError::ConservationFailure);
    }

    let allocated_total =
        u64::try_from(allocated_total).map_err(|_| AllocationError::AllocationOverflow)?;
    let rounding_dust = output_total
        .checked_sub(allocated_total)
        .ok_or(AllocationError::ConservationFailure)?;

    Ok(SettlementAllocation {
        quote_total,
        output_total,
        per_bid_output,
        rounding_dust,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floors_pro_rata_allocations_and_accounts_for_dust() {
        let result = allocate(&[1, 2, 3], 10, 100).unwrap();
        assert_eq!(result.quote_total, 6);
        assert_eq!(result.per_bid_output, vec![1, 3, 5]);
        assert_eq!(result.rounding_dust, 1);
    }

    #[test]
    fn eight_bid_batch_conserves_output() {
        let result = allocate(&[1; MAX_BIDS], 101, 1).unwrap();
        assert_eq!(result.quote_total, 8);
        assert_eq!(result.per_bid_output, vec![12; MAX_BIDS]);
        assert_eq!(result.rounding_dust, 5);
        assert_eq!(
            result
                .per_bid_output
                .iter()
                .map(|v| u128::from(*v))
                .sum::<u128>()
                + u128::from(result.rounding_dust),
            u128::from(result.output_total)
        );
    }

    #[test]
    fn rejects_empty_and_over_capacity_batches() {
        assert_eq!(allocate(&[], 10, 10), Err(AllocationError::EmptyBatch));
        assert_eq!(
            allocate(&[1; MAX_BIDS + 1], 10, 1),
            Err(AllocationError::TooManyBids)
        );
    }

    #[test]
    fn rejects_zero_or_over_limit_amounts() {
        assert_eq!(allocate(&[0], 10, 10), Err(AllocationError::ZeroAmount));
        assert_eq!(
            allocate(&[11], 10, 10),
            Err(AllocationError::AmountOverLimit)
        );
        assert_eq!(
            allocate(&[1], 10, 0),
            Err(AllocationError::ZeroMaxBidAmount)
        );
    }

    #[test]
    fn rejects_a_bid_cap_that_can_overflow_eight_slots() {
        assert_eq!(
            allocate(&[1], 10, u64::MAX),
            Err(AllocationError::MaxBidLimitTooLarge)
        );
        assert_eq!(
            allocate(
                &[MAX_TOKEN_CONFIDENTIAL_AMOUNT + 1],
                10,
                MAX_TOKEN_CONFIDENTIAL_AMOUNT + 1
            ),
            Err(AllocationError::MaxBidLimitTooLarge)
        );
    }

    #[test]
    fn splits_token_confidential_amounts_and_checks_the_mvp_aggregate() {
        assert_eq!(split_confidential_amount(0), Ok((0, 0)));
        assert_eq!(
            split_confidential_amount(MAX_TOKEN_CONFIDENTIAL_AMOUNT),
            Ok((u16::MAX, u32::MAX))
        );
        assert_eq!(
            split_confidential_amount(MAX_TOKEN_CONFIDENTIAL_AMOUNT + 1),
            Err(AllocationError::AmountOverLimit)
        );

        let low_sum = MAX_BIDS as u64 * u64::from(u16::MAX);
        let high_sum = MAX_BIDS as u64 * (MAX_MVP_BID_AMOUNT >> 16);
        assert_eq!(
            reconstruct_aggregate_from_parts(low_sum, high_sum),
            Ok(MAX_BIDS as u64 * MAX_MVP_BID_AMOUNT)
        );
    }

    #[test]
    fn rejects_decrypted_component_sums_outside_eight_bid_bounds() {
        let max_low_sum = MAX_BIDS as u64 * u64::from(u16::MAX);
        let max_high_sum = MAX_BIDS as u64 * (MAX_MVP_BID_AMOUNT >> 16);
        assert_eq!(
            reconstruct_aggregate_from_parts(max_low_sum + 1, 0),
            Err(AllocationError::InvalidAmountParts)
        );
        assert_eq!(
            reconstruct_aggregate_from_parts(0, max_high_sum + 1),
            Err(AllocationError::InvalidAmountParts)
        );
    }

    #[test]
    fn maximum_mvp_bid_times_u64_output_fits_u128() {
        let max_bid = MAX_MVP_BID_AMOUNT;
        let result = allocate(&[max_bid], u64::MAX, max_bid).unwrap();
        assert_eq!(result.quote_total, max_bid);
        assert_eq!(result.per_bid_output, vec![u64::MAX]);
        assert_eq!(result.rounding_dust, 0);
    }

    #[test]
    fn eight_maximum_bids_stay_inside_u64_aggregate_bound() {
        let max_bid = MAX_MVP_BID_AMOUNT;
        let result = allocate(&[max_bid; MAX_BIDS], u64::MAX, max_bid).unwrap();
        assert_eq!(
            u128::from(result.quote_total),
            u128::from(max_bid) * MAX_BIDS as u128
        );
    }

    #[test]
    fn every_output_matches_the_floor_inequality() {
        let amounts = [7, 13, 29, 31, 41, 43, 59, 61];
        let output = 997;
        let result = allocate(&amounts, output, 100).unwrap();
        let q = u128::from(result.quote_total);
        let y = u128::from(output);

        for (&amount, &value) in amounts.iter().zip(&result.per_bid_output) {
            let lhs = u128::from(value) * q;
            let product = u128::from(amount) * y;
            let rhs = u128::from(value + 1) * q;
            assert!(lhs <= product);
            assert!(product < rhs);
        }

        let allocated: u128 = result.per_bid_output.iter().map(|v| u128::from(*v)).sum();
        assert_eq!(allocated + u128::from(result.rounding_dust), y);
    }
}
