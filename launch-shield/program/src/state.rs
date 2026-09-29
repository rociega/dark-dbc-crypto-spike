use solana_program::{program_error::ProgramError, pubkey::Pubkey};

pub const CONFIG_LEN: usize = 8 + 32 + 66;
pub const AUCTION_LEN: usize = 363;
pub const BID_LEN: usize = 122;

const CONFIG_MAGIC: &[u8; 8] = b"SHCFG001";
const AUCTION_MAGIC: &[u8; 8] = b"SHWIN001";
const BID_MAGIC: &[u8; 8] = b"SHBID001";

pub const AUCTION_COMMITS: u8 = 0;
pub const AUCTION_REVEALS: u8 = 1;
pub const AUCTION_SETTLING: u8 = 2;
pub const AUCTION_SETTLED: u8 = 3;
pub const AUCTION_CANCELLED: u8 = 4;

pub const BID_COMMITTED: u8 = 0;
pub const BID_REVEALED: u8 = 1;
pub const BID_CLAIMED: u8 = 2;
pub const BID_FORFEITED: u8 = 3;
pub const BID_CANCELLED: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GlobalConfig {
    pub authority: Pubkey,
    pub sp1_vkey_hash: [u8; 66],
}

impl GlobalConfig {
    pub fn pack(&self, output: &mut [u8]) -> Result<(), ProgramError> {
        if output.len() != CONFIG_LEN {
            return Err(ProgramError::AccountDataTooSmall);
        }
        output.fill(0);
        let mut writer = Writer::new(output);
        writer.bytes(CONFIG_MAGIC)?;
        writer.pubkey(&self.authority)?;
        writer.bytes(&self.sp1_vkey_hash)?;
        Ok(())
    }

    pub fn unpack(input: &[u8]) -> Result<Self, ProgramError> {
        if input.len() != CONFIG_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let mut reader = Reader::new(input);
        reader.expect(CONFIG_MAGIC)?;
        Ok(Self {
            authority: reader.pubkey()?,
            sp1_vkey_hash: reader.array()?,
        })
    }

    pub fn vkey_hash_str(&self) -> Result<&str, ProgramError> {
        let value = core::str::from_utf8(&self.sp1_vkey_hash)
            .map_err(|_| ProgramError::InvalidAccountData)?;
        if value.len() != 66
            || !value.starts_with("0x")
            || !value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Auction {
    pub creator: Pubkey,
    pub auction_id: [u8; 32],
    pub quote_mint: Pubkey,
    pub quote_vault: Pubkey,
    pub dbc_config: Pubkey,
    pub start_slot: u64,
    pub commit_end_slot: u64,
    pub reveal_end_slot: u64,
    pub settlement_deadline_slot: u64,
    pub max_bid_amount: u64,
    pub bond_lamports: u64,
    pub min_output_numerator: u64,
    pub min_output_denominator: u64,
    pub bid_count: u8,
    pub revealed_count: u8,
    pub total_revealed_amount: u64,
    pub status: u8,
    pub settlement_q: u64,
    pub settlement_y: u64,
    pub dbc_pool: Pubkey,
    pub base_mint: Pubkey,
    pub base_output_vault: Pubkey,
    pub output_balance_before: u64,
}

impl Auction {
    pub fn pack(&self, output: &mut [u8]) -> Result<(), ProgramError> {
        if output.len() != AUCTION_LEN {
            return Err(ProgramError::AccountDataTooSmall);
        }
        output.fill(0);
        let mut writer = Writer::new(output);
        writer.bytes(AUCTION_MAGIC)?;
        writer.pubkey(&self.creator)?;
        writer.bytes(&self.auction_id)?;
        writer.pubkey(&self.quote_mint)?;
        writer.pubkey(&self.quote_vault)?;
        writer.pubkey(&self.dbc_config)?;
        writer.u64(self.start_slot)?;
        writer.u64(self.commit_end_slot)?;
        writer.u64(self.reveal_end_slot)?;
        writer.u64(self.settlement_deadline_slot)?;
        writer.u64(self.max_bid_amount)?;
        writer.u64(self.bond_lamports)?;
        writer.u64(self.min_output_numerator)?;
        writer.u64(self.min_output_denominator)?;
        writer.u8(self.bid_count)?;
        writer.u8(self.revealed_count)?;
        writer.u64(self.total_revealed_amount)?;
        writer.u8(self.status)?;
        writer.u64(self.settlement_q)?;
        writer.u64(self.settlement_y)?;
        writer.pubkey(&self.dbc_pool)?;
        writer.pubkey(&self.base_mint)?;
        writer.pubkey(&self.base_output_vault)?;
        writer.u64(self.output_balance_before)?;
        writer.finish(AUCTION_LEN)
    }

    pub fn unpack(input: &[u8]) -> Result<Self, ProgramError> {
        if input.len() != AUCTION_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let mut reader = Reader::new(input);
        reader.expect(AUCTION_MAGIC)?;
        let value = Self {
            creator: reader.pubkey()?,
            auction_id: reader.array()?,
            quote_mint: reader.pubkey()?,
            quote_vault: reader.pubkey()?,
            dbc_config: reader.pubkey()?,
            start_slot: reader.u64()?,
            commit_end_slot: reader.u64()?,
            reveal_end_slot: reader.u64()?,
            settlement_deadline_slot: reader.u64()?,
            max_bid_amount: reader.u64()?,
            bond_lamports: reader.u64()?,
            min_output_numerator: reader.u64()?,
            min_output_denominator: reader.u64()?,
            bid_count: reader.u8()?,
            revealed_count: reader.u8()?,
            total_revealed_amount: reader.u64()?,
            status: reader.u8()?,
            settlement_q: reader.u64()?,
            settlement_y: reader.u64()?,
            dbc_pool: reader.pubkey()?,
            base_mint: reader.pubkey()?,
            base_output_vault: reader.pubkey()?,
            output_balance_before: reader.u64()?,
        };
        if value.status > AUCTION_CANCELLED
            || value.bid_count > 8
            || value.revealed_count > value.bid_count
        {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bid {
    pub auction: Pubkey,
    pub bidder: Pubkey,
    pub commitment: [u8; 32],
    pub slot: u8,
    pub max_deposit: u64,
    pub amount: u64,
    pub status: u8,
}

impl Bid {
    pub fn pack(&self, output: &mut [u8]) -> Result<(), ProgramError> {
        if output.len() != BID_LEN {
            return Err(ProgramError::AccountDataTooSmall);
        }
        output.fill(0);
        let mut writer = Writer::new(output);
        writer.bytes(BID_MAGIC)?;
        writer.pubkey(&self.auction)?;
        writer.pubkey(&self.bidder)?;
        writer.bytes(&self.commitment)?;
        writer.u8(self.slot)?;
        writer.u64(self.max_deposit)?;
        writer.u64(self.amount)?;
        writer.u8(self.status)?;
        writer.finish(BID_LEN)
    }

    pub fn unpack(input: &[u8]) -> Result<Self, ProgramError> {
        if input.len() != BID_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let mut reader = Reader::new(input);
        reader.expect(BID_MAGIC)?;
        let value = Self {
            auction: reader.pubkey()?,
            bidder: reader.pubkey()?,
            commitment: reader.array()?,
            slot: reader.u8()?,
            max_deposit: reader.u64()?,
            amount: reader.u64()?,
            status: reader.u8()?,
        };
        if value.status > BID_CANCELLED {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(value)
    }
}

struct Writer<'a> {
    output: &'a mut [u8],
    offset: usize,
}

impl<'a> Writer<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self { output, offset: 0 }
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), ProgramError> {
        let end = self
            .offset
            .checked_add(value.len())
            .ok_or(ProgramError::AccountDataTooSmall)?;
        let destination = self
            .output
            .get_mut(self.offset..end)
            .ok_or(ProgramError::AccountDataTooSmall)?;
        destination.copy_from_slice(value);
        self.offset = end;
        Ok(())
    }

    fn pubkey(&mut self, value: &Pubkey) -> Result<(), ProgramError> {
        self.bytes(value.as_ref())
    }

    fn u8(&mut self, value: u8) -> Result<(), ProgramError> {
        self.bytes(&[value])
    }

    fn u64(&mut self, value: u64) -> Result<(), ProgramError> {
        self.bytes(&value.to_le_bytes())
    }

    fn finish(self, expected: usize) -> Result<(), ProgramError> {
        if self.offset == expected {
            Ok(())
        } else {
            Err(ProgramError::InvalidAccountData)
        }
    }
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn bytes<const N: usize>(&mut self) -> Result<[u8; N], ProgramError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(ProgramError::InvalidAccountData)?;
        let source = self
            .input
            .get(self.offset..end)
            .ok_or(ProgramError::InvalidAccountData)?;
        self.offset = end;
        let mut output = [0u8; N];
        output.copy_from_slice(source);
        Ok(output)
    }

    fn expect(&mut self, expected: &[u8]) -> Result<(), ProgramError> {
        let value = self.bytes::<8>()?;
        if value.as_slice() == expected {
            Ok(())
        } else {
            Err(ProgramError::InvalidAccountData)
        }
    }

    fn pubkey(&mut self) -> Result<Pubkey, ProgramError> {
        Ok(Pubkey::new_from_array(self.bytes()?))
    }

    fn u8(&mut self) -> Result<u8, ProgramError> {
        Ok(self.bytes::<1>()?[0])
    }

    fn u64(&mut self) -> Result<u64, ProgramError> {
        Ok(u64::from_le_bytes(self.bytes()?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProgramError> {
        self.bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auction_state_round_trips_with_exact_size() {
        let value = Auction {
            creator: Pubkey::new_unique(),
            auction_id: [5; 32],
            quote_mint: Pubkey::new_unique(),
            quote_vault: Pubkey::new_unique(),
            dbc_config: Pubkey::new_unique(),
            start_slot: 7,
            commit_end_slot: 19,
            reveal_end_slot: 31,
            settlement_deadline_slot: 287,
            max_bid_amount: 100,
            bond_lamports: 2_000,
            min_output_numerator: 3,
            min_output_denominator: 4,
            bid_count: 8,
            revealed_count: 6,
            total_revealed_amount: 222,
            status: AUCTION_REVEALS,
            settlement_q: 0,
            settlement_y: 0,
            dbc_pool: Pubkey::default(),
            base_mint: Pubkey::default(),
            base_output_vault: Pubkey::default(),
            output_balance_before: 0,
        };
        let mut bytes = [0u8; AUCTION_LEN];
        value.pack(&mut bytes).unwrap();
        assert_eq!(Auction::unpack(&bytes).unwrap(), value);
    }

    #[test]
    fn bid_state_round_trips_with_exact_size() {
        let value = Bid {
            auction: Pubkey::new_unique(),
            bidder: Pubkey::new_unique(),
            commitment: [9; 32],
            slot: 7,
            max_deposit: 100,
            amount: 25,
            status: BID_REVEALED,
        };
        let mut bytes = [0u8; BID_LEN];
        value.pack(&mut bytes).unwrap();
        assert_eq!(Bid::unpack(&bytes).unwrap(), value);
    }
}
