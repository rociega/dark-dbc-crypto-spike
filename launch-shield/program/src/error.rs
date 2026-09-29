use solana_program::program_error::ProgramError;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShieldError {
    InvalidInstruction = 1,
    InvalidAccount = 2,
    InvalidPda = 3,
    Unauthorized = 4,
    InvalidState = 5,
    WrongWindow = 6,
    BidLimitReached = 7,
    InvalidAmount = 8,
    InvalidCommitment = 9,
    InvalidProof = 10,
    InvalidTokenAccount = 11,
    ArithmeticOverflow = 12,
    InvalidDbcInstruction = 13,
    InvalidPool = 14,
    NoRevealedBids = 15,
    SlippageGuardFailed = 16,
    AlreadyClaimed = 17,
    InvalidVkeyHash = 18,
}

impl From<ShieldError> for ProgramError {
    fn from(value: ShieldError) -> Self {
        ProgramError::Custom(value as u32)
    }
}

pub type ShieldResult<T = ()> = Result<T, ProgramError>;
