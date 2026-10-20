use {
    crate::{
        error::TokenError,
        extension::{
            get_extension_bytes_if_present, BaseState, BaseStateWithExtensions, Extension,
            ExtensionType,
        },
    },
    alloc::vec::Vec,
    bytemuck::{Pod, Zeroable},
    core::mem::size_of,
    solana_address::Address,
    solana_nullable::MaybeNull,
    solana_program_error::{ProgramError, ProgramResult},
    solana_zero_copy::unaligned::{Bool, U64},
    solana_zk_sdk_pod::encryption::elgamal::{PodElGamalCiphertext, PodElGamalPubkey},
    spl_token_confidential_transfer_proof_extraction::encryption::PodFeeCiphertext,
    spl_type_length_value::variable_len_pack::VariableLenPack,
};

/// Confidential transfer fee extension instructions
pub mod instruction;

/// ElGamal ciphertext containing a transfer fee
pub type EncryptedFee = PodFeeCiphertext;
/// ElGamal ciphertext containing a withheld fee in an account
pub type EncryptedWithheldAmount = PodElGamalCiphertext;

/// Confidential transfer fee extension data for mints
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Pod, Zeroable)]
pub struct ConfidentialTransferFeeConfig {
    /// Optional authority to set the withdraw withheld authority ElGamal key
    pub authority: MaybeNull<Address>,

    /// Withheld fees from accounts must be encrypted with this ElGamal key.
    ///
    /// Note that whoever holds the ElGamal private key for this ElGamal public
    /// key has the ability to decode any withheld fee amount that are
    /// associated with accounts. When combined with the fee parameters, the
    /// withheld fee amounts can reveal information about transfer amounts.
    pub withdraw_withheld_authority_elgamal_pubkey: PodElGamalPubkey,

    /// If `false`, the harvest of withheld tokens to mint is rejected.
    pub harvest_to_mint_enabled: Bool,

    /// Withheld confidential transfer fee tokens that have been moved to the
    /// mint for withdrawal.
    pub withheld_amount: EncryptedWithheldAmount,
}

impl Extension for ConfidentialTransferFeeConfig {
    const TYPE: ExtensionType = ExtensionType::ConfidentialTransferFeeConfig;
}

/// Confidential transfer fee
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Pod, Zeroable)]
pub struct ConfidentialTransferFeeAmount {
    /// Amount withheld during confidential transfers, to be harvest to the mint
    pub withheld_amount: EncryptedWithheldAmount,
}

impl Extension for ConfidentialTransferFeeAmount {
    const TYPE: ExtensionType = ExtensionType::ConfidentialTransferFeeAmount;
}

impl ConfidentialTransferFeeAmount {
    /// Check if a confidential transfer fee account is in a closable state.
    pub fn closable(&self) -> ProgramResult {
        if self.withheld_amount == EncryptedWithheldAmount::zeroed() {
            Ok(())
        } else {
            Err(TokenError::ConfidentialTransferFeeAccountHasWithheldFee.into())
        }
    }
}

/// A retired withdraw withheld authority ElGamal key and the fees harvested to
/// the mint while it was current
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Pod, Zeroable)]
pub struct ConfidentialTransferFeeKeyRecord {
    /// Never changes after the record is appended
    pub withdraw_withheld_authority_elgamal_pubkey: PodElGamalPubkey,
    /// Harvested fees from accounts tagged with this record's key index
    pub withheld_amount: EncryptedWithheldAmount,
}

/// Maximum number of records in a `ConfidentialTransferFeeKeyHistory`, limited
/// by the `u16` TLV length
pub const MAX_KEY_HISTORY_LEN: usize =
    u16::MAX as usize / size_of::<ConfidentialTransferFeeKeyRecord>();

/// Records for every retired withdraw withheld authority ElGamal key. Record
/// `i` holds key index `i`, and the current key index is the number of records.
///
/// The program reads the records in place with
/// `ConfidentialTransferFeeKeyHistory::records_from_bytes`, since the full
/// history can be larger than the on-chain heap.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ConfidentialTransferFeeKeyHistory {
    /// Records ordered by key index
    pub records: Vec<ConfidentialTransferFeeKeyRecord>,
}

impl Extension for ConfidentialTransferFeeKeyHistory {
    const TYPE: ExtensionType = ExtensionType::ConfidentialTransferFeeKeyHistory;
}

impl ConfidentialTransferFeeKeyHistory {
    /// Interprets the extension bytes as records
    pub fn records_from_bytes(
        bytes: &[u8],
    ) -> Result<&[ConfidentialTransferFeeKeyRecord], ProgramError> {
        bytemuck::try_cast_slice(bytes).map_err(|_| ProgramError::InvalidAccountData)
    }

    /// Interprets the extension bytes as mutable records
    pub fn records_from_bytes_mut(
        bytes: &mut [u8],
    ) -> Result<&mut [ConfidentialTransferFeeKeyRecord], ProgramError> {
        bytemuck::try_cast_slice_mut(bytes).map_err(|_| ProgramError::InvalidAccountData)
    }
}

impl VariableLenPack for ConfidentialTransferFeeKeyHistory {
    fn pack_into_slice(&self, dst: &mut [u8]) -> Result<(), ProgramError> {
        let bytes: &[u8] = bytemuck::cast_slice(&self.records);
        if dst.len() != bytes.len() {
            return Err(ProgramError::InvalidAccountData);
        }
        dst.copy_from_slice(bytes);
        Ok(())
    }

    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        Ok(Self {
            records: Self::records_from_bytes(src)?.to_vec(),
        })
    }

    fn get_packed_len(&self) -> Result<usize, ProgramError> {
        self.records
            .len()
            .checked_mul(size_of::<ConfidentialTransferFeeKeyRecord>())
            .ok_or(ProgramError::InvalidArgument)
    }
}

/// Returns the current key index of a mint, which is the number of retired
/// withdraw withheld authority ElGamal keys. Fails if the mint's TLV data is
/// malformed.
pub fn current_key_index<S: BaseState, M: BaseStateWithExtensions<S>>(
    mint: &M,
) -> Result<u64, ProgramError> {
    match get_extension_bytes_if_present::<S, ConfidentialTransferFeeKeyHistory>(
        mint.get_tlv_data(),
    )? {
        Some(bytes) => {
            Ok(ConfidentialTransferFeeKeyHistory::records_from_bytes(bytes)?.len() as u64)
        }
        None => Ok(0),
    }
}

/// The key index of the withheld amount in a token account. An account without
/// this extension is at key index 0.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Pod, Zeroable)]
pub struct ConfidentialTransferFeeKeyIndex {
    /// Key index that the account's withheld amount is encrypted under
    pub key_index: U64,
}

impl Extension for ConfidentialTransferFeeKeyIndex {
    const TYPE: ExtensionType = ExtensionType::ConfidentialTransferFeeKeyIndex;
}

/// Returns the key index of a token account's withheld amount, or `None` if the
/// account doesn't have the `ConfidentialTransferFeeKeyIndex` extension. Fails
/// if the account's TLV data is malformed.
pub fn account_key_index<S: BaseState, A: BaseStateWithExtensions<S>>(
    account: &A,
) -> Result<Option<u64>, ProgramError> {
    get_extension_bytes_if_present::<S, ConfidentialTransferFeeKeyIndex>(account.get_tlv_data())?
        .map(|bytes| {
            bytemuck::try_from_bytes::<ConfidentialTransferFeeKeyIndex>(bytes)
                .map(|extension| extension.key_index.into())
                .map_err(|_| ProgramError::InvalidAccountData)
        })
        .transpose()
}
