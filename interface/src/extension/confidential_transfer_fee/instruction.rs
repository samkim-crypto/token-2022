#[cfg(feature = "serde")]
use {
    crate::serialization::{aeciphertext_fromstr, elgamalpubkey_fromstr},
    serde::{Deserialize, Serialize},
    serde_with::{As, DisplayFromStr},
};
use {
    crate::{
        check_program_account,
        error::TokenError,
        extension::confidential_transfer::{
            instruction::{CiphertextCiphertextEqualityProofData, PubkeyValidityProofData},
            DecryptableBalance,
        },
        instruction::{encode_instruction, TokenInstruction},
    },
    alloc::{vec, vec::Vec},
    bytemuck::{Pod, Zeroable},
    core::convert::TryFrom,
    num_enum::{IntoPrimitive, TryFromPrimitive},
    solana_address::Address,
    solana_instruction::{AccountMeta, Instruction},
    solana_nullable::MaybeNull,
    solana_program_error::ProgramError,
    solana_sdk_ids::{system_program, sysvar},
    solana_zero_copy::unaligned::U64,
    solana_zk_elgamal_proof_interface::instruction::ProofInstruction,
    solana_zk_sdk_pod::encryption::elgamal::PodElGamalPubkey,
    spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation,
};

/// Confidential Transfer extension instructions
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(Clone, Copy, Debug, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum ConfidentialTransferFeeInstruction {
    /// Initializes confidential transfer fees for a mint.
    ///
    /// The `ConfidentialTransferFeeInstruction::InitializeConfidentialTransferFeeConfig`
    /// instruction requires no signers and MUST be included within the same
    /// Transaction as `TokenInstruction::InitializeMint`. Otherwise another
    /// party can initialize the configuration.
    ///
    /// The instruction fails if the `TokenInstruction::InitializeMint`
    /// instruction has already executed for the mint.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The SPL Token mint.
    ///
    /// Data expected by this instruction:
    ///   `InitializeConfidentialTransferFeeConfigData`
    InitializeConfidentialTransferFeeConfig,

    /// Transfer all withheld confidential tokens in the mint to an account.
    /// Signed by the mint's withdraw withheld tokens authority.
    ///
    /// The withheld confidential tokens are aggregated directly into the
    /// destination available balance.
    ///
    /// In order for this instruction to be successfully processed, it must be
    /// accompanied by the `VerifyCiphertextCiphertextEquality` instruction
    /// of the `zk_elgamal_proof` program in the same transaction or the
    /// address of a context state account for the proof must be provided.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single owner/delegate
    ///   0. `[writable]` The token mint. Must include the `TransferFeeConfig`
    ///      extension.
    ///   1. `[writable]` The fee receiver account. Must include the
    ///      `TransferFeeAmount` and `ConfidentialTransferAccount` extensions.
    ///   2. `[]` Instructions sysvar if `VerifyCiphertextCiphertextEquality` is
    ///      included in the same transaction or context state account if
    ///      `VerifyCiphertextCiphertextEquality` is pre-verified into a context
    ///      state account.
    ///   3. `[signer]` The mint's `withdraw_withheld_authority`.
    ///
    ///   * Multisignature owner/delegate
    ///   0. `[writable]` The token mint. Must include the `TransferFeeConfig`
    ///      extension.
    ///   1. `[writable]` The fee receiver account. Must include the
    ///      `TransferFeeAmount` and `ConfidentialTransferAccount` extensions.
    ///   2. `[]` Instructions sysvar if `VerifyCiphertextCiphertextEquality` is
    ///      included in the same transaction or context state account if
    ///      `VerifyCiphertextCiphertextEquality` is pre-verified into a context
    ///      state account.
    ///   3. `[]` The mint's multisig `withdraw_withheld_authority`.
    ///   4. ..`4+M` `[signer]` M signer accounts.
    ///
    /// Data expected by this instruction:
    ///   `WithdrawWithheldTokensFromMintData`
    WithdrawWithheldTokensFromMint,

    /// Transfer all withheld tokens to an account. Signed by the mint's
    /// withdraw withheld tokens authority. This instruction is susceptible
    /// to front-running. Use `HarvestWithheldTokensToMint` and
    /// `WithdrawWithheldTokensFromMint` as an alternative.
    ///
    /// The withheld confidential tokens are aggregated directly into the
    /// destination available balance.
    ///
    /// Note on front-running: This instruction requires a zero-knowledge proof
    /// verification instruction that is checked with respect to the account
    /// state (the currently withheld fees). Suppose that a withdraw
    /// withheld authority generates the
    /// `WithdrawWithheldTokensFromAccounts` instruction along with a
    /// corresponding zero-knowledge proof for a specified set of accounts,
    /// and submits it on chain. If the withheld fees at any
    /// of the specified accounts change before the
    /// `WithdrawWithheldTokensFromAccounts` is executed on chain, the
    /// zero-knowledge proof will not verify with respect to the new state,
    /// forcing the transaction to fail.
    ///
    /// If front-running occurs, then users can look up the updated states of
    /// the accounts, generate a new zero-knowledge proof and try again.
    /// Alternatively, withdraw withheld authority can first move the
    /// withheld amount to the mint using `HarvestWithheldTokensToMint` and
    /// then move the withheld fees from mint to a specified destination
    /// account using `WithdrawWithheldTokensFromMint`.
    ///
    /// In order for this instruction to be successfully processed, it must be
    /// accompanied by the `VerifyWithdrawWithheldTokens` instruction of the
    /// `zk_elgamal_proof` program in the same transaction or the address of a
    /// context state account for the proof must be provided.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single owner/delegate
    ///   0. `[]` The token mint. Must include the `TransferFeeConfig`
    ///      extension.
    ///   1. `[writable]` The fee receiver account. Must include the
    ///      `TransferFeeAmount` and `ConfidentialTransferAccount` extensions.
    ///   2. `[]` Instructions sysvar if `VerifyCiphertextCiphertextEquality` is
    ///      included in the same transaction or context state account if
    ///      `VerifyCiphertextCiphertextEquality` is pre-verified into a context
    ///      state account.
    ///   3. `[signer]` The mint's `withdraw_withheld_authority`.
    ///   4. ..`4+N` `[writable]` The source accounts to withdraw from.
    ///
    ///   * Multisignature owner/delegate
    ///   0. `[]` The token mint. Must include the `TransferFeeConfig`
    ///      extension.
    ///   1. `[writable]` The fee receiver account. Must include the
    ///      `TransferFeeAmount` and `ConfidentialTransferAccount` extensions.
    ///   2. `[]` Instructions sysvar if `VerifyCiphertextCiphertextEquality` is
    ///      included in the same transaction or context state account if
    ///      `VerifyCiphertextCiphertextEquality` is pre-verified into a context
    ///      state account.
    ///   3. `[]` The mint's multisig `withdraw_withheld_authority`.
    ///   4. ..`4+M` `[signer]` M signer accounts.
    ///   5. `5+M+1..5+M+N` `[writable]` The source accounts to withdraw from.
    ///
    /// Data expected by this instruction:
    ///   `WithdrawWithheldTokensFromAccountsData`
    WithdrawWithheldTokensFromAccounts,

    /// Permissionless instruction to transfer all withheld confidential tokens
    /// to the mint.
    ///
    /// Succeeds for frozen accounts.
    ///
    /// Accounts provided should include both the `TransferFeeAmount` and
    /// `ConfidentialTransferAccount` extension. If not, the account is skipped.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The mint.
    ///   1. ..`1+N` `[writable]` The source accounts to harvest from.
    ///
    /// Data expected by this instruction:
    ///   None
    HarvestWithheldTokensToMint,

    /// Configure a confidential transfer fee mint to accept harvested
    /// confidential fees.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single owner/delegate
    ///   0. `[writable]` The token mint.
    ///   1. `[signer]` The confidential transfer fee authority.
    ///
    ///   *Multisignature owner/delegate
    ///   0. `[writable]` The token mint.
    ///   1. `[]` The confidential transfer fee multisig authority,
    ///   2. `[signer]` Required M signer accounts for the SPL Token Multisig
    ///      account.
    ///
    /// Data expected by this instruction:
    ///   None
    EnableHarvestToMint,

    /// Configure a confidential transfer fee mint to reject any harvested
    /// confidential fees.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Single owner/delegate
    ///   0. `[writable]` The token mint.
    ///   1. `[signer]` The confidential transfer fee authority.
    ///
    ///   *Multisignature owner/delegate
    ///   0. `[writable]` The token mint.
    ///   1. `[]` The confidential transfer fee multisig authority,
    ///   2. `[signer]` Required M signer accounts for the SPL Token Multisig
    ///      account.
    ///
    /// Data expected by this instruction:
    ///   None
    DisableHarvestToMint,

    /// Rotate the withdraw withheld authority ElGamal public key.
    ///
    /// The current key and the mint's withheld amount are appended to the
    /// `ConfidentialTransferFeeKeyHistory` as a new record, the mint's withheld
    /// amount is set to zero, and the new key becomes current. The current key
    /// index increases by one.
    ///
    /// The instruction requires both the confidential transfer fee authority
    /// and the transfer fee `withdraw_withheld_authority`. If the
    /// `withdraw_withheld_authority` is `None`, then the confidential transfer
    /// fee authority alone is enough, and account 3 is ignored.
    ///
    /// The instruction fails if the mint has a close authority, since the key
    /// history must outlive every token account that refers to it.
    ///
    /// The mint grows by one record (96 bytes), plus a 4-byte TLV header on the
    /// first rotation. The caller must transfer enough lamports to the mint
    /// beforehand to keep it rent-exempt.
    ///
    /// In order for this instruction to be successfully processed, it must be
    /// accompanied by the `VerifyPubkeyValidity` instruction of the
    /// `zk_elgamal_proof` program in the same transaction or the address of a
    /// context state account for the proof must be provided.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The token mint.
    ///   1. `[]` Instructions sysvar if `VerifyPubkeyValidity` is included in
    ///      the same transaction or context state account if
    ///      `VerifyPubkeyValidity` is pre-verified into a context state
    ///      account.
    ///   2. `[signer]` The confidential transfer fee authority, or `[]` if it
    ///      is a multisig.
    ///   3. `[signer]` The mint's `withdraw_withheld_authority`, or `[]` if it
    ///      is a multisig.
    ///   4. ..`4+M` `[signer]` M signer accounts for either multisig. A signer
    ///      shared by both multisigs is included once.
    ///
    /// Data expected by this instruction:
    ///   `RotateWithdrawWithheldAuthorityElGamalPubkeyData`
    RotateWithdrawWithheldAuthorityElGamalPubkey,

    /// Same as `WithdrawWithheldTokensFromMint`, except that the withheld
    /// amount is withdrawn from the given key index. If the key index is the
    /// current key index, the mint's withheld amount is withdrawn. Otherwise,
    /// the withheld amount of the record for that key index in the
    /// `ConfidentialTransferFeeKeyHistory` is withdrawn.
    ///
    /// Accounts expected by this instruction:
    ///   Same as `WithdrawWithheldTokensFromMint`
    ///
    /// Data expected by this instruction:
    ///   `WithdrawWithheldTokensFromMintForKeyIndexData`
    WithdrawWithheldTokensFromMintForKeyIndex,

    /// Same as `WithdrawWithheldTokensFromAccounts`, except that the withheld
    /// amounts are withdrawn only from source accounts at the given key index.
    /// Source accounts at any other key index are skipped.
    ///
    /// Accounts expected by this instruction:
    ///   Same as `WithdrawWithheldTokensFromAccounts`
    ///
    /// Data expected by this instruction:
    ///   `WithdrawWithheldTokensFromAccountsForKeyIndexData`
    WithdrawWithheldTokensFromAccountsForKeyIndex,

    /// Permissionless instruction to add the `ConfidentialTransferFeeKeyIndex`
    /// extension to a token account of a mint that has rotated its withdraw
    /// withheld authority ElGamal key at least once.
    ///
    /// If the account's withheld amount is zero, it is tagged with the current
    /// key index. Otherwise, it is tagged with key index 0, since its withheld
    /// amount was encrypted under the key that the mint was initialized with.
    /// If the account already has the extension, it is left unchanged.
    ///
    /// If the token account is not large enough to include the new extension,
    /// then optionally reallocate the account to increase the data size. To
    /// reallocate, a payer account to fund the reallocation and the system
    /// account should be included in the instruction.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[writable]` The SPL Token account.
    ///   1. `[]` The corresponding SPL Token mint.
    ///   2. `[signer, writable]` (Optional) The payer account to fund
    ///      reallocation
    ///   3. `[]` (Optional) System program for reallocation funding
    ///
    /// Data expected by this instruction:
    ///   None
    InitializeAccountKeyIndex,
}

/// Data expected by `InitializeConfidentialTransferFeeConfig`
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
#[repr(C)]
pub struct InitializeConfidentialTransferFeeConfigData {
    /// confidential transfer fee authority
    #[cfg_attr(feature = "serde", serde(with = "As::<Option<DisplayFromStr>>"))]
    pub authority: MaybeNull<Address>,

    /// ElGamal public key used to encrypt withheld fees.
    #[cfg_attr(feature = "serde", serde(with = "elgamalpubkey_fromstr"))]
    pub withdraw_withheld_authority_elgamal_pubkey: PodElGamalPubkey,
}

/// Data expected by
/// `ConfidentialTransferFeeInstruction::WithdrawWithheldTokensFromMint`
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
#[repr(C)]
pub struct WithdrawWithheldTokensFromMintData {
    /// Relative location of the `ProofInstruction::VerifyWithdrawWithheld`
    /// instruction to the `WithdrawWithheldTokensFromMint` instruction in
    /// the transaction. If the offset is `0`, then use a context state
    /// account for the proof.
    pub proof_instruction_offset: i8,
    /// The new decryptable balance in the destination token account.
    #[cfg_attr(feature = "serde", serde(with = "aeciphertext_fromstr"))]
    pub new_decryptable_available_balance: DecryptableBalance,
}

/// Data expected by
/// `ConfidentialTransferFeeInstruction::WithdrawWithheldTokensFromAccounts`
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
#[repr(C)]
pub struct WithdrawWithheldTokensFromAccountsData {
    /// Number of token accounts harvested
    pub num_token_accounts: u8,
    /// Relative location of the `ProofInstruction::VerifyWithdrawWithheld`
    /// instruction to the `VerifyWithdrawWithheldTokensFromAccounts`
    /// instruction in the transaction. If the offset is `0`, then use a
    /// context state account for the proof.
    pub proof_instruction_offset: i8,
    /// The new decryptable balance in the destination token account.
    #[cfg_attr(feature = "serde", serde(with = "aeciphertext_fromstr"))]
    pub new_decryptable_available_balance: DecryptableBalance,
}

/// Data expected by
/// `ConfidentialTransferFeeInstruction::RotateWithdrawWithheldAuthorityElGamalPubkey`
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
#[repr(C)]
pub struct RotateWithdrawWithheldAuthorityElGamalPubkeyData {
    /// The current key index of the mint before the rotation
    pub expected_key_index: U64,
    /// The new ElGamal public key used to encrypt withheld fees
    #[cfg_attr(feature = "serde", serde(with = "elgamalpubkey_fromstr"))]
    pub new_withdraw_withheld_authority_elgamal_pubkey: PodElGamalPubkey,
    /// Relative location of the `ProofInstruction::VerifyPubkeyValidity`
    /// instruction to the `RotateWithdrawWithheldAuthorityElGamalPubkey`
    /// instruction in the transaction. If the offset is `0`, then use a
    /// context state account for the proof.
    pub proof_instruction_offset: i8,
}

/// Data expected by
/// `ConfidentialTransferFeeInstruction::WithdrawWithheldTokensFromMintForKeyIndex`
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
#[repr(C)]
pub struct WithdrawWithheldTokensFromMintForKeyIndexData {
    /// The key index to withdraw from
    pub key_index: U64,
    /// Relative location of the
    /// `ProofInstruction::VerifyCiphertextCiphertextEquality` instruction to the
    /// `WithdrawWithheldTokensFromMintForKeyIndex` instruction in the
    /// transaction. If the offset is `0`, then use a context state account for
    /// the proof.
    pub proof_instruction_offset: i8,
    /// The new decryptable balance in the destination token account.
    #[cfg_attr(feature = "serde", serde(with = "aeciphertext_fromstr"))]
    pub new_decryptable_available_balance: DecryptableBalance,
}

/// Data expected by
/// `ConfidentialTransferFeeInstruction::WithdrawWithheldTokensFromAccountsForKeyIndex`
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
#[repr(C)]
pub struct WithdrawWithheldTokensFromAccountsForKeyIndexData {
    /// The key index to withdraw from
    pub key_index: U64,
    /// Number of token accounts harvested
    pub num_token_accounts: u8,
    /// Relative location of the
    /// `ProofInstruction::VerifyCiphertextCiphertextEquality` instruction to the
    /// `WithdrawWithheldTokensFromAccountsForKeyIndex` instruction in the
    /// transaction. If the offset is `0`, then use a context state account for
    /// the proof.
    pub proof_instruction_offset: i8,
    /// The new decryptable balance in the destination token account.
    #[cfg_attr(feature = "serde", serde(with = "aeciphertext_fromstr"))]
    pub new_decryptable_available_balance: DecryptableBalance,
}

/// Create a `InitializeConfidentialTransferFeeConfig` instruction
pub fn initialize_confidential_transfer_fee_config(
    token_program_id: &Address,
    mint: &Address,
    authority: Option<Address>,
    withdraw_withheld_authority_elgamal_pubkey: &PodElGamalPubkey,
) -> Result<Instruction, ProgramError> {
    check_program_account(token_program_id)?;
    let accounts = vec![AccountMeta::new(*mint, false)];

    Ok(encode_instruction(
        token_program_id,
        accounts,
        TokenInstruction::ConfidentialTransferFeeExtension,
        ConfidentialTransferFeeInstruction::InitializeConfidentialTransferFeeConfig,
        &InitializeConfidentialTransferFeeConfigData {
            authority: authority
                .try_into()
                .map_err(|_| ProgramError::InvalidArgument)?,
            withdraw_withheld_authority_elgamal_pubkey: *withdraw_withheld_authority_elgamal_pubkey,
        },
    ))
}

/// Create an inner `WithdrawWithheldTokensFromMint` instruction
///
/// This instruction is suitable for use with a cross-program `invoke`
pub fn inner_withdraw_withheld_tokens_from_mint(
    token_program_id: &Address,
    mint: &Address,
    destination: &Address,
    new_decryptable_available_balance: &DecryptableBalance,
    authority: &Address,
    multisig_signers: &[&Address],
    proof_data_location: ProofLocation<CiphertextCiphertextEqualityProofData>,
) -> Result<Instruction, ProgramError> {
    check_program_account(token_program_id)?;
    let mut accounts = vec![
        AccountMeta::new(*mint, false),
        AccountMeta::new(*destination, false),
    ];

    let proof_instruction_offset = match proof_data_location {
        ProofLocation::InstructionOffset(proof_instruction_offset, _) => {
            accounts.push(AccountMeta::new_readonly(sysvar::instructions::id(), false));
            proof_instruction_offset.into()
        }
        ProofLocation::ContextStateAccount(context_state_account) => {
            accounts.push(AccountMeta::new_readonly(*context_state_account, false));
            0
        }
    };

    accounts.push(AccountMeta::new_readonly(
        *authority,
        multisig_signers.is_empty(),
    ));

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    Ok(encode_instruction(
        token_program_id,
        accounts,
        TokenInstruction::ConfidentialTransferFeeExtension,
        ConfidentialTransferFeeInstruction::WithdrawWithheldTokensFromMint,
        &WithdrawWithheldTokensFromMintData {
            proof_instruction_offset,
            new_decryptable_available_balance: *new_decryptable_available_balance,
        },
    ))
}

/// Create an `WithdrawWithheldTokensFromMint` instruction
pub fn withdraw_withheld_tokens_from_mint(
    token_program_id: &Address,
    mint: &Address,
    destination: &Address,
    new_decryptable_available_balance: &DecryptableBalance,
    authority: &Address,
    multisig_signers: &[&Address],
    proof_data_location: ProofLocation<CiphertextCiphertextEqualityProofData>,
) -> Result<Vec<Instruction>, ProgramError> {
    let mut instructions = vec![inner_withdraw_withheld_tokens_from_mint(
        token_program_id,
        mint,
        destination,
        new_decryptable_available_balance,
        authority,
        multisig_signers,
        proof_data_location,
    )?];

    if let ProofLocation::InstructionOffset(proof_instruction_offset, proof_data) =
        proof_data_location
    {
        // This constructor appends the proof instruction right after the
        // `WithdrawWithheldTokensFromMint` instruction. This means that the proof
        // instruction offset must be always be 1. To use an arbitrary proof
        // instruction offset, use the
        // `inner_withdraw_withheld_tokens_from_mint` constructor.
        let proof_instruction_offset: i8 = proof_instruction_offset.into();
        if proof_instruction_offset != 1 {
            return Err(TokenError::InvalidProofInstructionOffset.into());
        }
        instructions.push(
            ProofInstruction::VerifyCiphertextCiphertextEquality
                .encode_verify_proof(None, proof_data),
        );
    };

    Ok(instructions)
}

/// Create an inner `WithdrawWithheldTokensFromMint` instruction
///
/// This instruction is suitable for use with a cross-program `invoke`
#[allow(clippy::too_many_arguments)]
pub fn inner_withdraw_withheld_tokens_from_accounts(
    token_program_id: &Address,
    mint: &Address,
    destination: &Address,
    new_decryptable_available_balance: &DecryptableBalance,
    authority: &Address,
    multisig_signers: &[&Address],
    sources: &[&Address],
    proof_data_location: ProofLocation<CiphertextCiphertextEqualityProofData>,
) -> Result<Instruction, ProgramError> {
    check_program_account(token_program_id)?;
    let num_token_accounts =
        u8::try_from(sources.len()).map_err(|_| ProgramError::InvalidInstructionData)?;
    let mut accounts = vec![
        AccountMeta::new(*mint, false),
        AccountMeta::new(*destination, false),
    ];

    let proof_instruction_offset = match proof_data_location {
        ProofLocation::InstructionOffset(proof_instruction_offset, _) => {
            accounts.push(AccountMeta::new_readonly(sysvar::instructions::id(), false));
            proof_instruction_offset.into()
        }
        ProofLocation::ContextStateAccount(context_state_account) => {
            accounts.push(AccountMeta::new_readonly(*context_state_account, false));
            0
        }
    };

    accounts.push(AccountMeta::new_readonly(
        *authority,
        multisig_signers.is_empty(),
    ));

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    for source in sources.iter() {
        accounts.push(AccountMeta::new(**source, false));
    }

    Ok(encode_instruction(
        token_program_id,
        accounts,
        TokenInstruction::ConfidentialTransferFeeExtension,
        ConfidentialTransferFeeInstruction::WithdrawWithheldTokensFromAccounts,
        &WithdrawWithheldTokensFromAccountsData {
            proof_instruction_offset,
            num_token_accounts,
            new_decryptable_available_balance: *new_decryptable_available_balance,
        },
    ))
}

/// Create a `WithdrawWithheldTokensFromAccounts` instruction
#[allow(clippy::too_many_arguments)]
pub fn withdraw_withheld_tokens_from_accounts(
    token_program_id: &Address,
    mint: &Address,
    destination: &Address,
    new_decryptable_available_balance: &DecryptableBalance,
    authority: &Address,
    multisig_signers: &[&Address],
    sources: &[&Address],
    proof_data_location: ProofLocation<CiphertextCiphertextEqualityProofData>,
) -> Result<Vec<Instruction>, ProgramError> {
    let mut instructions = vec![inner_withdraw_withheld_tokens_from_accounts(
        token_program_id,
        mint,
        destination,
        new_decryptable_available_balance,
        authority,
        multisig_signers,
        sources,
        proof_data_location,
    )?];

    if let ProofLocation::InstructionOffset(proof_instruction_offset, proof_data) =
        proof_data_location
    {
        // This constructor appends the proof instruction right after the
        // `WithdrawWithheldTokensFromAccounts` instruction. This means that the proof
        // instruction offset must always be 1. To use an arbitrary proof
        // instruction offset, use the
        // `inner_withdraw_withheld_tokens_from_accounts` constructor.
        let proof_instruction_offset: i8 = proof_instruction_offset.into();
        if proof_instruction_offset != 1 {
            return Err(TokenError::InvalidProofInstructionOffset.into());
        }
        instructions.push(
            ProofInstruction::VerifyCiphertextCiphertextEquality
                .encode_verify_proof(None, proof_data),
        );
    };

    Ok(instructions)
}

/// Creates a `HarvestWithheldTokensToMint` instruction
pub fn harvest_withheld_tokens_to_mint(
    token_program_id: &Address,
    mint: &Address,
    sources: &[&Address],
) -> Result<Instruction, ProgramError> {
    check_program_account(token_program_id)?;
    let mut accounts = vec![AccountMeta::new(*mint, false)];

    for source in sources.iter() {
        accounts.push(AccountMeta::new(**source, false));
    }

    Ok(encode_instruction(
        token_program_id,
        accounts,
        TokenInstruction::ConfidentialTransferFeeExtension,
        ConfidentialTransferFeeInstruction::HarvestWithheldTokensToMint,
        &(),
    ))
}

/// Create an `EnableHarvestToMint` instruction
pub fn enable_harvest_to_mint(
    token_program_id: &Address,
    mint: &Address,
    authority: &Address,
    multisig_signers: &[&Address],
) -> Result<Instruction, ProgramError> {
    check_program_account(token_program_id)?;
    let mut accounts = vec![
        AccountMeta::new(*mint, false),
        AccountMeta::new_readonly(*authority, multisig_signers.is_empty()),
    ];

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    Ok(encode_instruction(
        token_program_id,
        accounts,
        TokenInstruction::ConfidentialTransferFeeExtension,
        ConfidentialTransferFeeInstruction::EnableHarvestToMint,
        &(),
    ))
}

/// Create a `DisableHarvestToMint` instruction
pub fn disable_harvest_to_mint(
    token_program_id: &Address,
    mint: &Address,
    authority: &Address,
    multisig_signers: &[&Address],
) -> Result<Instruction, ProgramError> {
    check_program_account(token_program_id)?;
    let mut accounts = vec![
        AccountMeta::new(*mint, false),
        AccountMeta::new_readonly(*authority, multisig_signers.is_empty()),
    ];

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    Ok(encode_instruction(
        token_program_id,
        accounts,
        TokenInstruction::ConfidentialTransferFeeExtension,
        ConfidentialTransferFeeInstruction::DisableHarvestToMint,
        &(),
    ))
}

/// Create an inner `RotateWithdrawWithheldAuthorityElGamalPubkey` instruction
///
/// This instruction is suitable for use with a cross-program `invoke`.
///
/// If only one of the authorities is a multisig, include the other authority
/// in `multisig_signers`. If the mint's `withdraw_withheld_authority` is
/// `None`, pass the confidential transfer fee authority as
/// `withdraw_withheld_authority`.
#[allow(clippy::too_many_arguments)]
pub fn inner_rotate_withdraw_withheld_authority_elgamal_pubkey(
    token_program_id: &Address,
    mint: &Address,
    expected_key_index: u64,
    new_withdraw_withheld_authority_elgamal_pubkey: &PodElGamalPubkey,
    confidential_transfer_fee_authority: &Address,
    withdraw_withheld_authority: &Address,
    multisig_signers: &[&Address],
    proof_data_location: ProofLocation<PubkeyValidityProofData>,
) -> Result<Instruction, ProgramError> {
    check_program_account(token_program_id)?;
    let mut accounts = vec![AccountMeta::new(*mint, false)];

    let proof_instruction_offset = match proof_data_location {
        ProofLocation::InstructionOffset(proof_instruction_offset, _) => {
            accounts.push(AccountMeta::new_readonly(sysvar::instructions::id(), false));
            proof_instruction_offset.into()
        }
        ProofLocation::ContextStateAccount(context_state_account) => {
            accounts.push(AccountMeta::new_readonly(*context_state_account, false));
            0
        }
    };

    accounts.push(AccountMeta::new_readonly(
        *confidential_transfer_fee_authority,
        multisig_signers.is_empty(),
    ));
    accounts.push(AccountMeta::new_readonly(
        *withdraw_withheld_authority,
        multisig_signers.is_empty(),
    ));

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    Ok(encode_instruction(
        token_program_id,
        accounts,
        TokenInstruction::ConfidentialTransferFeeExtension,
        ConfidentialTransferFeeInstruction::RotateWithdrawWithheldAuthorityElGamalPubkey,
        &RotateWithdrawWithheldAuthorityElGamalPubkeyData {
            expected_key_index: expected_key_index.into(),
            new_withdraw_withheld_authority_elgamal_pubkey:
                *new_withdraw_withheld_authority_elgamal_pubkey,
            proof_instruction_offset,
        },
    ))
}

/// Create a `RotateWithdrawWithheldAuthorityElGamalPubkey` instruction
#[allow(clippy::too_many_arguments)]
pub fn rotate_withdraw_withheld_authority_elgamal_pubkey(
    token_program_id: &Address,
    mint: &Address,
    expected_key_index: u64,
    new_withdraw_withheld_authority_elgamal_pubkey: &PodElGamalPubkey,
    confidential_transfer_fee_authority: &Address,
    withdraw_withheld_authority: &Address,
    multisig_signers: &[&Address],
    proof_data_location: ProofLocation<PubkeyValidityProofData>,
) -> Result<Vec<Instruction>, ProgramError> {
    let mut instructions = vec![inner_rotate_withdraw_withheld_authority_elgamal_pubkey(
        token_program_id,
        mint,
        expected_key_index,
        new_withdraw_withheld_authority_elgamal_pubkey,
        confidential_transfer_fee_authority,
        withdraw_withheld_authority,
        multisig_signers,
        proof_data_location,
    )?];

    if let ProofLocation::InstructionOffset(proof_instruction_offset, proof_data) =
        proof_data_location
    {
        // This constructor appends the proof instruction right after the
        // `RotateWithdrawWithheldAuthorityElGamalPubkey` instruction. This means
        // that the proof instruction offset must always be 1. To use an
        // arbitrary proof instruction offset, use the
        // `inner_rotate_withdraw_withheld_authority_elgamal_pubkey` constructor.
        let proof_instruction_offset: i8 = proof_instruction_offset.into();
        if proof_instruction_offset != 1 {
            return Err(TokenError::InvalidProofInstructionOffset.into());
        }
        instructions
            .push(ProofInstruction::VerifyPubkeyValidity.encode_verify_proof(None, proof_data));
    };

    Ok(instructions)
}

/// Create an inner `WithdrawWithheldTokensFromMintForKeyIndex` instruction
///
/// This instruction is suitable for use with a cross-program `invoke`
#[allow(clippy::too_many_arguments)]
pub fn inner_withdraw_withheld_tokens_from_mint_for_key_index(
    token_program_id: &Address,
    mint: &Address,
    destination: &Address,
    key_index: u64,
    new_decryptable_available_balance: &DecryptableBalance,
    authority: &Address,
    multisig_signers: &[&Address],
    proof_data_location: ProofLocation<CiphertextCiphertextEqualityProofData>,
) -> Result<Instruction, ProgramError> {
    check_program_account(token_program_id)?;
    let mut accounts = vec![
        AccountMeta::new(*mint, false),
        AccountMeta::new(*destination, false),
    ];

    let proof_instruction_offset = match proof_data_location {
        ProofLocation::InstructionOffset(proof_instruction_offset, _) => {
            accounts.push(AccountMeta::new_readonly(sysvar::instructions::id(), false));
            proof_instruction_offset.into()
        }
        ProofLocation::ContextStateAccount(context_state_account) => {
            accounts.push(AccountMeta::new_readonly(*context_state_account, false));
            0
        }
    };

    accounts.push(AccountMeta::new_readonly(
        *authority,
        multisig_signers.is_empty(),
    ));

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    Ok(encode_instruction(
        token_program_id,
        accounts,
        TokenInstruction::ConfidentialTransferFeeExtension,
        ConfidentialTransferFeeInstruction::WithdrawWithheldTokensFromMintForKeyIndex,
        &WithdrawWithheldTokensFromMintForKeyIndexData {
            key_index: key_index.into(),
            proof_instruction_offset,
            new_decryptable_available_balance: *new_decryptable_available_balance,
        },
    ))
}

/// Create a `WithdrawWithheldTokensFromMintForKeyIndex` instruction
#[allow(clippy::too_many_arguments)]
pub fn withdraw_withheld_tokens_from_mint_for_key_index(
    token_program_id: &Address,
    mint: &Address,
    destination: &Address,
    key_index: u64,
    new_decryptable_available_balance: &DecryptableBalance,
    authority: &Address,
    multisig_signers: &[&Address],
    proof_data_location: ProofLocation<CiphertextCiphertextEqualityProofData>,
) -> Result<Vec<Instruction>, ProgramError> {
    let mut instructions = vec![inner_withdraw_withheld_tokens_from_mint_for_key_index(
        token_program_id,
        mint,
        destination,
        key_index,
        new_decryptable_available_balance,
        authority,
        multisig_signers,
        proof_data_location,
    )?];

    if let ProofLocation::InstructionOffset(proof_instruction_offset, proof_data) =
        proof_data_location
    {
        // This constructor appends the proof instruction right after the
        // `WithdrawWithheldTokensFromMintForKeyIndex` instruction. This means that
        // the proof instruction offset must always be 1. To use an arbitrary proof
        // instruction offset, use the
        // `inner_withdraw_withheld_tokens_from_mint_for_key_index` constructor.
        let proof_instruction_offset: i8 = proof_instruction_offset.into();
        if proof_instruction_offset != 1 {
            return Err(TokenError::InvalidProofInstructionOffset.into());
        }
        instructions.push(
            ProofInstruction::VerifyCiphertextCiphertextEquality
                .encode_verify_proof(None, proof_data),
        );
    };

    Ok(instructions)
}

/// Create an inner `WithdrawWithheldTokensFromAccountsForKeyIndex` instruction
///
/// This instruction is suitable for use with a cross-program `invoke`
#[allow(clippy::too_many_arguments)]
pub fn inner_withdraw_withheld_tokens_from_accounts_for_key_index(
    token_program_id: &Address,
    mint: &Address,
    destination: &Address,
    key_index: u64,
    new_decryptable_available_balance: &DecryptableBalance,
    authority: &Address,
    multisig_signers: &[&Address],
    sources: &[&Address],
    proof_data_location: ProofLocation<CiphertextCiphertextEqualityProofData>,
) -> Result<Instruction, ProgramError> {
    check_program_account(token_program_id)?;
    let num_token_accounts =
        u8::try_from(sources.len()).map_err(|_| ProgramError::InvalidInstructionData)?;
    let mut accounts = vec![
        AccountMeta::new(*mint, false),
        AccountMeta::new(*destination, false),
    ];

    let proof_instruction_offset = match proof_data_location {
        ProofLocation::InstructionOffset(proof_instruction_offset, _) => {
            accounts.push(AccountMeta::new_readonly(sysvar::instructions::id(), false));
            proof_instruction_offset.into()
        }
        ProofLocation::ContextStateAccount(context_state_account) => {
            accounts.push(AccountMeta::new_readonly(*context_state_account, false));
            0
        }
    };

    accounts.push(AccountMeta::new_readonly(
        *authority,
        multisig_signers.is_empty(),
    ));

    for multisig_signer in multisig_signers.iter() {
        accounts.push(AccountMeta::new_readonly(**multisig_signer, true));
    }

    for source in sources.iter() {
        accounts.push(AccountMeta::new(**source, false));
    }

    Ok(encode_instruction(
        token_program_id,
        accounts,
        TokenInstruction::ConfidentialTransferFeeExtension,
        ConfidentialTransferFeeInstruction::WithdrawWithheldTokensFromAccountsForKeyIndex,
        &WithdrawWithheldTokensFromAccountsForKeyIndexData {
            key_index: key_index.into(),
            num_token_accounts,
            proof_instruction_offset,
            new_decryptable_available_balance: *new_decryptable_available_balance,
        },
    ))
}

/// Create a `WithdrawWithheldTokensFromAccountsForKeyIndex` instruction
#[allow(clippy::too_many_arguments)]
pub fn withdraw_withheld_tokens_from_accounts_for_key_index(
    token_program_id: &Address,
    mint: &Address,
    destination: &Address,
    key_index: u64,
    new_decryptable_available_balance: &DecryptableBalance,
    authority: &Address,
    multisig_signers: &[&Address],
    sources: &[&Address],
    proof_data_location: ProofLocation<CiphertextCiphertextEqualityProofData>,
) -> Result<Vec<Instruction>, ProgramError> {
    let mut instructions = vec![inner_withdraw_withheld_tokens_from_accounts_for_key_index(
        token_program_id,
        mint,
        destination,
        key_index,
        new_decryptable_available_balance,
        authority,
        multisig_signers,
        sources,
        proof_data_location,
    )?];

    if let ProofLocation::InstructionOffset(proof_instruction_offset, proof_data) =
        proof_data_location
    {
        // This constructor appends the proof instruction right after the
        // `WithdrawWithheldTokensFromAccountsForKeyIndex` instruction. This means
        // that the proof instruction offset must always be 1. To use an arbitrary
        // proof instruction offset, use the
        // `inner_withdraw_withheld_tokens_from_accounts_for_key_index` constructor.
        let proof_instruction_offset: i8 = proof_instruction_offset.into();
        if proof_instruction_offset != 1 {
            return Err(TokenError::InvalidProofInstructionOffset.into());
        }
        instructions.push(
            ProofInstruction::VerifyCiphertextCiphertextEquality
                .encode_verify_proof(None, proof_data),
        );
    };

    Ok(instructions)
}

/// Create an `InitializeAccountKeyIndex` instruction
pub fn initialize_account_key_index(
    token_program_id: &Address,
    token_account: &Address,
    mint: &Address,
    payer: Option<&Address>,
) -> Result<Instruction, ProgramError> {
    check_program_account(token_program_id)?;
    let mut accounts = vec![
        AccountMeta::new(*token_account, false),
        AccountMeta::new_readonly(*mint, false),
    ];
    if let Some(payer) = payer {
        accounts.push(AccountMeta::new(*payer, true));
        accounts.push(AccountMeta::new_readonly(system_program::id(), false));
    }

    Ok(encode_instruction(
        token_program_id,
        accounts,
        TokenInstruction::ConfidentialTransferFeeExtension,
        ConfidentialTransferFeeInstruction::InitializeAccountKeyIndex,
        &(),
    ))
}
