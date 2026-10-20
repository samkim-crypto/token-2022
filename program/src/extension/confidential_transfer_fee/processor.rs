use {
    crate::{
        extension::confidential_transfer::processor::reallocate_for_extension_types,
        processor::Processor,
    },
    bytemuck::Zeroable,
    core::cmp::Ordering,
    pinocchio::{account::next_account_view, AccountView},
    solana_address::Address,
    solana_msg::msg,
    solana_nullable::MaybeNull,
    solana_program_error::{ProgramError, ProgramResult},
    solana_zk_sdk_pod::encryption::elgamal::PodElGamalPubkey,
    spl_token_2022_interface::{
        check_program_account,
        error::TokenError,
        extension::{
            alloc_and_append_to_variable_len_extension,
            confidential_transfer::{
                instruction::{
                    CiphertextCiphertextEqualityProofContext,
                    CiphertextCiphertextEqualityProofData, PubkeyValidityProofContext,
                    PubkeyValidityProofData,
                },
                ConfidentialTransferAccount, DecryptableBalance,
            },
            confidential_transfer_fee::{
                account_key_index, current_key_index,
                instruction::{
                    ConfidentialTransferFeeInstruction,
                    InitializeConfidentialTransferFeeConfigData,
                    RotateWithdrawWithheldAuthorityElGamalPubkeyData,
                    WithdrawWithheldTokensFromAccountsData,
                    WithdrawWithheldTokensFromAccountsForKeyIndexData,
                    WithdrawWithheldTokensFromMintData,
                    WithdrawWithheldTokensFromMintForKeyIndexData,
                },
                ConfidentialTransferFeeAmount, ConfidentialTransferFeeConfig,
                ConfidentialTransferFeeKeyHistory, ConfidentialTransferFeeKeyIndex,
                ConfidentialTransferFeeKeyRecord, EncryptedWithheldAmount, MAX_KEY_HISTORY_LEN,
            },
            mint_close_authority::MintCloseAuthority,
            transfer_fee::TransferFeeConfig,
            BaseStateWithExtensions, BaseStateWithExtensionsMut, ExtensionType,
            PodStateWithExtensions, PodStateWithExtensionsMut,
        },
        instruction::{decode_instruction_data, decode_instruction_type},
        pod::{PodAccount, PodMint},
    },
    spl_token_confidential_transfer_ciphertext_arithmetic as ciphertext_arithmetic,
    spl_token_confidential_transfer_proof_extraction::instruction::verify_and_extract_context,
};

/// Processes an [`InitializeConfidentialTransferFeeConfig`] instruction.
fn process_initialize_confidential_transfer_fee_config(
    accounts: &mut [AccountView],
    authority: &MaybeNull<Address>,
    withdraw_withheld_authority_elgamal_pubkey: &PodElGamalPubkey,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter_mut();
    let mint_account_info = next_account_view(account_info_iter)?;
    check_program_account(mint_account_info.owner())?;

    let mut mint_data = mint_account_info.try_borrow_mut()?;
    let mut mint = PodStateWithExtensionsMut::<PodMint>::unpack_uninitialized(&mut mint_data)?;
    let extension = mint.init_extension::<ConfidentialTransferFeeConfig>(true)?;
    extension.authority = *authority;
    extension.withdraw_withheld_authority_elgamal_pubkey =
        *withdraw_withheld_authority_elgamal_pubkey;
    extension.harvest_to_mint_enabled = true.into();
    extension.withheld_amount = EncryptedWithheldAmount::zeroed();

    Ok(())
}

/// Returns the withdraw withheld authority ElGamal public key for a key index
fn get_key_index_elgamal_pubkey(
    mint: &PodStateWithExtensionsMut<'_, PodMint>,
    key_index: u64,
    current_key_index: u64,
) -> Result<PodElGamalPubkey, ProgramError> {
    match key_index.cmp(&current_key_index) {
        Ordering::Equal => Ok(mint
            .get_extension::<ConfidentialTransferFeeConfig>()?
            .withdraw_withheld_authority_elgamal_pubkey),
        Ordering::Less => {
            let records = ConfidentialTransferFeeKeyHistory::records_from_bytes(
                mint.get_extension_bytes::<ConfidentialTransferFeeKeyHistory>()?,
            )?;
            usize::try_from(key_index)
                .ok()
                .and_then(|key_index| records.get(key_index))
                .map(|record| record.withdraw_withheld_authority_elgamal_pubkey)
                .ok_or_else(|| TokenError::ConfidentialTransferFeeKeyIndexMismatch.into())
        }
        Ordering::Greater => Err(TokenError::ConfidentialTransferFeeKeyIndexMismatch.into()),
    }
}

/// Returns the withdraw withheld authority ElGamal public key and the mint
/// withheld amount for a key index
fn get_key_index_bucket_mut<'a>(
    mint: &'a mut PodStateWithExtensionsMut<'_, PodMint>,
    key_index: u64,
    current_key_index: u64,
) -> Result<(PodElGamalPubkey, &'a mut EncryptedWithheldAmount), ProgramError> {
    match key_index.cmp(&current_key_index) {
        Ordering::Equal => {
            let confidential_transfer_fee_config =
                mint.get_extension_mut::<ConfidentialTransferFeeConfig>()?;
            Ok((
                confidential_transfer_fee_config.withdraw_withheld_authority_elgamal_pubkey,
                &mut confidential_transfer_fee_config.withheld_amount,
            ))
        }
        Ordering::Less => {
            let records = ConfidentialTransferFeeKeyHistory::records_from_bytes_mut(
                mint.get_extension_bytes_mut::<ConfidentialTransferFeeKeyHistory>()?,
            )?;
            let record = usize::try_from(key_index)
                .ok()
                .and_then(|key_index| records.get_mut(key_index))
                .ok_or(TokenError::ConfidentialTransferFeeKeyIndexMismatch)?;
            Ok((
                record.withdraw_withheld_authority_elgamal_pubkey,
                &mut record.withheld_amount,
            ))
        }
        Ordering::Greater => Err(TokenError::ConfidentialTransferFeeKeyIndexMismatch.into()),
    }
}

/// Processes a [`WithdrawWithheldTokensFromMint`] or
/// [`WithdrawWithheldTokensFromMintForKeyIndex`] instruction. If `key_index` is
/// `None`, the withheld amount is withdrawn from the current key index.
fn process_withdraw_withheld_tokens_from_mint(
    program_id: &Address,
    accounts: &mut [AccountView],
    key_index: Option<u64>,
    new_decryptable_available_balance: &DecryptableBalance,
    proof_instruction_offset: i64,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter_mut();
    let mint_account_info = next_account_view(account_info_iter)?;
    let destination_account_info = next_account_view(account_info_iter)?;

    // zero-knowledge proof certifies that the exact withheld amount is credited to
    // the destination account.
    let proof_context = verify_and_extract_context::<
        CiphertextCiphertextEqualityProofData,
        CiphertextCiphertextEqualityProofContext,
    >(account_info_iter, proof_instruction_offset, None)?;

    let authority_info = next_account_view(account_info_iter)?;
    let authority_info_data_len = authority_info.data_len();

    // unnecessary check, but helps for clarity
    check_program_account(mint_account_info.owner())?;

    // Note: Storing the address of the mint so borrow checker doesn't complain about
    // multiple borrows of `mint_account_info`.
    let mint_account_address = *mint_account_info.address();

    let mut mint_data = mint_account_info.try_borrow_mut()?;
    let mut mint = PodStateWithExtensionsMut::<PodMint>::unpack(&mut mint_data)?;

    // mint must be extended for fees
    {
        let transfer_fee_config = mint.get_extension::<TransferFeeConfig>()?;
        let withdraw_withheld_authority =
            Option::<Address>::from(transfer_fee_config.withdraw_withheld_authority)
                .ok_or(TokenError::NoAuthorityExists)?;
        Processor::validate_owner(
            program_id,
            &withdraw_withheld_authority,
            authority_info,
            authority_info_data_len,
            account_info_iter.as_slice(),
        )?;
    } // free `transfer_fee_config` to borrow `confidential_transfer_fee_config` as
      // mutable

    // mint must also be extended for confidential transfers, but forgo an explicit
    // check since it is not possible to initialize a confidential transfer mint
    // without it

    let current_key_index = current_key_index(&mint)?;
    let (withdraw_withheld_authority_elgamal_pubkey, mint_withheld_amount) =
        get_key_index_bucket_mut(
            &mut mint,
            key_index.unwrap_or(current_key_index),
            current_key_index,
        )?;

    // basic checks for the destination account - must be extended for confidential
    // transfers
    check_program_account(destination_account_info.owner())?;
    let mut destination_account_data = destination_account_info.try_borrow_mut()?;
    let mut destination_account =
        PodStateWithExtensionsMut::<PodAccount>::unpack(&mut destination_account_data)?;

    if destination_account.base.mint != mint_account_address {
        return Err(TokenError::MintMismatch.into());
    }
    if destination_account.base.is_frozen() {
        return Err(TokenError::AccountFrozen.into());
    }
    let destination_confidential_transfer_account =
        destination_account.get_extension_mut::<ConfidentialTransferAccount>()?;
    destination_confidential_transfer_account.valid_as_withheld_amount_destination()?;

    // The funds are moved from the mint to a destination account. Here, the
    // `source` equates to the withdraw withheld authority associated in the
    // mint.

    // Check that the withdraw authority ElGamal public key associated with the mint
    // is consistent with what was actually used to generate the zkp.
    if proof_context.first_pubkey != withdraw_withheld_authority_elgamal_pubkey {
        return Err(TokenError::ConfidentialTransferElGamalPubkeyMismatch.into());
    }
    // Check that the ElGamal public key associated with the destination account is
    // consistent with what was actually used to generate the zkp.
    if proof_context.second_pubkey != destination_confidential_transfer_account.elgamal_pubkey {
        return Err(TokenError::ConfidentialTransferElGamalPubkeyMismatch.into());
    }
    // Check that the withheld amount ciphertext is consistent with the ciphertext
    // data that was actually used to generate the zkp.
    if proof_context.first_ciphertext != *mint_withheld_amount {
        return Err(TokenError::ConfidentialTransferBalanceMismatch.into());
    }

    // The proof data contains the mint withheld amount encrypted under the
    // destination ElGamal pubkey. Add this amount to the available balance.
    destination_confidential_transfer_account.available_balance = ciphertext_arithmetic::add(
        &destination_confidential_transfer_account.available_balance,
        &proof_context.second_ciphertext,
    )
    .ok_or(TokenError::CiphertextArithmeticFailed)?;

    destination_confidential_transfer_account.decryptable_available_balance =
        *new_decryptable_available_balance;

    // Fee is now withdrawn, so zero out the mint withheld amount.
    *mint_withheld_amount = EncryptedWithheldAmount::zeroed();

    Ok(())
}

/// Processes a [`WithdrawWithheldTokensFromAccounts`] or
/// [`WithdrawWithheldTokensFromAccountsForKeyIndex`] instruction. If `key_index`
/// is `None`, the withheld amounts are withdrawn from accounts at the current
/// key index.
fn process_withdraw_withheld_tokens_from_accounts(
    program_id: &Address,
    accounts: &mut [AccountView],
    key_index: Option<u64>,
    num_token_accounts: u8,
    new_decryptable_available_balance: &DecryptableBalance,
    proof_instruction_offset: i64,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter_mut();
    let mint_account_info = next_account_view(account_info_iter)?;
    let destination_account_info = next_account_view(account_info_iter)?;

    // zero-knowledge proof certifies that the exact aggregate withheld amount is
    // credited to the destination account.
    let proof_context = verify_and_extract_context::<
        CiphertextCiphertextEqualityProofData,
        CiphertextCiphertextEqualityProofContext,
    >(account_info_iter, proof_instruction_offset, None)?;

    let authority_info = next_account_view(account_info_iter)?;
    let authority_info_data_len = authority_info.data_len();
    let account_infos = account_info_iter.as_slice();
    let num_signers = account_infos
        .len()
        .saturating_sub(num_token_accounts as usize);

    // unnecessary check, but helps for clarity
    check_program_account(mint_account_info.owner())?;

    // Note: Storing the address of the mint so borrow checker doesn't complain about
    // multiple borrows of `mint_account_info`.
    let mint_account_address = *mint_account_info.address();

    let mut mint_data = mint_account_info.try_borrow_mut()?;
    let mint = PodStateWithExtensionsMut::<PodMint>::unpack(&mut mint_data)?;

    // mint must be extended for fees
    let transfer_fee_config = mint.get_extension::<TransferFeeConfig>()?;
    let withdraw_withheld_authority =
        Option::<Address>::from(transfer_fee_config.withdraw_withheld_authority)
            .ok_or(TokenError::NoAuthorityExists)?;
    Processor::validate_owner(
        program_id,
        &withdraw_withheld_authority,
        authority_info,
        authority_info_data_len,
        &account_infos[..num_signers],
    )?;

    check_program_account(destination_account_info.owner())?;

    // Note: Storing the address of the account so borrow checker doesn't complain about
    // multiple borrows of `destination_account_info`.
    let destination_account_address = *destination_account_info.address();

    let mut destination_account_data = destination_account_info.try_borrow_mut()?;
    let mut destination_account =
        PodStateWithExtensionsMut::<PodAccount>::unpack(&mut destination_account_data)?;
    if destination_account.base.mint != mint_account_address {
        return Err(TokenError::MintMismatch.into());
    }
    if destination_account.base.is_frozen() {
        return Err(TokenError::AccountFrozen.into());
    }

    let current_key_index = current_key_index(&mint)?;
    let key_index = key_index.unwrap_or(current_key_index);

    // summation of withheld amount ciphertexts is expensive, so do all preliminary
    // checks before the summation
    {
        let destination_confidential_transfer_account =
            destination_account.get_extension::<ConfidentialTransferAccount>()?;
        destination_confidential_transfer_account.valid_as_withheld_amount_destination()?;

        // The funds are moved from the accounts to a destination account. Here, the
        // `source` equates to the withdraw withheld authority associated in the
        // mint.

        // Checks that the withdraw authority ElGamal public key associated with the
        // mint is consistent with what was actually used to generate the zkp.
        let withdraw_withheld_authority_elgamal_pubkey =
            get_key_index_elgamal_pubkey(&mint, key_index, current_key_index)?;
        if proof_context.first_pubkey != withdraw_withheld_authority_elgamal_pubkey {
            return Err(TokenError::ConfidentialTransferElGamalPubkeyMismatch.into());
        }
        // Checks that the ElGamal public key associated with the destination account is
        // consistent with what was actually used to generate the zkp.
        if proof_context.second_pubkey != destination_confidential_transfer_account.elgamal_pubkey {
            return Err(TokenError::ConfidentialTransferElGamalPubkeyMismatch.into());
        }
    } // free `destination_confidential_transfer_account`

    // Sum up the withheld amounts in all the accounts.
    let mut aggregate_withheld_amount = EncryptedWithheldAmount::zeroed();
    for account_info in account_info_iter.skip(num_signers) {
        // self-harvest, can't double-borrow the underlying data
        if account_info.address() == &destination_account_address {
            if account_key_index(&destination_account)?.unwrap_or(0) != key_index {
                msg!(
                    "Error harvesting from {}: {}",
                    account_info.address(),
                    TokenError::ConfidentialTransferFeeKeyIndexMismatch
                );
                continue;
            }
            let destination_confidential_transfer_fee_amount = destination_account
                .get_extension_mut::<ConfidentialTransferFeeAmount>()
                .map_err(|_| TokenError::InvalidState)?;

            aggregate_withheld_amount = ciphertext_arithmetic::add(
                &aggregate_withheld_amount,
                &destination_confidential_transfer_fee_amount.withheld_amount,
            )
            .ok_or(TokenError::CiphertextArithmeticFailed)?;

            destination_confidential_transfer_fee_amount.withheld_amount =
                EncryptedWithheldAmount::zeroed();
        } else {
            match harvest_from_account(&mint_account_address, account_info, |account_key_index| {
                account_key_index == key_index
            }) {
                Ok((encrypted_withheld_amount, _)) => {
                    aggregate_withheld_amount = ciphertext_arithmetic::add(
                        &aggregate_withheld_amount,
                        &encrypted_withheld_amount,
                    )
                    .ok_or(TokenError::CiphertextArithmeticFailed)?;
                }
                Err(e) => {
                    msg!("Error harvesting from {}: {}", account_info.address(), e);
                }
            }
        }
    }

    // Checks that the withheld amount ciphertext is consistent with the ciphertext
    // data that was actually used to generate the zkp.
    if proof_context.first_ciphertext != aggregate_withheld_amount {
        return Err(TokenError::ConfidentialTransferBalanceMismatch.into());
    }

    // The proof data contains the mint withheld amount encrypted under the
    // destination ElGamal pubkey. This amount is added to the destination
    // available balance.
    let destination_confidential_transfer_account =
        destination_account.get_extension_mut::<ConfidentialTransferAccount>()?;
    destination_confidential_transfer_account.available_balance = ciphertext_arithmetic::add(
        &destination_confidential_transfer_account.available_balance,
        &proof_context.second_ciphertext,
    )
    .ok_or(ProgramError::InvalidInstructionData)?;

    destination_confidential_transfer_account.decryptable_available_balance =
        *new_decryptable_available_balance;

    Ok(())
}

/// Clears the withheld amount of a token account and returns it with its key
/// index. The account is left untouched if `is_valid_key_index` rejects its key
/// index.
fn harvest_from_account<'b>(
    mint_key: &'b Address,
    token_account_info: &'b mut AccountView,
    is_valid_key_index: impl FnOnce(u64) -> bool,
) -> Result<(EncryptedWithheldAmount, u64), TokenError> {
    // Note: Storing the address of the account so borrow checker doesn't complain about
    // multiple borrows of `token_account_info`.
    let token_account_owner = *token_account_info.owner();

    let mut token_account_data = token_account_info
        .try_borrow_mut()
        .map_err(|_| TokenError::InvalidState)?;
    let mut token_account =
        PodStateWithExtensionsMut::<PodAccount>::unpack(&mut token_account_data)
            .map_err(|_| TokenError::InvalidState)?;
    if token_account.base.mint != *mint_key {
        return Err(TokenError::MintMismatch);
    }
    check_program_account(&token_account_owner).map_err(|_| TokenError::InvalidState)?;

    let key_index = account_key_index(&token_account)
        .map_err(|_| TokenError::InvalidState)?
        .unwrap_or(0);
    if !is_valid_key_index(key_index) {
        return Err(TokenError::ConfidentialTransferFeeKeyIndexMismatch);
    }

    let confidential_transfer_token_account = token_account
        .get_extension_mut::<ConfidentialTransferFeeAmount>()
        .map_err(|_| TokenError::InvalidState)?;

    let withheld_amount = confidential_transfer_token_account.withheld_amount;
    confidential_transfer_token_account.withheld_amount = EncryptedWithheldAmount::zeroed();

    Ok((withheld_amount, key_index))
}

/// Process a [`HarvestWithheldTokensToMint`] instruction.
fn process_harvest_withheld_tokens_to_mint(accounts: &mut [AccountView]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter_mut();
    let mint_account_info = next_account_view(account_info_iter)?;

    check_program_account(mint_account_info.owner())?;

    // Note: Storing the address of the mint so borrow checker doesn't complain about
    // multiple borrows of `token_account_info`.
    let mint_account_address = *mint_account_info.address();

    let mut mint_data = mint_account_info.try_borrow_mut()?;
    let mut mint = PodStateWithExtensionsMut::<PodMint>::unpack(&mut mint_data)?;
    mint.get_extension::<TransferFeeConfig>()?;
    let current_key_index = current_key_index(&mint)?;
    let confidential_transfer_fee_mint = mint.get_extension::<ConfidentialTransferFeeConfig>()?;

    let harvest_to_mint_enabled: bool = confidential_transfer_fee_mint
        .harvest_to_mint_enabled
        .into();
    if !harvest_to_mint_enabled {
        return Err(TokenError::HarvestToMintDisabled.into());
    }

    let mut current_mint_withheld_amount = confidential_transfer_fee_mint.withheld_amount;
    for token_account_info in account_info_iter {
        match harvest_from_account(&mint_account_address, token_account_info, |key_index| {
            key_index <= current_key_index
        }) {
            Ok((withheld_amount, key_index)) if key_index == current_key_index => {
                current_mint_withheld_amount =
                    ciphertext_arithmetic::add(&current_mint_withheld_amount, &withheld_amount)
                        .ok_or(TokenError::CiphertextArithmeticFailed)?;
            }
            Ok((withheld_amount, key_index)) => {
                let (_, mint_withheld_amount) =
                    get_key_index_bucket_mut(&mut mint, key_index, current_key_index)?;
                *mint_withheld_amount =
                    ciphertext_arithmetic::add(mint_withheld_amount, &withheld_amount)
                        .ok_or(TokenError::CiphertextArithmeticFailed)?;
            }
            Err(e) => {
                msg!(
                    "Error harvesting from {}: {}",
                    token_account_info.address(),
                    e
                );
            }
        }
    }

    mint.get_extension_mut::<ConfidentialTransferFeeConfig>()?
        .withheld_amount = current_mint_withheld_amount;
    Ok(())
}

/// Process a [`EnableHarvestToMint`] instruction.
fn process_enable_harvest_to_mint(
    program_id: &Address,
    accounts: &mut [AccountView],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter_mut();
    let mint_info = next_account_view(account_info_iter)?;
    let authority_info = next_account_view(account_info_iter)?;
    let authority_info_data_len = authority_info.data_len();

    check_program_account(mint_info.owner())?;
    let mint_data = &mut mint_info.try_borrow_mut()?;
    let mut mint = PodStateWithExtensionsMut::<PodMint>::unpack(mint_data)?;
    let confidential_transfer_fee_mint =
        mint.get_extension_mut::<ConfidentialTransferFeeConfig>()?;

    let maybe_confidential_transfer_fee_authority: Option<Address> =
        confidential_transfer_fee_mint.authority.into();
    let confidential_transfer_fee_authority =
        maybe_confidential_transfer_fee_authority.ok_or(TokenError::NoAuthorityExists)?;

    Processor::validate_owner(
        program_id,
        &confidential_transfer_fee_authority,
        authority_info,
        authority_info_data_len,
        account_info_iter.as_slice(),
    )?;

    confidential_transfer_fee_mint.harvest_to_mint_enabled = true.into();
    Ok(())
}

/// Process a [`DisableHarvestToMint`] instruction.
fn process_disable_harvest_to_mint(
    program_id: &Address,
    accounts: &mut [AccountView],
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter_mut();
    let mint_info = next_account_view(account_info_iter)?;
    let authority_info = next_account_view(account_info_iter)?;
    let authority_info_data_len = authority_info.data_len();

    check_program_account(mint_info.owner())?;
    let mint_data = &mut mint_info.try_borrow_mut()?;
    let mut mint = PodStateWithExtensionsMut::<PodMint>::unpack(mint_data)?;
    let confidential_transfer_fee_mint =
        mint.get_extension_mut::<ConfidentialTransferFeeConfig>()?;

    let maybe_confidential_transfer_fee_authority: Option<Address> =
        confidential_transfer_fee_mint.authority.into();
    let confidential_transfer_fee_authority =
        maybe_confidential_transfer_fee_authority.ok_or(TokenError::NoAuthorityExists)?;

    Processor::validate_owner(
        program_id,
        &confidential_transfer_fee_authority,
        authority_info,
        authority_info_data_len,
        account_info_iter.as_slice(),
    )?;

    confidential_transfer_fee_mint.harvest_to_mint_enabled = false.into();
    Ok(())
}

/// Process a [`RotateWithdrawWithheldAuthorityElGamalPubkey`] instruction.
fn process_rotate_withdraw_withheld_authority_elgamal_pubkey(
    program_id: &Address,
    accounts: &mut [AccountView],
    expected_key_index: u64,
    new_withdraw_withheld_authority_elgamal_pubkey: &PodElGamalPubkey,
    proof_instruction_offset: i64,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter_mut();
    let mint_account_info = next_account_view(account_info_iter)?;

    // zero-knowledge proof certifies that the new ElGamal public key is valid
    let proof_context = verify_and_extract_context::<
        PubkeyValidityProofData,
        PubkeyValidityProofContext,
    >(account_info_iter, proof_instruction_offset, None)?;
    if proof_context.pubkey != *new_withdraw_withheld_authority_elgamal_pubkey {
        return Err(TokenError::ConfidentialTransferElGamalPubkeyMismatch.into());
    }

    let confidential_transfer_fee_authority_info = next_account_view(account_info_iter)?;
    let confidential_transfer_fee_authority_info_data_len =
        confidential_transfer_fee_authority_info.data_len();
    let withdraw_withheld_authority_info = next_account_view(account_info_iter)?;
    let withdraw_withheld_authority_info_data_len = withdraw_withheld_authority_info.data_len();
    let signers = account_info_iter.as_slice();

    check_program_account(mint_account_info.owner())?;

    let retired_record = {
        let mint_data = mint_account_info.try_borrow()?;
        let mint = PodStateWithExtensions::<PodMint>::unpack(&mint_data)?;

        if current_key_index(&mint)? != expected_key_index {
            return Err(TokenError::ConfidentialTransferFeeKeyIndexMismatch.into());
        }
        if expected_key_index >= MAX_KEY_HISTORY_LEN as u64 {
            return Err(TokenError::ConfidentialTransferFeeKeyHistoryFull.into());
        }

        // The key history must outlive every token account that refers to it, so
        // the mint must never be closable
        if let Ok(mint_close_authority) = mint.get_extension::<MintCloseAuthority>() {
            if Option::<Address>::from(mint_close_authority.close_authority).is_some() {
                return Err(TokenError::MintHasCloseAuthority.into());
            }
        }

        let confidential_transfer_fee_config =
            mint.get_extension::<ConfidentialTransferFeeConfig>()?;
        if confidential_transfer_fee_config.withdraw_withheld_authority_elgamal_pubkey
            == *new_withdraw_withheld_authority_elgamal_pubkey
        {
            return Err(ProgramError::InvalidArgument);
        }

        let confidential_transfer_fee_authority =
            Option::<Address>::from(confidential_transfer_fee_config.authority)
                .ok_or(TokenError::NoAuthorityExists)?;
        Processor::validate_owner(
            program_id,
            &confidential_transfer_fee_authority,
            confidential_transfer_fee_authority_info,
            confidential_transfer_fee_authority_info_data_len,
            signers,
        )?;

        // If there is no withdraw withheld authority, then the withheld fees can
        // never be withdrawn, so the confidential transfer fee authority alone is
        // enough
        let transfer_fee_config = mint.get_extension::<TransferFeeConfig>()?;
        if let Some(withdraw_withheld_authority) =
            Option::<Address>::from(transfer_fee_config.withdraw_withheld_authority)
        {
            Processor::validate_owner(
                program_id,
                &withdraw_withheld_authority,
                withdraw_withheld_authority_info,
                withdraw_withheld_authority_info_data_len,
                signers,
            )?;
        }

        ConfidentialTransferFeeKeyRecord {
            withdraw_withheld_authority_elgamal_pubkey: confidential_transfer_fee_config
                .withdraw_withheld_authority_elgamal_pubkey,
            withheld_amount: confidential_transfer_fee_config.withheld_amount,
        }
    };

    alloc_and_append_to_variable_len_extension::<PodMint, ConfidentialTransferFeeKeyHistory>(
        mint_account_info,
        bytemuck::bytes_of(&retired_record),
    )?;

    let mut mint_data = mint_account_info.try_borrow_mut()?;
    let mut mint = PodStateWithExtensionsMut::<PodMint>::unpack(&mut mint_data)?;
    let confidential_transfer_fee_config =
        mint.get_extension_mut::<ConfidentialTransferFeeConfig>()?;
    confidential_transfer_fee_config.withdraw_withheld_authority_elgamal_pubkey =
        *new_withdraw_withheld_authority_elgamal_pubkey;
    confidential_transfer_fee_config.withheld_amount = EncryptedWithheldAmount::zeroed();

    Ok(())
}

/// Process an [`InitializeAccountKeyIndex`] instruction.
fn process_initialize_account_key_index(accounts: &mut [AccountView]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter_mut();
    let token_account_info = next_account_view(account_info_iter)?;
    let mint_info = next_account_view(account_info_iter)?;

    check_program_account(mint_info.owner())?;
    let current_key_index = {
        let mint_data = mint_info.try_borrow()?;
        let mint = PodStateWithExtensions::<PodMint>::unpack(&mint_data)?;
        current_key_index(&mint)?
    };
    // Accounts of a mint that has never rotated its key stay untagged
    if current_key_index == 0 {
        return Err(TokenError::InvalidState.into());
    }

    check_program_account(token_account_info.owner())?;
    let key_index = {
        let token_account_data = token_account_info.try_borrow()?;
        let token_account = PodStateWithExtensions::<PodAccount>::unpack(&token_account_data)?;
        if token_account.base.mint != *mint_info.address() {
            return Err(TokenError::MintMismatch.into());
        }
        let confidential_transfer_fee_amount =
            token_account.get_extension::<ConfidentialTransferFeeAmount>()?;

        // Anyone can tag an account, so a transaction that tags the account
        // before using it must not fail if another caller tagged it first
        if account_key_index(&token_account)?.is_some() {
            return Ok(());
        }

        // A nonzero withheld amount of an untagged account is encrypted under the
        // key that the mint was initialized with
        if confidential_transfer_fee_amount.withheld_amount == EncryptedWithheldAmount::zeroed() {
            current_key_index
        } else {
            0
        }
    };

    // if a payer account for reallocation is provided, then reallocate
    if let Ok(payer_info) = next_account_view(account_info_iter) {
        let _system_program_info = next_account_view(account_info_iter)?;
        let mut extension_types = {
            let token_account_data = token_account_info.try_borrow()?;
            let token_account = PodStateWithExtensions::<PodAccount>::unpack(&token_account_data)?;
            token_account.get_extension_types()?
        };
        extension_types.push(ExtensionType::ConfidentialTransferFeeKeyIndex);
        reallocate_for_extension_types(token_account_info, payer_info, &extension_types)?;
    }

    let mut token_account_data = token_account_info.try_borrow_mut()?;
    let mut token_account =
        PodStateWithExtensionsMut::<PodAccount>::unpack(&mut token_account_data)?;
    let confidential_transfer_fee_key_index =
        token_account.init_extension::<ConfidentialTransferFeeKeyIndex>(false)?;
    confidential_transfer_fee_key_index.key_index = key_index.into();

    Ok(())
}

#[allow(dead_code)]
pub(crate) fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    input: &[u8],
) -> ProgramResult {
    check_program_account(program_id)?;

    match decode_instruction_type(input)? {
        ConfidentialTransferFeeInstruction::InitializeConfidentialTransferFeeConfig => {
            msg!("ConfidentialTransferFeeInstruction::InitializeConfidentialTransferFeeConfig");
            let data =
                decode_instruction_data::<InitializeConfidentialTransferFeeConfigData>(input)?;
            process_initialize_confidential_transfer_fee_config(
                accounts,
                &data.authority,
                &data.withdraw_withheld_authority_elgamal_pubkey,
            )
        }
        ConfidentialTransferFeeInstruction::WithdrawWithheldTokensFromMint => {
            msg!("ConfidentialTransferFeeInstruction::WithdrawWithheldTokensFromMint");
            let data = decode_instruction_data::<WithdrawWithheldTokensFromMintData>(input)?;
            process_withdraw_withheld_tokens_from_mint(
                program_id,
                accounts,
                None,
                &data.new_decryptable_available_balance,
                data.proof_instruction_offset as i64,
            )
        }
        ConfidentialTransferFeeInstruction::WithdrawWithheldTokensFromAccounts => {
            msg!("ConfidentialTransferFeeInstruction::WithdrawWithheldTokensFromAccounts");
            let data = decode_instruction_data::<WithdrawWithheldTokensFromAccountsData>(input)?;
            process_withdraw_withheld_tokens_from_accounts(
                program_id,
                accounts,
                None,
                data.num_token_accounts,
                &data.new_decryptable_available_balance,
                data.proof_instruction_offset as i64,
            )
        }
        ConfidentialTransferFeeInstruction::HarvestWithheldTokensToMint => {
            msg!("ConfidentialTransferFeeInstruction::HarvestWithheldTokensToMint");
            process_harvest_withheld_tokens_to_mint(accounts)
        }
        ConfidentialTransferFeeInstruction::EnableHarvestToMint => {
            msg!("ConfidentialTransferFeeInstruction::EnableHarvestToMint");
            process_enable_harvest_to_mint(program_id, accounts)
        }
        ConfidentialTransferFeeInstruction::DisableHarvestToMint => {
            msg!("ConfidentialTransferFeeInstruction::DisableHarvestToMint");
            process_disable_harvest_to_mint(program_id, accounts)
        }
        ConfidentialTransferFeeInstruction::RotateWithdrawWithheldAuthorityElGamalPubkey => {
            msg!(
                "ConfidentialTransferFeeInstruction::RotateWithdrawWithheldAuthorityElGamalPubkey"
            );
            let data =
                decode_instruction_data::<RotateWithdrawWithheldAuthorityElGamalPubkeyData>(input)?;
            process_rotate_withdraw_withheld_authority_elgamal_pubkey(
                program_id,
                accounts,
                data.expected_key_index.into(),
                &data.new_withdraw_withheld_authority_elgamal_pubkey,
                data.proof_instruction_offset as i64,
            )
        }
        ConfidentialTransferFeeInstruction::WithdrawWithheldTokensFromMintForKeyIndex => {
            msg!("ConfidentialTransferFeeInstruction::WithdrawWithheldTokensFromMintForKeyIndex");
            let data =
                decode_instruction_data::<WithdrawWithheldTokensFromMintForKeyIndexData>(input)?;
            process_withdraw_withheld_tokens_from_mint(
                program_id,
                accounts,
                Some(data.key_index.into()),
                &data.new_decryptable_available_balance,
                data.proof_instruction_offset as i64,
            )
        }
        ConfidentialTransferFeeInstruction::WithdrawWithheldTokensFromAccountsForKeyIndex => {
            msg!(
                "ConfidentialTransferFeeInstruction::WithdrawWithheldTokensFromAccountsForKeyIndex"
            );
            let data = decode_instruction_data::<WithdrawWithheldTokensFromAccountsForKeyIndexData>(
                input,
            )?;
            process_withdraw_withheld_tokens_from_accounts(
                program_id,
                accounts,
                Some(data.key_index.into()),
                data.num_token_accounts,
                &data.new_decryptable_available_balance,
                data.proof_instruction_offset as i64,
            )
        }
        ConfidentialTransferFeeInstruction::InitializeAccountKeyIndex => {
            msg!("ConfidentialTransferFeeInstruction::InitializeAccountKeyIndex");
            process_initialize_account_key_index(accounts)
        }
    }
}
