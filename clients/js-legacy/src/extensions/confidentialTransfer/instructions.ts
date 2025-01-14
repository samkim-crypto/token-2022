import { struct, u8 } from '@solana/buffer-layout';
import { bool, publicKey } from '@solana/buffer-layout-utils';
import { PublicKey, TransactionInstruction } from '@solana/web3.js';
import { programSupportsExtensions, TOKEN_2022_PROGRAM_ID } from '../../constants.js';
import { TokenUnsupportedInstructionError } from '../../errors.js';
import { TokenInstruction } from '../../instructions/types.js';
import { elgamalPublicKey } from './elgamal.js';
import { PodElGamalPubkey } from '@solana/zk-sdk';

export enum ConfidentialTransferInstruction {
    InitializeMint = 0,
    UpdateMint = 1,
}

export interface InitializeMintData {
    instruction: TokenInstruction.ConfidentialTransferExtension;
    confidentialTransferInstruction: ConfidentialTransferInstruction.InitializeMint;
    confidentialTransferMintAuthority: PublicKey | null;
    autoApproveNewAccounts: boolean;
    auditorElGamalPubkey: PodElGamalPubkey | null;
}

export const initializeMintData = struct<InitializeMintData>([
    u8('instruction'),
    u8('confidentialTransferInstruction'),
    publicKey('confidentialTransferMintAuthority'),
    bool('autoApproveNewAccounts'),
    elgamalPublicKey('auditorElGamalPubkey'),
]);

/**
 * Construct a ConfidentialTransferInitializeMint instruction
 *
 * @param mint                              Token mint account
 * @param confidentialTransferMintAuthority Authority that can update confidential transfer mint
 * @param autoApproveNewAccounts            Auto-approve account policy
 * @param auditorElGamalPubkey              Optional auditor ElGamal public key
 * @param programId                         SPL Token program account
 *
 * @return Instruction to add to a transaction
 */
export function createConfidentialTransferInitializeMintInstruction(
    mint: PublicKey,
    confidentialTransferMintAuthority: PublicKey | null,
    autoApproveNewAccounts: boolean,
    auditorElGamalPubkey: PodElGamalPubkey | null,
    programId = TOKEN_2022_PROGRAM_ID,
): TransactionInstruction {
    if (!programSupportsExtensions(programId)) {
        throw new TokenUnsupportedInstructionError();
    }
    const keys = [{ pubkey: mint, isSigner: false, isWritable: true }];

    const data = Buffer.alloc(initializeMintData.span);

    initializeMintData.encode(
        {
            instruction: TokenInstruction.ConfidentialTransferExtension,
            confidentialTransferInstruction: ConfidentialTransferInstruction.InitializeMint,
            confidentialTransferMintAuthority: confidentialTransferMintAuthority ?? PublicKey.default,
            autoApproveNewAccounts: autoApproveNewAccounts,
            auditorElGamalPubkey: auditorElGamalPubkey ?? PodElGamalPubkey.zeroed(),
        },
        data,
    );

    return new TransactionInstruction({ keys, programId, data });
}

export interface UpdateMintData {
    instruction: TokenInstruction.ConfidentialTransferExtension;
    confidentialTransferInstruction: ConfidentialTransferInstruction.UpdateMint;
    autoApproveNewAccounts: boolean;
    auditorElGamalPubkey: PodElGamalPubkey | null;
}

export const updateMintData = struct<UpdateMintData>([
    u8('instruction'),
    u8('confidentialTransferInstruction'),
    bool('autoApproveNewAccounts'),
    elgamalPublicKey('auditorElGamalPubkey'),
]);

/**
 * Construct an UpdateMint instruction
 *
 * @param mint                              Token mint account
 * @param confidentialTransferMintAuthority Authority that can update confidential transfer mint
 * @param autoApproveNewAccounts            New auto-approve account policy
 * @param auditorElGamalPubkey              New auditor ElGamal public key
 * @param programId                         SPL Token program account
 *
 * @return Instruction to add to a transaction
 */
export function createConfidentialTransferUpdateMintInstruction(
    mint: PublicKey,
    confidentialTransferMintAuthority: PublicKey,
    autoApproveNewAccounts: boolean,
    auditorElGamalPubkey: PodElGamalPubkey | null,
    programId = TOKEN_2022_PROGRAM_ID,
): TransactionInstruction {
    if (!programSupportsExtensions(programId)) {
        throw new TokenUnsupportedInstructionError();
    }
    const keys = [
        { pubkey: mint, isSigner: false, isWritable: true },
        { pubkey: confidentialTransferMintAuthority, isSigner: true, isWritable: false },
    ];

    const data = Buffer.alloc(updateMintData.span);
    updateMintData.encode(
        {
            instruction: TokenInstruction.ConfidentialTransferExtension,
            confidentialTransferInstruction: ConfidentialTransferInstruction.UpdateMint,
            autoApproveNewAccounts: autoApproveNewAccounts,
            auditorElGamalPubkey: auditorElGamalPubkey ?? PodElGamalPubkey.zeroed(),
        },
        data,
    );

    return new TransactionInstruction({ keys, programId, data });
}
