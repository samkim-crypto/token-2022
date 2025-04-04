/**
 * This code was AUTOGENERATED using the codama library.
 * Please DO NOT EDIT THIS FILE, instead use visitors
 * to add features, then rerun codama to update it.
 *
 * @see https://github.com/codama-idl/codama
 */

import {
  AccountRole,
  combineCodec,
  getStructDecoder,
  getStructEncoder,
  getU8Decoder,
  getU8Encoder,
  transformEncoder,
  type Address,
  type Codec,
  type Decoder,
  type Encoder,
  type IAccountMeta,
  type IAccountSignerMeta,
  type IInstruction,
  type IInstructionWithAccounts,
  type IInstructionWithData,
  type ReadonlyAccount,
  type ReadonlySignerAccount,
  type TransactionSigner,
  type WritableAccount,
} from '@solana/kit';
import { TOKEN_2022_PROGRAM_ADDRESS } from '../programs';
import { getAccountMetaFactory, type ResolvedAccount } from '../shared';

export const ENABLE_HARVEST_TO_MINT_DISCRIMINATOR = 37;

export function getEnableHarvestToMintDiscriminatorBytes() {
  return getU8Encoder().encode(ENABLE_HARVEST_TO_MINT_DISCRIMINATOR);
}

export const ENABLE_HARVEST_TO_MINT_CONFIDENTIAL_TRANSFER_FEE_DISCRIMINATOR = 4;

export function getEnableHarvestToMintConfidentialTransferFeeDiscriminatorBytes() {
  return getU8Encoder().encode(
    ENABLE_HARVEST_TO_MINT_CONFIDENTIAL_TRANSFER_FEE_DISCRIMINATOR
  );
}

export type EnableHarvestToMintInstruction<
  TProgram extends string = typeof TOKEN_2022_PROGRAM_ADDRESS,
  TAccountMint extends string | IAccountMeta<string> = string,
  TAccountAuthority extends string | IAccountMeta<string> = string,
  TRemainingAccounts extends readonly IAccountMeta<string>[] = [],
> = IInstruction<TProgram> &
  IInstructionWithData<Uint8Array> &
  IInstructionWithAccounts<
    [
      TAccountMint extends string
        ? WritableAccount<TAccountMint>
        : TAccountMint,
      TAccountAuthority extends string
        ? ReadonlyAccount<TAccountAuthority>
        : TAccountAuthority,
      ...TRemainingAccounts,
    ]
  >;

export type EnableHarvestToMintInstructionData = {
  discriminator: number;
  confidentialTransferFeeDiscriminator: number;
};

export type EnableHarvestToMintInstructionDataArgs = {};

export function getEnableHarvestToMintInstructionDataEncoder(): Encoder<EnableHarvestToMintInstructionDataArgs> {
  return transformEncoder(
    getStructEncoder([
      ['discriminator', getU8Encoder()],
      ['confidentialTransferFeeDiscriminator', getU8Encoder()],
    ]),
    (value) => ({
      ...value,
      discriminator: ENABLE_HARVEST_TO_MINT_DISCRIMINATOR,
      confidentialTransferFeeDiscriminator:
        ENABLE_HARVEST_TO_MINT_CONFIDENTIAL_TRANSFER_FEE_DISCRIMINATOR,
    })
  );
}

export function getEnableHarvestToMintInstructionDataDecoder(): Decoder<EnableHarvestToMintInstructionData> {
  return getStructDecoder([
    ['discriminator', getU8Decoder()],
    ['confidentialTransferFeeDiscriminator', getU8Decoder()],
  ]);
}

export function getEnableHarvestToMintInstructionDataCodec(): Codec<
  EnableHarvestToMintInstructionDataArgs,
  EnableHarvestToMintInstructionData
> {
  return combineCodec(
    getEnableHarvestToMintInstructionDataEncoder(),
    getEnableHarvestToMintInstructionDataDecoder()
  );
}

export type EnableHarvestToMintInput<
  TAccountMint extends string = string,
  TAccountAuthority extends string = string,
> = {
  /** The token mint. */
  mint: Address<TAccountMint>;
  /** The confidential transfer fee authority */
  authority: Address<TAccountAuthority> | TransactionSigner<TAccountAuthority>;
  multiSigners?: Array<TransactionSigner>;
};

export function getEnableHarvestToMintInstruction<
  TAccountMint extends string,
  TAccountAuthority extends string,
  TProgramAddress extends Address = typeof TOKEN_2022_PROGRAM_ADDRESS,
>(
  input: EnableHarvestToMintInput<TAccountMint, TAccountAuthority>,
  config?: { programAddress?: TProgramAddress }
): EnableHarvestToMintInstruction<
  TProgramAddress,
  TAccountMint,
  (typeof input)['authority'] extends TransactionSigner<TAccountAuthority>
    ? ReadonlySignerAccount<TAccountAuthority> &
        IAccountSignerMeta<TAccountAuthority>
    : TAccountAuthority
> {
  // Program address.
  const programAddress = config?.programAddress ?? TOKEN_2022_PROGRAM_ADDRESS;

  // Original accounts.
  const originalAccounts = {
    mint: { value: input.mint ?? null, isWritable: true },
    authority: { value: input.authority ?? null, isWritable: false },
  };
  const accounts = originalAccounts as Record<
    keyof typeof originalAccounts,
    ResolvedAccount
  >;

  // Original args.
  const args = { ...input };

  // Remaining accounts.
  const remainingAccounts: IAccountMeta[] = (args.multiSigners ?? []).map(
    (signer) => ({
      address: signer.address,
      role: AccountRole.READONLY_SIGNER,
      signer,
    })
  );

  const getAccountMeta = getAccountMetaFactory(programAddress, 'programId');
  const instruction = {
    accounts: [
      getAccountMeta(accounts.mint),
      getAccountMeta(accounts.authority),
      ...remainingAccounts,
    ],
    programAddress,
    data: getEnableHarvestToMintInstructionDataEncoder().encode({}),
  } as EnableHarvestToMintInstruction<
    TProgramAddress,
    TAccountMint,
    (typeof input)['authority'] extends TransactionSigner<TAccountAuthority>
      ? ReadonlySignerAccount<TAccountAuthority> &
          IAccountSignerMeta<TAccountAuthority>
      : TAccountAuthority
  >;

  return instruction;
}

export type ParsedEnableHarvestToMintInstruction<
  TProgram extends string = typeof TOKEN_2022_PROGRAM_ADDRESS,
  TAccountMetas extends readonly IAccountMeta[] = readonly IAccountMeta[],
> = {
  programAddress: Address<TProgram>;
  accounts: {
    /** The token mint. */
    mint: TAccountMetas[0];
    /** The confidential transfer fee authority */
    authority: TAccountMetas[1];
  };
  data: EnableHarvestToMintInstructionData;
};

export function parseEnableHarvestToMintInstruction<
  TProgram extends string,
  TAccountMetas extends readonly IAccountMeta[],
>(
  instruction: IInstruction<TProgram> &
    IInstructionWithAccounts<TAccountMetas> &
    IInstructionWithData<Uint8Array>
): ParsedEnableHarvestToMintInstruction<TProgram, TAccountMetas> {
  if (instruction.accounts.length < 2) {
    // TODO: Coded error.
    throw new Error('Not enough accounts');
  }
  let accountIndex = 0;
  const getNextAccount = () => {
    const accountMeta = instruction.accounts![accountIndex]!;
    accountIndex += 1;
    return accountMeta;
  };
  return {
    programAddress: instruction.programAddress,
    accounts: {
      mint: getNextAccount(),
      authority: getNextAccount(),
    },
    data: getEnableHarvestToMintInstructionDataDecoder().decode(
      instruction.data
    ),
  };
}
