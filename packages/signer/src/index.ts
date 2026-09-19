import type { Address } from './address.ts'
import { toBytes, type Hex } from './bytes.ts'
import { withPrivateKey } from './derivation.ts'
import { privateKeyToAddress, signDigest, type Signature } from './ecdsa.ts'
import { hashPersonalMessage } from './personal.ts'
import { serializeTransaction, transactionSigningHash, type Transaction } from './transaction.ts'
import { hashTypedData, type TypedData } from './typed-data.ts'

export type { Address } from './address.ts'
export type { Hex } from './bytes.ts'
export type { Signature } from './ecdsa.ts'
export type { AccessListEntry, Eip1559Transaction, LegacyTransaction, Transaction } from './transaction.ts'
export type { TypedData, TypedDataField, TypedDataTypes } from './typed-data.ts'
export type { VaultHeader, VaultKey, VaultParameters } from './vault.ts'

export { derivationPath } from './derivation.ts'
export { serializeSignature } from './ecdsa.ts'
export { generateMnemonic, mnemonicToSeed, validateMnemonic } from './mnemonic.ts'
export { hashPersonalMessage } from './personal.ts'
export { transactionSigningHash } from './transaction.ts'
export { hashTypedData } from './typed-data.ts'
export { createVaultKey, deriveVaultKey, vaultKeyFor } from './kdf.ts'
export { createVaultSalt, openVault, readVaultHeader, sealVault, VAULT_PARAMETERS } from './vault.ts'

export function deriveAddress(seed: Uint8Array, index: number): Address {
  return withPrivateKey(seed, index, privateKeyToAddress)
}

export function signTransaction(seed: Uint8Array, index: number, transaction: Transaction): Hex {
  const digest = toBytes(transactionSigningHash(transaction))
  return withPrivateKey(seed, index, privateKey => serializeTransaction(transaction, signDigest(privateKey, digest)))
}

export function signTypedData(seed: Uint8Array, index: number, typedData: TypedData): Signature {
  const digest = toBytes(hashTypedData(typedData))
  return withPrivateKey(seed, index, privateKey => signDigest(privateKey, digest))
}

export function signPersonalMessage(seed: Uint8Array, index: number, message: Uint8Array): Signature {
  const digest = toBytes(hashPersonalMessage(message))
  return withPrivateKey(seed, index, privateKey => signDigest(privateKey, digest))
}
