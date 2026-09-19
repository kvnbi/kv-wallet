import { parseAddress, type Address } from './address.ts'
import { concatBytes, keccak256, minimalBytes, toBigInt, toBytes, toHex, type Hex } from './bytes.ts'
import { component, parity, type Signature } from './ecdsa.ts'
import { rlpEncode, type RlpInput } from './rlp.ts'

export interface AccessListEntry {
  address: Address
  storageKeys: readonly Hex[]
}

export interface LegacyTransaction {
  type: 'legacy'
  chainId: bigint
  nonce: bigint
  gasPrice: bigint
  gasLimit: bigint
  to: Address | null
  value: bigint
  data: Hex
}

export interface Eip1559Transaction {
  type: 'eip1559'
  chainId: bigint
  nonce: bigint
  maxPriorityFeePerGas: bigint
  maxFeePerGas: bigint
  gasLimit: bigint
  to: Address | null
  value: bigint
  data: Hex
  accessList: readonly AccessListEntry[]
}

export type Transaction = LegacyTransaction | Eip1559Transaction

const WORD = 2n ** 256n

const UINT64 = 2n ** 64n

const EMPTY = new Uint8Array(0)

export function transactionSigningPayload(transaction: Transaction): Uint8Array {
  if (transaction.type === 'legacy') {
    return rlpEncode([...legacyFields(transaction), encodeChainId(transaction.chainId), EMPTY, EMPTY])
  }
  if (transaction.type === 'eip1559') return concatBytes(Uint8Array.of(0x02), rlpEncode(eip1559Fields(transaction)))
  throw new Error('unsupported transaction type')
}

export function transactionSigningHash(transaction: Transaction): Hex {
  return toHex(keccak256(transactionSigningPayload(transaction)))
}

export function serializeTransaction(transaction: Transaction, signature: Signature): Hex {
  const yParity = BigInt(parity(signature.yParity))
  const r = minimalBytes(toBigInt(component(signature.r)))
  const s = minimalBytes(toBigInt(component(signature.s)))
  if (transaction.type === 'legacy') {
    const fields = legacyFields(transaction)
    return toHex(rlpEncode([...fields, minimalBytes(yParity + transaction.chainId * 2n + 35n), r, s]))
  }
  if (transaction.type === 'eip1559') {
    return toHex(concatBytes(Uint8Array.of(0x02), rlpEncode([...eip1559Fields(transaction), minimalBytes(yParity), r, s])))
  }
  throw new Error('unsupported transaction type')
}

function legacyFields(transaction: LegacyTransaction): RlpInput[] {
  encodeChainId(transaction.chainId)
  return [
    integer('nonce', transaction.nonce, UINT64),
    integer('gasPrice', transaction.gasPrice, WORD),
    integer('gasLimit', transaction.gasLimit, UINT64),
    recipient(transaction.to),
    integer('value', transaction.value, WORD),
    toBytes(transaction.data),
  ]
}

function eip1559Fields(transaction: Eip1559Transaction): RlpInput[] {
  const chainId = encodeChainId(transaction.chainId)
  const priority = integer('maxPriorityFeePerGas', transaction.maxPriorityFeePerGas, WORD)
  const max = integer('maxFeePerGas', transaction.maxFeePerGas, WORD)
  if (transaction.maxPriorityFeePerGas > transaction.maxFeePerGas) {
    throw new Error('maxPriorityFeePerGas must not exceed maxFeePerGas')
  }
  return [
    chainId,
    integer('nonce', transaction.nonce, UINT64),
    priority,
    max,
    integer('gasLimit', transaction.gasLimit, UINT64),
    recipient(transaction.to),
    integer('value', transaction.value, WORD),
    toBytes(transaction.data),
    accessList(transaction.accessList),
  ]
}

function encodeChainId(value: bigint): Uint8Array {
  if (typeof value !== 'bigint' || value < 1n || value >= UINT64) throw new Error('chainId must be a positive integer below 2^64')
  return minimalBytes(value)
}

function integer(name: string, value: bigint, limit: bigint): Uint8Array {
  if (typeof value !== 'bigint' || value < 0n || value >= limit) throw new Error(`${name} is out of range`)
  return minimalBytes(value)
}

function recipient(to: Address | null): Uint8Array {
  return to === null ? EMPTY : parseAddress(to)
}

function accessList(entries: readonly AccessListEntry[]): RlpInput {
  if (!Array.isArray(entries)) throw new Error('accessList must be an array')
  return entries.map(entry => {
    if (!Array.isArray(entry.storageKeys)) throw new Error('storageKeys must be an array')
    return [parseAddress(entry.address), entry.storageKeys.map(storageKey)]
  })
}

function storageKey(key: Hex): Uint8Array {
  const bytes = toBytes(key)
  if (bytes.length !== 32) throw new Error('storage keys must be 32 bytes')
  return bytes
}
