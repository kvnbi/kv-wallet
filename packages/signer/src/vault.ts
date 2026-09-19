import { randomBytes } from '@noble/hashes/utils.js'
import { decrypt, encrypt, NONCE_LENGTH, TAG_LENGTH } from './aead.ts'
import { concatBytes } from './bytes.ts'

export interface VaultParameters {
  memoryKiB: number
  iterations: number
  parallelism: number
}

export interface VaultKey {
  key: Uint8Array
  salt: Uint8Array
  parameters: VaultParameters
}

export interface VaultHeader {
  version: number
  kdf: 'argon2id'
  parameters: VaultParameters
  salt: Uint8Array
  nonce: Uint8Array
}

export const VAULT_VERSION = 1

export const VAULT_PARAMETERS: VaultParameters = { memoryKiB: 65536, iterations: 3, parallelism: 1 }

export const SALT_LENGTH = 16

export const RECORD_LENGTH = 256

export const MAX_SECRET_LENGTH = RECORD_LENGTH - 2

export const HEADER_LENGTH = 42

export const VAULT_LENGTH = HEADER_LENGTH + RECORD_LENGTH + TAG_LENGTH

const MAGIC = Uint8Array.of(0x4b, 0x56, 0x57)

const ARGON2ID = 1

const MEMORY_MIN = 8192

const MEMORY_MAX = 262144

const ITERATIONS_MIN = 1

const ITERATIONS_MAX = 16

const PARALLELISM_MIN = 1

const PARALLELISM_MAX = 4

export function createVaultSalt(): Uint8Array {
  return randomBytes(SALT_LENGTH)
}

export async function sealVault(vaultKey: VaultKey, secret: Uint8Array): Promise<Uint8Array> {
  return sealVaultWithNonce(vaultKey, secret, randomBytes(NONCE_LENGTH))
}

export async function sealVaultWithNonce(
  vaultKey: VaultKey,
  secret: Uint8Array,
  nonce: Uint8Array,
): Promise<Uint8Array> {
  const header = encodeHeader({
    version: VAULT_VERSION,
    kdf: 'argon2id',
    parameters: vaultKey.parameters,
    salt: vaultKey.salt,
    nonce,
  })
  const record = encodeRecord(secret)
  try {
    return concatBytes(header, await encrypt(vaultKey.key, nonce, header, record))
  } finally {
    record.fill(0)
  }
}

export async function openVault(key: Uint8Array, vault: Uint8Array): Promise<Uint8Array> {
  const header = readVaultHeader(vault)
  const record = await decrypt(key, header.nonce, vault.subarray(0, HEADER_LENGTH), vault.subarray(HEADER_LENGTH))
  try {
    return decodeRecord(record)
  } finally {
    record.fill(0)
  }
}

export function readVaultHeader(vault: Uint8Array): VaultHeader {
  if (!(vault instanceof Uint8Array)) throw new Error('vault must be bytes')
  if (vault.length !== VAULT_LENGTH) throw new Error(`vault must be exactly ${VAULT_LENGTH} bytes`)
  for (let i = 0; i < MAGIC.length; i++) {
    if (vault[i] !== MAGIC[i]) throw new Error('not a KV Wallet vault')
  }
  const version = vault[3] ?? 0
  if (version !== VAULT_VERSION) throw new Error(`unsupported vault version ${version}`)
  if (vault[4] !== ARGON2ID) throw new Error('unsupported key derivation function')
  const parameters = {
    memoryKiB: readUint32(vault, 5),
    iterations: readUint32(vault, 9),
    parallelism: vault[13] ?? 0,
  }
  assertParameters(parameters)
  return { version, kdf: 'argon2id', parameters, salt: vault.slice(14, 30), nonce: vault.slice(30, 42) }
}

export function assertParameters(parameters: VaultParameters): void {
  const { memoryKiB, iterations, parallelism } = parameters
  bound('memoryKiB', memoryKiB, MEMORY_MIN, MEMORY_MAX)
  bound('iterations', iterations, ITERATIONS_MIN, ITERATIONS_MAX)
  bound('parallelism', parallelism, PARALLELISM_MIN, PARALLELISM_MAX)
  if (memoryKiB < 8 * parallelism) throw new Error('memoryKiB must be at least 8 times parallelism')
}

function bound(name: string, value: number, min: number, max: number): void {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer from ${min} to ${max}`)
  }
}

function encodeHeader(header: VaultHeader): Uint8Array {
  assertParameters(header.parameters)
  if (!(header.salt instanceof Uint8Array) || header.salt.length !== SALT_LENGTH) {
    throw new Error(`salt must be ${SALT_LENGTH} bytes`)
  }
  if (!(header.nonce instanceof Uint8Array) || header.nonce.length !== NONCE_LENGTH) {
    throw new Error(`nonce must be ${NONCE_LENGTH} bytes`)
  }
  const out = new Uint8Array(HEADER_LENGTH)
  out.set(MAGIC, 0)
  out[3] = header.version
  out[4] = ARGON2ID
  writeUint32(out, 5, header.parameters.memoryKiB)
  writeUint32(out, 9, header.parameters.iterations)
  out[13] = header.parameters.parallelism
  out.set(header.salt, 14)
  out.set(header.nonce, 30)
  return out
}

function encodeRecord(secret: Uint8Array): Uint8Array {
  if (!(secret instanceof Uint8Array)) throw new Error('secret must be bytes')
  if (secret.length > MAX_SECRET_LENGTH) throw new Error(`secret must be at most ${MAX_SECRET_LENGTH} bytes`)
  const record = new Uint8Array(RECORD_LENGTH)
  record[0] = secret.length >>> 8
  record[1] = secret.length & 0xff
  record.set(secret, 2)
  return record
}

function decodeRecord(record: Uint8Array): Uint8Array {
  if (record.length !== RECORD_LENGTH) throw new Error('vault record has the wrong length')
  const length = ((record[0] ?? 0) << 8) | (record[1] ?? 0)
  if (length > MAX_SECRET_LENGTH) throw new Error('vault record is malformed')
  for (let i = 2 + length; i < RECORD_LENGTH; i++) {
    if (record[i] !== 0) throw new Error('vault record padding is not zero')
  }
  return record.slice(2, 2 + length)
}

function readUint32(bytes: Uint8Array, offset: number): number {
  return ((bytes[offset] ?? 0) * 0x1000000) + (((bytes[offset + 1] ?? 0) << 16) | ((bytes[offset + 2] ?? 0) << 8) | (bytes[offset + 3] ?? 0))
}

function writeUint32(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = (value >>> 24) & 0xff
  bytes[offset + 1] = (value >>> 16) & 0xff
  bytes[offset + 2] = (value >>> 8) & 0xff
  bytes[offset + 3] = value & 0xff
}
