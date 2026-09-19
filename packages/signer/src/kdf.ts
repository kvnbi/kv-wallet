import { argon2id } from '@noble/hashes/argon2.js'
import { KEY_LENGTH } from './aead.ts'
import { utf8ToBytes } from './bytes.ts'
import {
  assertParameters,
  createVaultSalt,
  readVaultHeader,
  SALT_LENGTH,
  VAULT_PARAMETERS,
  type VaultKey,
  type VaultParameters,
} from './vault.ts'

const ARGON2_VERSION = 0x13

export function normalizePassword(password: string): string {
  if (typeof password !== 'string') throw new Error('password must be a string')
  return password.normalize('NFC')
}

export function createVaultKey(password: string, parameters: VaultParameters = VAULT_PARAMETERS): VaultKey {
  return deriveVaultKey(password, createVaultSalt(), parameters)
}

export function vaultKeyFor(password: string, vault: Uint8Array): VaultKey {
  const header = readVaultHeader(vault)
  return deriveVaultKey(password, header.salt, header.parameters)
}

export function deriveVaultKey(
  password: string,
  salt: Uint8Array,
  parameters: VaultParameters = VAULT_PARAMETERS,
): VaultKey {
  assertParameters(parameters)
  if (!(salt instanceof Uint8Array) || salt.length !== SALT_LENGTH) throw new Error(`salt must be ${SALT_LENGTH} bytes`)
  const secret = utf8ToBytes(normalizePassword(password))
  if (secret.length === 0) throw new Error('password must not be empty')
  try {
    const key = argon2id(secret, salt, {
      t: parameters.iterations,
      m: parameters.memoryKiB,
      p: parameters.parallelism,
      dkLen: KEY_LENGTH,
      version: ARGON2_VERSION,
    })
    return { key, salt: salt.slice(), parameters: { ...parameters } }
  } finally {
    secret.fill(0)
  }
}
