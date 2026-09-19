import assert from 'node:assert/strict'
import { test } from 'node:test'
import { encrypt } from '../src/aead.ts'
import { concatBytes, toBytes, toHex, utf8ToBytes } from '../src/bytes.ts'
import {
  createVaultSalt,
  HEADER_LENGTH,
  MAX_SECRET_LENGTH,
  openVault,
  readVaultHeader,
  RECORD_LENGTH,
  sealVault,
  sealVaultWithNonce,
  VAULT_LENGTH,
  VAULT_PARAMETERS,
  VAULT_VERSION,
  type VaultKey,
} from '../src/vault.ts'
import { fixture } from './load.ts'

const golden = fixture('vault-golden.json')

const bip39 = fixture('bip39.json')

const vaultKey: VaultKey = {
  key: new Uint8Array(32).fill(7),
  salt: new Uint8Array(16).fill(9),
  parameters: VAULT_PARAMETERS,
}

async function sealed(secret: Uint8Array): Promise<Uint8Array> {
  return sealVault(vaultKey, secret)
}

function tampered(vault: Uint8Array, offset: number): Uint8Array {
  const copy = vault.slice()
  copy[offset] = (copy[offset] ?? 0) ^ 0x01
  return copy
}

test('reproduces a vault built by an independent implementation', async () => {
  const key = toBytes(golden.key)
  const built = await sealVaultWithNonce(
    { key, salt: toBytes(golden.salt), parameters: golden.parameters },
    utf8ToBytes(golden.secretUtf8),
    toBytes(golden.nonce),
  )
  assert.equal(toHex(built), golden.vault)
  assert.equal(toHex(built.subarray(0, HEADER_LENGTH)), golden.header)
  assert.equal(toHex(await openVault(key, toBytes(golden.vault))), toHex(utf8ToBytes(golden.secretUtf8)))
})

test('round trips a secret and records the parameters in the header', async () => {
  const secret = utf8ToBytes(bip39.cases[0].mnemonic)
  const vault = await sealed(secret)
  assert.equal(vault.length, VAULT_LENGTH)
  const header = readVaultHeader(vault)
  assert.equal(header.version, VAULT_VERSION)
  assert.equal(header.kdf, 'argon2id')
  assert.deepEqual(header.parameters, VAULT_PARAMETERS)
  assert.deepEqual(header.salt, vaultKey.salt)
  assert.equal(header.nonce.length, 12)
  assert.equal(toHex(await openVault(vaultKey.key, vault)), toHex(secret))
})

test('the vault is always the same size, so the phrase length does not leak', async () => {
  const lengths = new Set<number>()
  for (const entry of bip39.cases as { mnemonic: string }[]) {
    lengths.add((await sealed(utf8ToBytes(entry.mnemonic))).length)
  }
  assert.deepEqual([...lengths], [VAULT_LENGTH])
  assert.ok((bip39.cases as { mnemonic: string }[]).some(e => e.mnemonic.split(' ').length === 24))
})

test('the header layout is fixed at the documented offsets', async () => {
  const vault = await sealed(utf8ToBytes('secret'))
  assert.equal(toHex(vault.subarray(0, 3)), '0x4b5657')
  assert.equal(vault[3], VAULT_VERSION)
  assert.equal(vault[4], 1)
  assert.equal(toHex(vault.subarray(5, 9)), '0x00010000')
  assert.equal(toHex(vault.subarray(9, 13)), '0x00000003')
  assert.equal(vault[13], 1)
  assert.equal(toHex(vault.subarray(14, 30)), toHex(vaultKey.salt))
  assert.equal(toHex(vault.subarray(30, 42)), toHex(readVaultHeader(vault).nonce))
})

test('every header field is authenticated, so none can be altered', async () => {
  const vault = await sealed(utf8ToBytes('secret'))
  for (const offset of [3, 5, 9, 13, 14, 29, 30, 41]) {
    await assert.rejects(() => openVault(vaultKey.key, tampered(vault, offset)), /authentication failed|unsupported|must be an integer/, `offset ${offset}`)
  }
  const downgraded = vault.slice()
  downgraded[5] = 0x00
  downgraded[6] = 0x00
  downgraded[7] = 0x20
  downgraded[8] = 0x00
  assert.deepEqual(readVaultHeader(downgraded).parameters.memoryKiB, 8192)
  await assert.rejects(() => openVault(vaultKey.key, downgraded), /authentication failed/)
})

test('a tampered ciphertext, a wrong key and a wrong length are all rejected', async () => {
  const vault = await sealed(utf8ToBytes('secret'))
  await assert.rejects(() => openVault(vaultKey.key, tampered(vault, HEADER_LENGTH + 4)), /authentication failed/)
  await assert.rejects(() => openVault(vaultKey.key, tampered(vault, VAULT_LENGTH - 1)), /authentication failed/)
  await assert.rejects(() => openVault(new Uint8Array(32).fill(8), vault), /authentication failed/)
  await assert.rejects(() => openVault(vaultKey.key, vault.subarray(0, VAULT_LENGTH - 1)), /must be exactly 314 bytes/)
  assert.throws(() => readVaultHeader(new Uint8Array(VAULT_LENGTH)), /not a KV Wallet vault/)
  assert.throws(() => readVaultHeader('vault' as never), /vault must be bytes/)
})

test('an unknown version or key derivation function is refused', async () => {
  const vault = await sealed(utf8ToBytes('secret'))
  const future = vault.slice()
  future[3] = 2
  assert.throws(() => readVaultHeader(future), /unsupported vault version 2/)
  const other = vault.slice()
  other[4] = 2
  assert.throws(() => readVaultHeader(other), /unsupported key derivation function/)
})

test('each seal uses a fresh nonce and produces different bytes', async () => {
  const secret = utf8ToBytes('secret')
  const nonces = new Set<string>()
  const bodies = new Set<string>()
  for (let i = 0; i < 16; i++) {
    const vault = await sealed(secret)
    nonces.add(toHex(readVaultHeader(vault).nonce))
    bodies.add(toHex(vault.subarray(HEADER_LENGTH)))
    assert.equal(toHex(await openVault(vaultKey.key, vault)), toHex(secret))
  }
  assert.equal(nonces.size, 16)
  assert.equal(bodies.size, 16)
})

test('secrets are limited to the record size', async () => {
  const largest = await sealed(new Uint8Array(MAX_SECRET_LENGTH).fill(1))
  assert.equal((await openVault(vaultKey.key, largest)).length, MAX_SECRET_LENGTH)
  assert.equal((await openVault(vaultKey.key, await sealed(new Uint8Array(0)))).length, 0)
  await assert.rejects(() => sealed(new Uint8Array(MAX_SECRET_LENGTH + 1)), /at most 254 bytes/)
  await assert.rejects(() => sealed('secret' as never), /secret must be bytes/)
})

test('key derivation parameters are bounded on both write and read', async () => {
  const cases: [number, number, number, RegExp][] = [
    [1024, 3, 1, /memoryKiB must be an integer from 8192 to 262144/],
    [1048576, 3, 1, /memoryKiB must be an integer from 8192 to 262144/],
    [65536, 0, 1, /iterations must be an integer from 1 to 16/],
    [65536, 17, 1, /iterations must be an integer from 1 to 16/],
    [65536, 3, 0, /parallelism must be an integer from 1 to 4/],
    [65536, 3, 5, /parallelism must be an integer from 1 to 4/],
  ]
  for (const [memoryKiB, iterations, parallelism, message] of cases) {
    const parameters = { memoryKiB, iterations, parallelism }
    await assert.rejects(() => sealVault({ ...vaultKey, parameters }, utf8ToBytes('secret')), message)
    const vault = (await sealed(utf8ToBytes('secret'))).slice()
    vault[5] = (memoryKiB >>> 24) & 0xff
    vault[6] = (memoryKiB >>> 16) & 0xff
    vault[7] = (memoryKiB >>> 8) & 0xff
    vault[8] = memoryKiB & 0xff
    vault[9] = (iterations >>> 24) & 0xff
    vault[10] = (iterations >>> 16) & 0xff
    vault[11] = (iterations >>> 8) & 0xff
    vault[12] = iterations & 0xff
    vault[13] = parallelism
    assert.throws(() => readVaultHeader(vault), message)
  }
})

test('a malformed record is refused even when it authenticates correctly', async () => {
  const vault = await sealed(utf8ToBytes('secret'))
  const header = vault.subarray(0, HEADER_LENGTH)
  const { nonce } = readVaultHeader(vault)
  const forge = async (record: Uint8Array): Promise<Uint8Array> =>
    concatBytes(header, await encrypt(vaultKey.key, nonce, header, record))
  const padded = new Uint8Array(RECORD_LENGTH)
  padded[1] = 6
  padded.set(utf8ToBytes('secret'), 2)
  padded[RECORD_LENGTH - 1] = 0xff
  const paddedVault = await forge(padded)
  await assert.rejects(() => openVault(vaultKey.key, paddedVault), /padding is not zero/)
  const oversized = new Uint8Array(RECORD_LENGTH)
  oversized[0] = 0xff
  oversized[1] = 0xff
  const oversizedVault = await forge(oversized)
  await assert.rejects(() => openVault(vaultKey.key, oversizedVault), /record is malformed/)
})

test('salts are 16 random bytes', () => {
  const salt = createVaultSalt()
  assert.equal(salt.length, 16)
  assert.notEqual(toHex(salt), toHex(createVaultSalt()))
})
