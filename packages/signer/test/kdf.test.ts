import { argon2id } from '@noble/hashes/argon2.js'
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { toBytes, toHex, utf8ToBytes } from '../src/bytes.ts'
import { createVaultKey, deriveVaultKey, normalizePassword, vaultKeyFor } from '../src/kdf.ts'
import { openVault, sealVault, VAULT_PARAMETERS, type VaultParameters } from '../src/vault.ts'
import { fixture } from './load.ts'

const argon2 = fixture('argon2.json')

const CHEAP: VaultParameters = { memoryKiB: 8192, iterations: 1, parallelism: 1 }

const SALT = new Uint8Array(16).fill(5)

test('matches the RFC 9106 Argon2id test vector', () => {
  const vector = argon2.rfc9106
  const tag = argon2id(toBytes(vector.password), toBytes(vector.salt), {
    t: vector.parameters.iterations,
    m: vector.parameters.memoryKiB,
    p: vector.parameters.parallelism,
    dkLen: 32,
    key: toBytes(vector.secret),
    personalization: toBytes(vector.associatedData),
    version: vector.version,
  })
  assert.equal(toHex(tag), vector.tag)
})

test('matches OpenSSL on every vector', () => {
  const cases = argon2.cases as any[]
  assert.equal(cases.length, 9)
  for (const vector of cases) {
    assert.equal(toHex(utf8ToBytes(vector.password)), vector.passwordUtf8, vector.name)
    const derived = deriveVaultKey(vector.password, toBytes(vector.salt), vector.parameters)
    assert.equal(toHex(derived.key), vector.key, vector.name)
    assert.equal(derived.key.length, 32, vector.name)
  }
})

test('both spellings of an accented password derive the same key', () => {
  const composed = 'Paßwört'
  const decomposed = 'Paßwört'
  assert.notEqual(composed, decomposed)
  assert.equal(normalizePassword(composed), normalizePassword(decomposed))
  assert.equal(toHex(deriveVaultKey(composed, SALT, CHEAP).key), toHex(deriveVaultKey(decomposed, SALT, CHEAP).key))
})

test('the key changes with the password, the salt and the parameters', () => {
  const base = toHex(deriveVaultKey('password', SALT, CHEAP).key)
  assert.notEqual(base, toHex(deriveVaultKey('passwore', SALT, CHEAP).key))
  assert.notEqual(base, toHex(deriveVaultKey('password ', SALT, CHEAP).key))
  assert.notEqual(base, toHex(deriveVaultKey('password', new Uint8Array(16).fill(6), CHEAP).key))
  assert.notEqual(base, toHex(deriveVaultKey('password', SALT, { ...CHEAP, iterations: 2 }).key))
  assert.notEqual(base, toHex(deriveVaultKey('password', SALT, { ...CHEAP, memoryKiB: 16384 }).key))
  assert.notEqual(base, toHex(deriveVaultKey('password', SALT, { ...CHEAP, parallelism: 2 }).key))
})

test('deriving is deterministic', () => {
  assert.equal(toHex(deriveVaultKey('password', SALT, CHEAP).key), toHex(deriveVaultKey('password', SALT, CHEAP).key))
})

test('rejects an empty password, a non string password and a wrong sized salt', () => {
  assert.throws(() => deriveVaultKey('', SALT, CHEAP), /password must not be empty/)
  assert.throws(() => deriveVaultKey(undefined as never, SALT, CHEAP), /password must be a string/)
  assert.throws(() => deriveVaultKey('password', new Uint8Array(15), CHEAP), /salt must be 16 bytes/)
  assert.throws(() => deriveVaultKey('password', 'salt' as never, CHEAP), /salt must be 16 bytes/)
})

test('out of range parameters are refused before any hashing starts', () => {
  const cases: [VaultParameters, RegExp][] = [
    [{ memoryKiB: 1048576, iterations: 3, parallelism: 1 }, /memoryKiB must be an integer from 8192 to 262144/],
    [{ memoryKiB: 1024, iterations: 3, parallelism: 1 }, /memoryKiB must be an integer from 8192 to 262144/],
    [{ memoryKiB: 65536, iterations: 0, parallelism: 1 }, /iterations must be an integer from 1 to 16/],
    [{ memoryKiB: 65536, iterations: 3, parallelism: 9 }, /parallelism must be an integer from 1 to 4/],
  ]
  for (const [parameters, message] of cases) {
    const started = performance.now()
    assert.throws(() => deriveVaultKey('password', SALT, parameters), message)
    assert.ok(performance.now() - started < 1000)
  }
})

test('createVaultKey uses a fresh random salt and the default parameters', () => {
  const first = createVaultKey('password', CHEAP)
  const second = createVaultKey('password', CHEAP)
  assert.equal(first.salt.length, 16)
  assert.notEqual(toHex(first.salt), toHex(second.salt))
  assert.notEqual(toHex(first.key), toHex(second.key))
  assert.deepEqual(createVaultKey('password', CHEAP).parameters, CHEAP)
  assert.deepEqual(VAULT_PARAMETERS, { memoryKiB: 65536, iterations: 3, parallelism: 1 })
})

test('the returned salt and parameters are copies of the inputs', () => {
  const salt = new Uint8Array(16).fill(1)
  const parameters = { ...CHEAP }
  const derived = deriveVaultKey('password', salt, parameters)
  salt.fill(9)
  derived.parameters.memoryKiB = 1
  assert.notEqual(toHex(derived.salt), toHex(salt))
  assert.equal(parameters.memoryKiB, CHEAP.memoryKiB)
})

test('a vault opens with its password and with no other', async () => {
  const password = 'correct horse battery staple'
  const secret = utf8ToBytes('test test test test test test test test test test test junk')
  const vault = await sealVault(createVaultKey(password, CHEAP), secret)
  assert.equal(toHex(await openVault(vaultKeyFor(password, vault).key, vault)), toHex(secret))
  const wrong = vaultKeyFor('correct horse battery stapl3', vault)
  await assert.rejects(() => openVault(wrong.key, vault), /authentication failed/)
})

test('vaultKeyFor uses the parameters stored in the vault, not the defaults', async () => {
  const parameters: VaultParameters = { memoryKiB: 16384, iterations: 2, parallelism: 2 }
  const vault = await sealVault(createVaultKey('password', parameters), utf8ToBytes('secret'))
  const derived = vaultKeyFor('password', vault)
  assert.deepEqual(derived.parameters, parameters)
  assert.equal(toHex(await openVault(derived.key, vault)), toHex(utf8ToBytes('secret')))
  assert.notEqual(toHex(deriveVaultKey('password', derived.salt, CHEAP).key), toHex(derived.key))
})
