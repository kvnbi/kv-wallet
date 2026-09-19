import assert from 'node:assert/strict'
import { test } from 'node:test'
import { toBytes, toHex } from '../src/bytes.ts'
import { derivationPath, deriveNode, derivePrivateKey, withPrivateKey } from '../src/derivation.ts'
import { mnemonicToSeed } from '../src/mnemonic.ts'
import { fixture } from './load.ts'

const bip32 = fixture('bip32.json')

const anvil = fixture('derivation.json')

const seed = mnemonicToSeed(anvil.mnemonic)

test('every BIP-32 vector derives the expected extended key', () => {
  let count = 0
  for (const vector of bip32.vectors) {
    for (const { indices, xprv } of vector.derivations) {
      assert.equal(deriveNode(toBytes(vector.seed), indices).privateExtendedKey, xprv)
      count++
    }
  }
  assert.equal(count, 17)
})

test('the Ethereum path derives the published default accounts', () => {
  for (const { index, path, privateKey } of anvil.accounts) {
    assert.equal(derivationPath(index), path)
    assert.equal(toHex(derivePrivateKey(seed, index)), privateKey)
  }
})

test('indices outside the non hardened range are rejected', () => {
  for (const bad of [-1, 2 ** 31, 2 ** 32, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1, '0']) {
    assert.throws(() => derivePrivateKey(seed, bad as number), /account index must be an integer/)
    assert.throws(() => derivationPath(bad as number), /account index must be an integer/)
  }
  assert.equal(derivationPath(2 ** 31 - 1), "m/44'/60'/0'/0/2147483647")
})

test('the private key is zeroed after use, including when use throws', () => {
  const keys: Uint8Array[] = []
  withPrivateKey(seed, 0, key => {
    keys.push(key)
    assert.equal(toHex(key), anvil.accounts[0].privateKey)
  })
  assert.throws(() => withPrivateKey(seed, 0, key => {
    keys.push(key)
    throw new Error('boom')
  }), /boom/)
  assert.equal(keys.length, 2)
  for (const key of keys) assert.ok(key.every(byte => byte === 0))
})
