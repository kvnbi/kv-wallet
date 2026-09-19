import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { test } from 'node:test'
import { toHex } from '../src/bytes.ts'
import { deriveNode } from '../src/derivation.ts'
import { generateMnemonic, mnemonicToSeed, validateMnemonic, wordlist } from '../src/mnemonic.ts'
import { fixture } from './load.ts'

const bip39 = fixture('bip39.json')

const [first] = bip39.cases

test('the wordlist is byte identical to the canonical BIP-39 english list', () => {
  assert.equal(createHash('sha256').update(`${wordlist.join('\n')}\n`).digest('hex'), bip39.wordlistSha256)
})

test('every Trezor vector validates and derives the expected seed and master key', () => {
  assert.equal(bip39.cases.length, 24)
  for (const { mnemonic, seed, xprv } of bip39.cases) {
    assert.equal(validateMnemonic(mnemonic), true)
    const derived = mnemonicToSeed(mnemonic, bip39.passphrase)
    assert.equal(toHex(derived), seed)
    assert.equal(deriveNode(derived, []).privateExtendedKey, xprv)
  }
})

test('the passphrase is case sensitive', () => {
  assert.notEqual(toHex(mnemonicToSeed(first.mnemonic, 'TREZOR')), toHex(mnemonicToSeed(first.mnemonic, 'trezor')))
})

test('whitespace and letter case in the phrase are normalised', () => {
  const messy = `  ${first.mnemonic.toUpperCase().split(' ').join('   ')}\n`
  assert.equal(toHex(mnemonicToSeed(messy, bip39.passphrase)), first.seed)
})

test('a phrase with a bad checksum is rejected rather than deriving a different wallet', () => {
  const bad = Array(12).fill('abandon').join(' ')
  assert.equal(validateMnemonic(bad), false)
  assert.throws(() => mnemonicToSeed(bad), /invalid mnemonic/)
})

test('unknown words, wrong lengths and non strings are rejected', () => {
  const words = first.mnemonic.split(' ')
  assert.equal(validateMnemonic([...words.slice(0, 11), 'notaword'].join(' ')), false)
  assert.equal(validateMnemonic(words.slice(0, 11).join(' ')), false)
  assert.equal(validateMnemonic(''), false)
  assert.equal(validateMnemonic(undefined), false)
})

test('generated phrases are 12 words, validate, and differ', () => {
  const phrase = generateMnemonic()
  assert.equal(phrase.split(' ').length, 12)
  assert.equal(validateMnemonic(phrase), true)
  assert.notEqual(generateMnemonic(), phrase)
})

test('imported phrases of every standard length are accepted', () => {
  const lengths = new Set<number>((bip39.cases as { mnemonic: string }[]).map(c => c.mnemonic.split(' ').length))
  assert.deepEqual([...lengths].sort((a, b) => a - b), [12, 18, 24])
})
