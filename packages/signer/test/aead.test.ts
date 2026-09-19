import assert from 'node:assert/strict'
import { createCipheriv, randomBytes } from 'node:crypto'
import { test } from 'node:test'
import { decrypt, encrypt } from '../src/aead.ts'
import { toBytes, toHex } from '../src/bytes.ts'
import { fixture } from './load.ts'

const { cases } = fixture('aes-gcm.json')

test('matches every Wycheproof vector for AES-256-GCM with a 96 bit nonce', async () => {
  let accepted = 0
  let rejected = 0
  for (const vector of cases as any[]) {
    const key = toBytes(`0x${vector.key}`)
    const nonce = toBytes(`0x${vector.iv}`)
    const aad = toBytes(`0x${vector.aad}`)
    const sealed = toBytes(`0x${vector.ct}${vector.tag}`)
    const label = `tcId ${vector.tcId} ${vector.comment}`
    if (vector.result === 'valid') {
      assert.equal(toHex(await encrypt(key, nonce, aad, toBytes(`0x${vector.msg}`))), `0x${vector.ct}${vector.tag}`, label)
      assert.equal(toHex(await decrypt(key, nonce, aad, sealed)), `0x${vector.msg}`, label)
      accepted++
    } else {
      await assert.rejects(() => decrypt(key, nonce, aad, sealed), /authentication failed|too short/, label)
      rejected++
    }
  }
  assert.equal(accepted, 39)
  assert.equal(rejected, 27)
})

test('agrees with the node crypto implementation on random inputs', async () => {
  for (let i = 0; i < 24; i++) {
    const key = randomBytes(32)
    const nonce = randomBytes(12)
    const aad = randomBytes(i)
    const message = randomBytes(i * 7)
    const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 })
    cipher.setAAD(aad, { plaintextLength: message.length })
    const expected = Buffer.concat([cipher.update(message), cipher.final(), cipher.getAuthTag()])
    const actual = await encrypt(new Uint8Array(key), new Uint8Array(nonce), new Uint8Array(aad), new Uint8Array(message))
    assert.equal(toHex(actual), `0x${expected.toString('hex')}`)
  }
})

test('associated data is authenticated', async () => {
  const key = new Uint8Array(32).fill(3)
  const nonce = new Uint8Array(12).fill(4)
  const sealed = await encrypt(key, nonce, utf8('header'), utf8('secret'))
  assert.equal(toHex(await decrypt(key, nonce, utf8('header'), sealed)), toHex(utf8('secret')))
  await assert.rejects(() => decrypt(key, nonce, utf8('headen'), sealed), /authentication failed/)
})

test('rejects wrong sized keys and nonces and truncated ciphertext', async () => {
  const key = new Uint8Array(32)
  const nonce = new Uint8Array(12)
  const empty = new Uint8Array(0)
  for (const size of [16, 24, 31, 33]) {
    await assert.rejects(() => encrypt(new Uint8Array(size), nonce, empty, empty), /key must be 32 bytes/, `key size ${size}`)
  }
  await assert.rejects(() => encrypt(key, new Uint8Array(11), empty, empty), /nonce must be 12 bytes/)
  await assert.rejects(() => decrypt(key, nonce, empty, new Uint8Array(15)), /too short/)
})

function utf8(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'utf8'))
}
