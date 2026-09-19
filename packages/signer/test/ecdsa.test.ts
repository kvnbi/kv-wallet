import assert from 'node:assert/strict'
import { test } from 'node:test'
import { keccak256, toBytes, utf8ToBytes } from '../src/bytes.ts'
import { privateKeyToAddress, recoverAddress, serializeSignature, signDigest } from '../src/ecdsa.ts'
import { fixture } from './load.ts'

const eip155 = fixture('eip155.json')

const { mail } = fixture('eip712.json')

const cow = keccak256(utf8ToBytes(mail.privateKeyPreimage))

const ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n

test('signs the EIP-155 digest to the published r, s and recovery bit', () => {
  assert.deepEqual(signDigest(toBytes(eip155.privateKey), toBytes(eip155.signingHash)), eip155.signature)
})

test('signs the EIP-712 digest to the published r, s and recovery bit', () => {
  assert.deepEqual(signDigest(cow, toBytes(mail.digest)), mail.signature)
})

test('derives the published address from a private key', () => {
  assert.equal(privateKeyToAddress(cow), mail.address)
})

test('recovers the signer from a digest and signature', () => {
  assert.equal(recoverAddress(toBytes(mail.digest), mail.signature), mail.address)
})

test('signatures are deterministic and use low s', () => {
  for (let i = 0; i < 32; i++) {
    const digest = keccak256(Uint8Array.of(i))
    const signature = signDigest(cow, digest)
    assert.deepEqual(signDigest(cow, digest), signature)
    assert.ok(BigInt(signature.s) <= ORDER / 2n)
  }
})

test('serialises as r, s and a v of 27 or 28', () => {
  assert.equal(serializeSignature(mail.signature), `${mail.signature.r}${mail.signature.s.slice(2)}1c`)
})

test('rejects wrong length digests and malformed signatures', () => {
  assert.throws(() => signDigest(cow, new Uint8Array(31)), /expected a 32 byte digest/)
  assert.throws(() => recoverAddress(toBytes(mail.digest), { ...mail.signature, yParity: 2 }), /yParity must be 0 or 1/)
  assert.throws(() => serializeSignature({ ...mail.signature, r: '0x00' }), /expected a 32 byte signature component/)
})
