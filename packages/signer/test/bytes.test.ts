import assert from 'node:assert/strict'
import { test } from 'node:test'
import { fixedBytes, keccak256, minimalBytes, toBigInt, toBytes, toHex } from '../src/bytes.ts'
import { fixture } from './load.ts'

const vectors = fixture('keccak.json')

test('keccak256 matches independently computed outputs', () => {
  for (const { input, output } of vectors.cases) assert.equal(toHex(keccak256(toBytes(input))), output)
})

test('keccak256 is Keccak and not FIPS SHA3', () => {
  assert.notEqual(toHex(keccak256(new Uint8Array(0))), vectors.sha3_256Empty)
})

test('hex parsing rejects malformed input', () => {
  for (const bad of ['ab', '0xabc', '0xzz', '0X00', ' 0x00', 12, null, undefined]) {
    assert.throws(() => toBytes(bad), /expected 0x prefixed hex/)
  }
})

test('hex parsing accepts empty input and either letter case', () => {
  assert.deepEqual(toBytes('0x'), new Uint8Array(0))
  assert.deepEqual(toBytes('0xAbCd'), Uint8Array.of(0xab, 0xcd))
})

test('integers encode minimally and at fixed width', () => {
  assert.deepEqual(minimalBytes(0n), new Uint8Array(0))
  assert.deepEqual(minimalBytes(255n), Uint8Array.of(0xff))
  assert.deepEqual(minimalBytes(256n), Uint8Array.of(0x01, 0x00))
  assert.throws(() => minimalBytes(-1n), /non negative/)
  assert.deepEqual(fixedBytes(1n, 4), Uint8Array.of(0, 0, 0, 1))
  assert.throws(() => fixedBytes(256n, 1), /does not fit in 1 bytes/)
  assert.equal(toBigInt(new Uint8Array(0)), 0n)
  assert.equal(toBigInt(Uint8Array.of(0x01, 0x00)), 256n)
})
