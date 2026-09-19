import assert from 'node:assert/strict'
import { test } from 'node:test'
import { parseAddress, publicKeyToAddress, toChecksumAddress } from '../src/address.ts'
import { fixture } from './load.ts'

const { addresses } = fixture('eip55.json')

test('checksums match every EIP-55 test case', () => {
  for (const address of addresses) assert.equal(toChecksumAddress(parseAddress(address.toLowerCase())), address)
})

test('parsing accepts any letter case because case never changes the signed bytes', () => {
  const lower = parseAddress('0xdd2a3d9f938e13cd947ec05abc7fe734df8dd826')
  assert.deepEqual(parseAddress('0xDD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826'), lower)
  assert.deepEqual(parseAddress('0xDD2A3D9F938E13CD947EC05ABC7FE734DF8DD826'), lower)
})

test('parsing rejects anything other than 20 bytes of 0x prefixed hex', () => {
  const bad = [`0x${'0'.repeat(39)}`, `0x${'0'.repeat(41)}`, '0'.repeat(40), `0x${'g'.repeat(40)}`, 1, null]
  for (const value of bad) assert.throws(() => parseAddress(value), /expected a 20 byte hex address/)
})

test('public key conversion requires an uncompressed key', () => {
  assert.throws(() => publicKeyToAddress(new Uint8Array(33)), /expected an uncompressed public key/)
  assert.throws(() => publicKeyToAddress(new Uint8Array(65)), /expected an uncompressed public key/)
})
