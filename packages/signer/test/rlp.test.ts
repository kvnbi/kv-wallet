import assert from 'node:assert/strict'
import { test } from 'node:test'
import { minimalBytes, toHex, utf8ToBytes } from '../src/bytes.ts'
import { rlpEncode, type RlpInput } from '../src/rlp.ts'
import { fixture } from './load.ts'

const { cases } = fixture('rlp.json')

function input(value: unknown): RlpInput {
  if (Array.isArray(value)) return value.map(input)
  if (typeof value === 'number') return minimalBytes(BigInt(value))
  if (typeof value !== 'string') throw new Error('unexpected rlp test input')
  if (value.startsWith('#')) return minimalBytes(BigInt(value.slice(1)))
  return utf8ToBytes(value)
}

test('the official suite has not been truncated', () => {
  assert.equal(Object.keys(cases).length, 28)
})

for (const [name, { in: value, out }] of Object.entries(cases as Record<string, { in: unknown; out: string }>)) {
  test(`rlp ${name}`, () => assert.equal(toHex(rlpEncode(input(value))), out.toLowerCase()))
}
