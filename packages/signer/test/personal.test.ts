import assert from 'node:assert/strict'
import { test } from 'node:test'
import { toBytes } from '../src/bytes.ts'
import { hashPersonalMessage } from '../src/personal.ts'
import { fixture } from './load.ts'

const { cases, characterLengthHash } = fixture('eip191.json')

for (const { name, message, hash } of cases) {
  test(`personal message ${name}`, () => assert.equal(hashPersonalMessage(toBytes(message)), hash))
}

test('the length prefix counts bytes, not characters', () => {
  const multibyte = (cases as { name: string; message: string }[]).find(c => c.name.startsWith('multibyte'))
  assert.ok(multibyte)
  assert.equal(toBytes(multibyte.message).length, 6)
  assert.notEqual(hashPersonalMessage(toBytes(multibyte.message)), characterLengthHash)
})

test('rejects a string where bytes are required', () => {
  assert.throws(() => hashPersonalMessage('Hello World' as never), /expected message bytes/)
})
