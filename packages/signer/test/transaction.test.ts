import assert from 'node:assert/strict'
import { test } from 'node:test'
import { parseAddress, toChecksumAddress } from '../src/address.ts'
import { keccak256, toBytes, toHex } from '../src/bytes.ts'
import { recoverAddress, signDigest } from '../src/ecdsa.ts'
import {
  serializeTransaction,
  transactionSigningHash,
  transactionSigningPayload,
  type Eip1559Transaction,
  type Transaction,
} from '../src/transaction.ts'
import { fixture, transaction } from './load.ts'

const eip155 = fixture('eip155.json')

const mainnet = fixture('transactions.json')

test('EIP-155 payload, hash, signature and serialisation match the spec', () => {
  const tx = transaction(eip155.transaction)
  assert.equal(toHex(transactionSigningPayload(tx)), eip155.signingPayload)
  assert.equal(transactionSigningHash(tx), eip155.signingHash)
  const signature = signDigest(toBytes(eip155.privateKey), toBytes(eip155.signingHash))
  assert.deepEqual(signature, eip155.signature)
  assert.equal(serializeTransaction(tx, signature), eip155.serialized)
})

for (const vector of mainnet.cases) {
  test(`mainnet ${vector.name}`, () => {
    const tx = transaction(vector.transaction)
    assert.equal(toHex(keccak256(toBytes(serializeTransaction(tx, vector.signature)))), vector.hash)
    const sender = recoverAddress(toBytes(transactionSigningHash(tx)), vector.signature)
    assert.equal(sender, toChecksumAddress(parseAddress(vector.from)))
  })
}

test('the mainnet set still covers the encodings that break naive serialisers', () => {
  const cases: any[] = mainnet.cases
  assert.ok(cases.some(c => c.signature.r.startsWith('0x00') || c.signature.s.startsWith('0x00')))
  assert.ok(cases.some(c => c.transaction.to === null))
  assert.ok(cases.some(c => (c.transaction.accessList ?? []).some((entry: any) => entry.storageKeys.length > 1)))
  assert.ok(cases.some(c => c.transaction.type === 'legacy'))
})

test('rejects transactions that are invalid or unsafe to sign, each by its own guard', () => {
  const legacy = transaction(eip155.transaction)
  const eip1559 = (mainnet.cases as any[]).find(c => c.transaction.type === 'eip1559' && c.transaction.to !== null)
  const base = transaction(eip1559.transaction) as Eip1559Transaction
  const cases: [unknown, RegExp][] = [
    [{ ...legacy, chainId: 0n }, /chainId must be a positive integer/],
    [{ ...legacy, chainId: 2n ** 64n }, /chainId must be a positive integer/],
    [{ ...base, chainId: 0n }, /chainId must be a positive integer/],
    [{ ...base, maxPriorityFeePerGas: base.maxFeePerGas + 1n }, /maxPriorityFeePerGas must not exceed maxFeePerGas/],
    [{ ...base, nonce: 2n ** 64n }, /nonce is out of range/],
    [{ ...base, nonce: 1 }, /nonce is out of range/],
    [{ ...base, gasLimit: 2n ** 64n }, /gasLimit is out of range/],
    [{ ...base, value: -1n }, /value is out of range/],
    [{ ...base, value: 2n ** 256n }, /value is out of range/],
    [{ ...base, to: '0x1234' }, /expected a 20 byte hex address/],
    [{ ...base, data: '0xabc' }, /expected 0x prefixed hex/],
    [{ ...base, accessList: [{ address: base.to, storageKeys: [`0x${'00'.repeat(31)}`] }] }, /storage keys must be 32 bytes/],
    [{ ...base, accessList: [{ address: '0x1234', storageKeys: [] }] }, /expected a 20 byte hex address/],
    [{ ...base, type: 'eip2930' }, /unsupported transaction type/],
    [{ ...base, type: 'eip7702' }, /unsupported transaction type/],
  ]
  for (const [tx, message] of cases) assert.throws(() => transactionSigningHash(tx as Transaction), message)
  assert.throws(() => serializeTransaction(base, { ...mainnet.cases[0].signature, yParity: 2 }), /yParity must be 0 or 1/)
})
