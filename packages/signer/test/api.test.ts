import assert from 'node:assert/strict'
import { test } from 'node:test'
import { toBytes, utf8ToBytes } from '../src/bytes.ts'
import { recoverAddress, signDigest } from '../src/ecdsa.ts'
import * as signer from '../src/index.ts'
import { serializeTransaction } from '../src/transaction.ts'
import { fixture, transaction } from './load.ts'

const anvil = fixture('derivation.json')

const { mail } = fixture('eip712.json')

const mainnet = fixture('transactions.json')

const seed = signer.mnemonicToSeed(anvil.mnemonic)

const tx = transaction((mainnet.cases as any[]).find(c => c.transaction.type === 'eip1559').transaction)

test('the public surface is exactly the reviewed set, with no way to sign a raw digest', () => {
  assert.deepEqual(Object.keys(signer).sort(), [
    'VAULT_PARAMETERS',
    'createVaultKey',
    'createVaultSalt',
    'derivationPath',
    'deriveAddress',
    'deriveVaultKey',
    'generateMnemonic',
    'hashPersonalMessage',
    'hashTypedData',
    'mnemonicToSeed',
    'openVault',
    'readVaultHeader',
    'sealVault',
    'serializeSignature',
    'signPersonalMessage',
    'signTransaction',
    'signTypedData',
    'transactionSigningHash',
    'validateMnemonic',
    'vaultKeyFor',
  ])
})

test('derives the published default addresses from the phrase end to end', () => {
  for (const { index, address } of anvil.accounts) assert.equal(signer.deriveAddress(seed, index), address)
})

test('signTransaction signs with the key at the requested index', () => {
  const digest = toBytes(signer.transactionSigningHash(tx))
  for (const { index, privateKey, address } of anvil.accounts) {
    const signature = signDigest(toBytes(privateKey), digest)
    assert.equal(signer.signTransaction(seed, index, tx), serializeTransaction(tx, signature))
    assert.equal(recoverAddress(digest, signature), address)
  }
})

test('typed data and personal message signatures recover to the signing account', () => {
  const typed = signer.signTypedData(seed, 1, mail.typedData)
  assert.equal(recoverAddress(toBytes(signer.hashTypedData(mail.typedData)), typed), anvil.accounts[1].address)
  const message = utf8ToBytes('KV Wallet')
  const personal = signer.signPersonalMessage(seed, 0, message)
  assert.equal(recoverAddress(toBytes(signer.hashPersonalMessage(message)), personal), anvil.accounts[0].address)
})

test('malformed requests fail before any key is derived', () => {
  const unusable = new Uint8Array(0)
  assert.throws(() => signer.signTypedData(unusable, 0, { ...mail.typedData, primaryType: 'Missing' }), /invalid primary type/)
  assert.throws(() => signer.signTransaction(unusable, 0, { ...tx, chainId: 0n }), /chainId/)
  assert.throws(() => signer.signPersonalMessage(unusable, 0, 'text' as never), /expected message bytes/)
})
