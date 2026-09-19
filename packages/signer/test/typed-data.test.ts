import assert from 'node:assert/strict'
import { test } from 'node:test'
import { keccak256, toBytes, toHex, utf8ToBytes } from '../src/bytes.ts'
import { serializeSignature, signDigest } from '../src/ecdsa.ts'
import { encodeData, encodeType, hashStruct, hashTypedData, typeHash } from '../src/typed-data.ts'
import { fixture } from './load.ts'

const { mail, arrays } = fixture('eip712.json')

const oracle = fixture('eip712-oracle.json')

function single(type: string, value: unknown): string {
  const types = { EIP712Domain: [], T: [{ name: 'x', type }] }
  return toHex(encodeData(types, 'T', { x: value }).subarray(32))
}

test('reproduces every intermediate value of the EIP-712 reference example', () => {
  const { types, primaryType, domain, message } = mail.typedData
  assert.equal(encodeType(types, primaryType), mail.encodeType)
  assert.equal(toHex(typeHash(types, primaryType)), mail.typeHash)
  assert.equal(toHex(encodeData(types, primaryType, message)), mail.encodeData)
  assert.equal(toHex(hashStruct(types, primaryType, message)), mail.messageHash)
  assert.equal(toHex(hashStruct(types, 'EIP712Domain', domain)), mail.domainSeparator)
  assert.equal(hashTypedData(mail.typedData), mail.digest)
  assert.deepEqual(signDigest(keccak256(utf8ToBytes(mail.privateKeyPreimage)), toBytes(mail.digest)), mail.signature)
})

test('reproduces MetaMask for nested struct arrays and an empty domain', () => {
  const { types, primaryType, message } = arrays.typedData
  assert.equal(encodeType(types, primaryType), arrays.encodeType)
  assert.equal(toHex(encodeData(types, primaryType, message)), arrays.encodeData)
  assert.equal(toHex(hashStruct(types, primaryType, message)), arrays.messageHash)
  const signature = signDigest(toBytes(arrays.privateKey), toBytes(hashTypedData(arrays.typedData)))
  assert.equal(serializeSignature(signature), arrays.serializedSignature)
})

for (const [name, vector] of Object.entries(oracle.cases as Record<string, any>)) {
  test(`agrees with MetaMask and ethers: ${name}`, () => {
    const { types, primaryType, domain, message } = vector.typedData
    assert.equal(encodeType(types, primaryType), vector.encodeType)
    assert.equal(toHex(hashStruct(types, primaryType, message)), vector.messageHash)
    assert.equal(toHex(hashStruct(types, 'EIP712Domain', domain)), vector.domainSeparator)
    assert.equal(hashTypedData(vector.typedData), vector.digest)
  })
}

test('a self referencing struct appears once, as the primary type', () => {
  const { types, primaryType, encodeType: expected } = oracle.recursiveTypeEncoding
  assert.equal(encodeType(types, primaryType), expected)
})

test('the oracle set still covers sorting, array only and transitive dependencies', () => {
  for (const name of ['specSorting', 'arrayOnlyDependency', 'transitiveChain', 'permit2Batch']) assert.ok(oracle.cases[name], name)
})

test('atomic and dynamic values follow the encoding rules in the spec', () => {
  const empty = toHex(keccak256(new Uint8Array(0)))
  assert.equal(single('bool', true), `0x${'00'.repeat(31)}01`)
  assert.equal(single('bool', false), `0x${'00'.repeat(32)}`)
  assert.equal(single('int8', -128), `0x${'ff'.repeat(31)}80`)
  assert.equal(single('int256', -1), `0x${'ff'.repeat(32)}`)
  assert.equal(single('uint256', '0xff'), `0x${'00'.repeat(31)}ff`)
  assert.equal(single('uint256', (2n ** 256n - 1n).toString()), `0x${'ff'.repeat(32)}`)
  assert.equal(single('bytes4', '0xdeadbeef'), `0xdeadbeef${'00'.repeat(28)}`)
  assert.equal(single('address', `0x${'11'.repeat(20)}`), `0x${'00'.repeat(12)}${'11'.repeat(20)}`)
  assert.equal(single('string', ''), empty)
  assert.equal(single('bytes', '0x'), empty)
  assert.equal(single('uint256[]', []), empty)
})

test('rejects typed data that is ambiguous or malformed, each by its own guard', () => {
  const ok = mail.typedData
  const withTypes = (extra: object) => ({ ...ok, types: { ...ok.types, ...extra } })
  const cases: [any, RegExp][] = [
    [{ ...ok, types: { Person: ok.types.Person, Mail: ok.types.Mail } }, /types must include EIP712Domain/],
    [{ ...ok, primaryType: 'Missing' }, /invalid primary type/],
    [{ ...ok, primaryType: 'EIP712Domain', message: ok.domain }, /invalid primary type/],
    [withTypes({ Mail: [{ name: 'from', type: 'Unknown' }] }), /unknown type in Mail/],
    [withTypes({ Mail: [{ name: 'x', type: 'uint' }] }), /unknown type in Mail/],
    [withTypes({ Mail: [{ name: 'x', type: 'uint7' }] }), /unknown type in Mail/],
    [withTypes({ Mail: [{ name: 'x', type: 'bytes33' }] }), /unknown type in Mail/],
    [withTypes({ Mail: [{ name: 'x', type: 'Person[0]' }] }), /unknown type in Mail/],
    [withTypes({ Mail: [{ name: 'a,uint256 b', type: 'string' }] }), /invalid field name in Mail/],
    [withTypes({ Mail: [{ name: 'a', type: 'string' }, { name: 'a', type: 'string' }] }), /invalid field name in Mail/],
    [{ ...ok, message: { ...ok.message, contents: undefined } }, /missing value for contents/],
    [{ ...ok, message: { ...ok.message, contents: null } }, /missing value for contents/],
    [{ ...ok, message: { from: ok.message.from, to: ok.message.to } }, /missing value for contents/],
  ]
  for (const [typedData, message] of cases) assert.throws(() => hashTypedData(typedData), message)
})

test('a struct may not shadow a primitive type name', () => {
  const ok = mail.typedData
  const shadowed = {
    ...ok,
    types: { ...ok.types, address: [{ name: 'x', type: 'uint256' }] },
    message: { ...ok.message, from: { name: 'Cow', wallet: { x: 1 } }, to: { name: 'Bob', wallet: { x: 2 } } },
  }
  assert.throws(() => hashTypedData(shadowed), /invalid struct name address/)
})

test('rejects values outside their declared type', () => {
  const cases: [string, unknown, RegExp][] = [
    ['uint8', 256, /uint8 value is out of range/],
    ['uint8', -1, /uint8 value is out of range/],
    ['int8', 128, /int8 value is out of range/],
    ['int8', -129, /int8 value is out of range/],
    ['uint256', 1.5, /expected a safe integer/],
    ['uint256', 2 ** 53, /expected a safe integer/],
    ['uint256', '1e3', /expected an integer/],
    ['bool', 'true', /expected a boolean/],
    ['bool', 1, /expected a boolean/],
    ['bytes4', '0xdead', /expected exactly 4 bytes for bytes4/],
    ['bytes4', '0xdeadbeef00', /expected exactly 4 bytes for bytes4/],
    ['address', '0x1234', /expected a 20 byte hex address/],
    ['string', 5, /expected a string/],
    ['bytes', 'hello', /expected 0x prefixed hex/],
    ['uint256[2]', [1], /expected 2 elements for uint256\[2\]/],
    ['uint256[]', 'x', /expected an array for uint256\[\]/],
  ]
  for (const [type, value, message] of cases) assert.throws(() => single(type, value), message)
})

test('ignores message properties the type does not declare, as MetaMask does', () => {
  const extra = { ...mail.typedData, message: { ...mail.typedData.message, injected: 'ignored' } }
  assert.equal(hashTypedData(extra), mail.digest)
})
