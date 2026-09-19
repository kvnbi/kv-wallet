import { keccak256, toBytes, toHex, utf8ToBytes, type Hex } from './bytes.ts'

export type Address = Hex

const ADDRESS = /^0x[0-9a-fA-F]{40}$/

export function parseAddress(value: unknown): Uint8Array {
  if (typeof value !== 'string' || !ADDRESS.test(value)) throw new Error('expected a 20 byte hex address')
  return toBytes(value)
}

export function toChecksumAddress(address: Uint8Array): Address {
  if (address.length !== 20) throw new Error('expected a 20 byte address')
  const lower = toHex(address).slice(2)
  const hash = toHex(keccak256(utf8ToBytes(lower))).slice(2)
  let body = ''
  for (let i = 0; i < 40; i++) {
    const char = lower.charAt(i)
    body += Number.parseInt(hash.charAt(i), 16) >= 8 ? char.toUpperCase() : char
  }
  return `0x${body}`
}

export function publicKeyToAddress(publicKey: Uint8Array): Address {
  if (publicKey.length !== 65 || publicKey[0] !== 0x04) throw new Error('expected an uncompressed public key')
  return toChecksumAddress(keccak256(publicKey.subarray(1)).subarray(12))
}
