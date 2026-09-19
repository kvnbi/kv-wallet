import { keccak_256 } from '@noble/hashes/sha3.js'
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js'

export type Hex = `0x${string}`

const HEX = /^0x(?:[0-9a-fA-F]{2})*$/

export function isHex(value: unknown): value is Hex {
  return typeof value === 'string' && HEX.test(value)
}

export function toBytes(value: unknown): Uint8Array {
  if (!isHex(value)) throw new Error('expected 0x prefixed hex with an even number of digits')
  return hexToBytes(value.slice(2))
}

export function toHex(bytes: Uint8Array): Hex {
  return `0x${bytesToHex(bytes)}`
}

export function toBigInt(bytes: Uint8Array): bigint {
  return bytes.length === 0 ? 0n : BigInt(toHex(bytes))
}

export function minimalBytes(value: bigint): Uint8Array {
  if (value < 0n) throw new Error('expected a non negative integer')
  if (value === 0n) return new Uint8Array(0)
  const hex = value.toString(16)
  return hexToBytes(hex.length % 2 === 0 ? hex : `0${hex}`)
}

export function fixedBytes(value: bigint, length: number): Uint8Array {
  const bytes = minimalBytes(value)
  if (bytes.length > length) throw new Error(`integer does not fit in ${length} bytes`)
  const out = new Uint8Array(length)
  out.set(bytes, length - bytes.length)
  return out
}

export function keccak256(data: Uint8Array): Uint8Array {
  return keccak_256(data)
}

export { concatBytes, utf8ToBytes }
