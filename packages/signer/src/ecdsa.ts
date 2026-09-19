import { secp256k1 } from '@noble/curves/secp256k1.js'
import { publicKeyToAddress, type Address } from './address.ts'
import { concatBytes, toBytes, toHex, type Hex } from './bytes.ts'

export interface Signature {
  r: Hex
  s: Hex
  yParity: 0 | 1
}

export function signDigest(privateKey: Uint8Array, digest: Uint8Array): Signature {
  if (digest.length !== 32) throw new Error('expected a 32 byte digest')
  const recovered = secp256k1.sign(digest, privateKey, { prehash: false, lowS: true, format: 'recovered' })
  const id = recovered[0]
  if (id !== 0 && id !== 1) throw new Error('unsupported recovery id')
  return { r: toHex(recovered.subarray(1, 33)), s: toHex(recovered.subarray(33, 65)), yParity: id === 0 ? 0 : 1 }
}

export function recoverAddress(digest: Uint8Array, signature: Signature): Address {
  if (digest.length !== 32) throw new Error('expected a 32 byte digest')
  const recovered = concatBytes(Uint8Array.of(parity(signature.yParity)), component(signature.r), component(signature.s))
  const compressed = secp256k1.recoverPublicKey(recovered, digest, { prehash: false })
  return publicKeyToAddress(secp256k1.Point.fromBytes(compressed).toBytes(false))
}

export function privateKeyToAddress(privateKey: Uint8Array): Address {
  return publicKeyToAddress(secp256k1.getPublicKey(privateKey, false))
}

export function serializeSignature(signature: Signature): Hex {
  return toHex(concatBytes(component(signature.r), component(signature.s), Uint8Array.of(27 + parity(signature.yParity))))
}

export function component(value: Hex): Uint8Array {
  const bytes = toBytes(value)
  if (bytes.length !== 32) throw new Error('expected a 32 byte signature component')
  return bytes
}

export function parity(value: number): 0 | 1 {
  if (value !== 0 && value !== 1) throw new Error('yParity must be 0 or 1')
  return value === 0 ? 0 : 1
}
