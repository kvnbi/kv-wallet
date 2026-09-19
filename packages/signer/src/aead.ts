import { subtle, type AesGcmParams, type AesKey } from './webcrypto.ts'

export const KEY_LENGTH = 32

export const NONCE_LENGTH = 12

export const TAG_LENGTH = 16

export async function encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  additionalData: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const handle = await importKey(key, nonce)
  return new Uint8Array(await subtle().encrypt(params(nonce, additionalData), handle, plaintext))
}

export async function decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  additionalData: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  if (ciphertext.length < TAG_LENGTH) throw new Error('ciphertext is too short to hold an authentication tag')
  const handle = await importKey(key, nonce)
  try {
    return new Uint8Array(await subtle().decrypt(params(nonce, additionalData), handle, ciphertext))
  } catch {
    throw new Error('authentication failed')
  }
}

async function importKey(key: Uint8Array, nonce: Uint8Array): Promise<AesKey> {
  if (!(key instanceof Uint8Array) || key.length !== KEY_LENGTH) throw new Error('key must be 32 bytes')
  if (!(nonce instanceof Uint8Array) || nonce.length !== NONCE_LENGTH) throw new Error('nonce must be 12 bytes')
  return subtle().importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

function params(nonce: Uint8Array, additionalData: Uint8Array): AesGcmParams {
  return { name: 'AES-GCM', iv: nonce, tagLength: TAG_LENGTH * 8, additionalData }
}
