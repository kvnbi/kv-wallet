export interface AesGcmParams {
  name: 'AES-GCM'
  iv: Uint8Array
  tagLength: number
  additionalData: Uint8Array
}

export interface AesKey {
  readonly type: string
}

export interface SubtleLike {
  importKey(
    format: 'raw',
    keyData: Uint8Array,
    algorithm: { name: 'AES-GCM' },
    extractable: boolean,
    usages: readonly string[],
  ): Promise<AesKey>
  encrypt(algorithm: AesGcmParams, key: AesKey, data: Uint8Array): Promise<ArrayBuffer>
  decrypt(algorithm: AesGcmParams, key: AesKey, data: Uint8Array): Promise<ArrayBuffer>
}

export function subtle(): SubtleLike {
  const provider = (globalThis as unknown as { crypto?: { subtle?: SubtleLike } }).crypto
  if (!provider?.subtle) throw new Error('WebCrypto is not available')
  return provider.subtle
}
