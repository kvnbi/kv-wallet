import { HDKey } from '@scure/bip32'

const HARDENED = 0x80000000

const ETHEREUM: readonly number[] = [44 + HARDENED, 60 + HARDENED, HARDENED, 0]

export function derivationPath(index: number): string {
  assertIndex(index)
  return `m/44'/60'/0'/0/${index}`
}

export function deriveNode(seed: Uint8Array, path: readonly number[]): HDKey {
  let node = HDKey.fromMasterSeed(seed)
  for (const index of path) {
    const child = node.deriveChild(index)
    node.wipePrivateData()
    node = child
  }
  return node
}

export function derivePrivateKey(seed: Uint8Array, index: number): Uint8Array {
  assertIndex(index)
  const node = deriveNode(seed, [...ETHEREUM, index])
  const key = node.privateKey
  node.wipePrivateData()
  if (!key) throw new Error('derivation produced no private key')
  return key
}

export function withPrivateKey<T>(seed: Uint8Array, index: number, use: (privateKey: Uint8Array) => T): T {
  const key = derivePrivateKey(seed, index)
  try {
    return use(key)
  } finally {
    key.fill(0)
  }
}

function assertIndex(index: number): void {
  if (!Number.isSafeInteger(index) || index < 0 || index >= HARDENED) {
    throw new Error('account index must be an integer from 0 to 2147483647')
  }
}
