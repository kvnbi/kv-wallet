export type Hex = `0x${string}`

export type Address = Hex

export interface SigningRequest {
  chainId: number
  derivationPath: string
  digest: Hex
}

export interface Signature {
  r: Hex
  s: Hex
  yParity: 0 | 1
}

export interface VaultParameters {
  memoryKiB: number
  iterations: number
  parallelism: number
}

export const VAULT_PARAMETERS: VaultParameters = {
  memoryKiB: 65536,
  iterations: 3,
  parallelism: 1,
}

export const MAX_FEE_BASIS_POINTS = 50

export async function sign(request: SigningRequest): Promise<Signature> {
  void request
  throw new Error('signer.sign not implemented')
}

export async function deriveAddress(derivationPath: string): Promise<Address> {
  void derivationPath
  throw new Error('signer.deriveAddress not implemented')
}
