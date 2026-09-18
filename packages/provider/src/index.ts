export interface RequestArguments {
  method: string
  params?: readonly unknown[] | object
}

export interface Eip1193Provider {
  request(args: RequestArguments): Promise<unknown>
  on(event: string, listener: (...args: unknown[]) => void): void
  removeListener(event: string, listener: (...args: unknown[]) => void): void
}

export interface Eip6963ProviderInfo {
  uuid: string
  name: string
  icon: string
  rdns: string
}

export interface Eip6963ProviderDetail {
  info: Eip6963ProviderInfo
  provider: Eip1193Provider
}

export const PROVIDER_RDNS = 'app.kvwallet'

export const PROVIDER_NAME = 'KV Wallet'

export const FORBIDDEN_METHODS: readonly string[] = ['eth_sign']

export function createProvider(): Eip1193Provider {
  throw new Error('provider.createProvider not implemented')
}

export function announce(detail: Eip6963ProviderDetail): void {
  void detail
  throw new Error('provider.announce not implemented')
}
