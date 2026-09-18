export interface BridgeMessage {
  id: string
  method: string
  params: readonly unknown[]
}

export const BRIDGE_CHANNEL = 'kv-wallet'

export function start(): void {
  throw new Error('bridge.start not implemented')
}
