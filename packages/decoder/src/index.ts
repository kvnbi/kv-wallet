export type Hex = `0x${string}`

export type Address = Hex

export type Confidence = 'explained' | 'partial' | 'opaque' | 'forbidden'

export interface BalanceChange {
  asset: Address | 'native'
  delta: bigint
}

export interface ApprovalChange {
  token: Address
  spender: Address
  amount: bigint
  unlimited: boolean
}

export interface Explanation {
  confidence: Confidence
  summary: string
  balanceChanges: BalanceChange[]
  approvalChanges: ApprovalChange[]
  unexplained: string[]
}

export interface CallRequest {
  chainId: number
  from: Address
  to: Address
  value: bigint
  data: Hex
}

export interface SimulationResult {
  succeeded: boolean
  balanceChanges: BalanceChange[]
  approvalChanges: ApprovalChange[]
}

export async function explain(
  request: CallRequest,
  simulation: SimulationResult | null,
): Promise<Explanation> {
  void request
  void simulation
  throw new Error('decoder.explain not implemented')
}

export function isSignable(explanation: Explanation): boolean {
  return explanation.confidence === 'explained' || explanation.confidence === 'partial'
}
