import { readFileSync } from 'node:fs'
import type { Transaction } from '../src/transaction.ts'

export function fixture(name: string): any {
  return JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'))
}

export function transaction(raw: any): Transaction {
  const big = (key: string): bigint => BigInt(raw[key])
  if (raw.type === 'legacy') {
    return {
      type: 'legacy',
      chainId: big('chainId'),
      nonce: big('nonce'),
      gasPrice: big('gasPrice'),
      gasLimit: big('gasLimit'),
      to: raw.to,
      value: big('value'),
      data: raw.data,
    }
  }
  return {
    type: 'eip1559',
    chainId: big('chainId'),
    nonce: big('nonce'),
    maxPriorityFeePerGas: big('maxPriorityFeePerGas'),
    maxFeePerGas: big('maxFeePerGas'),
    gasLimit: big('gasLimit'),
    to: raw.to,
    value: big('value'),
    data: raw.data,
    accessList: raw.accessList,
  }
}
