import { concatBytes, keccak256, toHex, utf8ToBytes, type Hex } from './bytes.ts'

export function hashPersonalMessage(message: Uint8Array): Hex {
  if (!(message instanceof Uint8Array)) throw new Error('expected message bytes')
  const prefix = utf8ToBytes(`\x19Ethereum Signed Message:\n${message.length}`)
  return toHex(keccak256(concatBytes(prefix, message)))
}
