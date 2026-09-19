import { concatBytes, minimalBytes } from './bytes.ts'

export type RlpInput = Uint8Array | readonly RlpInput[]

export function rlpEncode(input: RlpInput): Uint8Array {
  if (input instanceof Uint8Array) {
    if (input.length === 1 && (input[0] ?? 0x80) < 0x80) return input.slice()
    return concatBytes(prefix(input.length, 0x80), input)
  }
  const payload = concatBytes(...input.map(rlpEncode))
  return concatBytes(prefix(payload.length, 0xc0), payload)
}

function prefix(length: number, offset: number): Uint8Array {
  if (length <= 55) return Uint8Array.of(offset + length)
  const size = minimalBytes(BigInt(length))
  return concatBytes(Uint8Array.of(offset + 55 + size.length), size)
}
