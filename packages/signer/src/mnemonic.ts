import { generateMnemonic as generate, mnemonicToSeedSync, validateMnemonic as validate } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'

export function normalizeMnemonic(mnemonic: string): string {
  return mnemonic.trim().toLowerCase().split(/\s+/).join(' ')
}

export function generateMnemonic(): string {
  return generate(wordlist, 128)
}

export function validateMnemonic(mnemonic: unknown): boolean {
  return typeof mnemonic === 'string' && validate(normalizeMnemonic(mnemonic), wordlist)
}

export function mnemonicToSeed(mnemonic: string, passphrase = ''): Uint8Array {
  if (!validateMnemonic(mnemonic)) throw new Error('invalid mnemonic')
  return mnemonicToSeedSync(normalizeMnemonic(mnemonic), passphrase)
}

export { wordlist }
