import { deriveVaultKey } from '../packages/signer/src/kdf.ts'
import { VAULT_PARAMETERS } from '../packages/signer/src/vault.ts'

const TARGET_MIN = 500
const TARGET_MAX = 1000
const RUNS = 5
const PASSWORD = 'correct horse battery staple'
const SALT = new Uint8Array(16).fill(1)

function median(values) {
  const sorted = [...values].sort((a, b) => a - b)
  const middle = Math.floor(sorted.length / 2)
  return sorted.length % 2 === 0 ? (sorted[middle - 1] + sorted[middle]) / 2 : sorted[middle]
}

function measure(parameters) {
  deriveVaultKey(PASSWORD, SALT, parameters)
  const samples = []
  for (let i = 0; i < RUNS; i++) {
    const started = performance.now()
    deriveVaultKey(PASSWORD, SALT, parameters)
    samples.push(performance.now() - started)
  }
  return median(samples)
}

const candidates = [
  { memoryKiB: 19456, iterations: 2, parallelism: 1 },
  { memoryKiB: 32768, iterations: 2, parallelism: 1 },
  { memoryKiB: 32768, iterations: 3, parallelism: 1 },
  { memoryKiB: 65536, iterations: 2, parallelism: 1 },
  { memoryKiB: 65536, iterations: 3, parallelism: 1 },
  { memoryKiB: 131072, iterations: 3, parallelism: 1 },
  { memoryKiB: 262144, iterations: 3, parallelism: 1 },
]

console.log(`node ${process.version} on ${process.platform} ${process.arch}`)
console.log(`target ${TARGET_MIN} to ${TARGET_MAX} ms on a mid range 2023 laptop, median of ${RUNS} runs\n`)
console.log('  memory      passes    median    verdict')
for (const parameters of candidates) {
  const ms = measure(parameters)
  const configured = parameters.memoryKiB === VAULT_PARAMETERS.memoryKiB
    && parameters.iterations === VAULT_PARAMETERS.iterations
    && parameters.parallelism === VAULT_PARAMETERS.parallelism
  const verdict = ms < TARGET_MIN ? 'below target on this machine' : ms > TARGET_MAX ? 'above target' : 'within target'
  const memory = `${String(parameters.memoryKiB / 1024).padStart(4)} MiB`
  console.log(`  ${memory}  ${String(parameters.iterations).padStart(6)}  ${`${ms.toFixed(0)} ms`.padStart(8)}    ${verdict}${configured ? '   <- configured' : ''}`)
}
