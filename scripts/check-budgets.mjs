import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { extname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('..', import.meta.url))

const BUDGETS = {
  signerLines: 1500,
  trustedCoreLines: 8000,
  productionDependencies: 25,
  bundleBytes: 2_000_000,
}

const SIGNER_PACKAGE_ALLOWLIST = ['@noble/curves', '@noble/hashes', '@scure/bip32', '@scure/bip39']

const FORBIDDEN_GLOBALS = [
  'fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource', 'navigator', 'importScripts',
  'document', 'window', 'self', 'localStorage', 'sessionStorage', 'indexedDB', 'caches',
  'chrome', 'browser', 'Worker', 'postMessage', 'process', 'require', '__dirname',
]

const SKIP_DIRECTORIES = new Set(['node_modules', 'dist', '.git'])

function walk(directory, extensions) {
  if (!existsSync(directory)) return []
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    if (SKIP_DIRECTORIES.has(entry.name)) return []
    const path = join(directory, entry.name)
    if (entry.isDirectory()) return walk(path, extensions)
    return entry.isFile() && (extensions === null || extensions.includes(extname(path))) ? [path] : []
  })
}

function lineCount(text) {
  if (text.length === 0) return 0
  return text.replace(/\n$/, '').split('\n').length
}

function countLines(packages) {
  return packages
    .flatMap(name => walk(join(ROOT, 'packages', name, 'src'), ['.ts']))
    .reduce((total, path) => total + lineCount(readFileSync(path, 'utf8')), 0)
}

function countProductionDependencies() {
  const lock = JSON.parse(readFileSync(join(ROOT, 'package-lock.json'), 'utf8'))
  return Object.entries(lock.packages)
    .filter(([path, entry]) => path.startsWith('node_modules/') && !entry.link && !entry.dev)
    .length
}

function stripLiterals(source) {
  const interpolations = []
  const withoutTemplates = source.replace(/`(?:\\.|[^`\\])*`/gs, template => {
    for (const [, expression] of template.matchAll(/\$\{([^}]*)\}/g)) interpolations.push(expression)
    return '``'
  })
  const withoutStrings = withoutTemplates
    .replace(/'(?:\\.|[^'\\\n])*'/g, "''")
    .replace(/"(?:\\.|[^"\\\n])*"/g, '""')
  return [withoutStrings, ...interpolations].join('\n')
}

function signerIsolationViolations() {
  const violations = []
  for (const path of walk(join(ROOT, 'packages', 'signer', 'src'), ['.ts'])) {
    const where = relative(ROOT, path)
    const source = readFileSync(path, 'utf8')
    for (const [, specifier] of source.matchAll(/(?:\bfrom|\bimport|\brequire)\s*\(?\s*['"]([^'"]+)['"]/g)) {
      if (specifier.startsWith('./') || specifier.startsWith('../')) continue
      const allowed = SIGNER_PACKAGE_ALLOWLIST.some(name => specifier === name || specifier.startsWith(`${name}/`))
      if (!allowed) violations.push(`${where} imports ${specifier}`)
    }
    const code = stripLiterals(source)
    for (const name of FORBIDDEN_GLOBALS) {
      const bare = new RegExp(`(?<![.\\w$])${name}(?![\\w$:])`)
      const member = new RegExp(`\\.\\s*${name}(?![\\w$])`)
      if (bare.test(code) || member.test(code)) violations.push(`${where} reaches ${name}`)
    }
  }
  return violations
}

function commentViolations() {
  const violations = []
  const files = [...walk(join(ROOT, 'packages'), ['.ts']), ...walk(join(ROOT, 'scripts'), ['.mjs'])]
  for (const path of files) {
    const code = stripLiterals(readFileSync(path, 'utf8'))
    if (/(?:^|[^:])\/\//.test(code) || /\/\*/.test(code)) violations.push(`${relative(ROOT, path)} contains a comment`)
  }
  return violations
}

function dashViolations() {
  const violations = []
  const files = [
    ...walk(join(ROOT, 'packages'), ['.ts', '.json', '.html']),
    ...walk(join(ROOT, 'scripts'), ['.mjs']),
    ...walk(join(ROOT, '.github'), ['.yml']),
    join(ROOT, 'package.json'),
  ]
  for (const path of files) {
    if (!existsSync(path)) continue
    const text = readFileSync(path, 'utf8')
    if (/[\u2014\u2013]/.test(text)) violations.push(`${relative(ROOT, path)} contains an em or en dash`)
  }
  return violations
}

function bundleBytes() {
  const bundle = join(ROOT, 'packages', 'extension', 'dist', 'bundle')
  if (!existsSync(bundle)) return null
  return walk(bundle, null).reduce((total, path) => total + statSync(path).size, 0)
}

const results = []

function record(name, value, limit, formatted) {
  results.push({
    name,
    formatted: formatted ?? String(value),
    limit,
    failed: value !== null && value > limit,
    pending: value === null,
  })
}

record('signer source lines', countLines(['signer']), BUDGETS.signerLines)
record('trusted core source lines', countLines(['signer', 'decoder', 'provider']), BUDGETS.trustedCoreLines)
record('production dependencies', countProductionDependencies(), BUDGETS.productionDependencies)
const bytes = bundleBytes()
record('extension bundle bytes', bytes, BUDGETS.bundleBytes, bytes === null ? 'pending, no bundle yet' : String(bytes))

const violations = [...signerIsolationViolations(), ...commentViolations(), ...dashViolations()]
record('signer network and DOM access', signerIsolationViolations().length, 0)
record('comments in source', commentViolations().length, 0)
record('em and en dashes', dashViolations().length, 0)

const width = Math.max(...results.map(result => result.name.length))
for (const result of results) {
  const status = result.pending ? 'PENDING' : result.failed ? 'FAIL' : 'ok'
  console.log(`  ${result.name.padEnd(width)}  ${result.formatted.padStart(22)}  limit ${String(result.limit).padStart(9)}  ${status}`)
}
for (const violation of violations) console.log(`  violation: ${violation}`)

const failed = results.filter(result => result.failed)
console.log(failed.length === 0 ? '\nall budgets within limits' : `\n${failed.length} budget failures`)
process.exit(failed.length === 0 ? 0 : 1)
