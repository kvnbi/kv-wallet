import { parseAddress } from './address.ts'
import { concatBytes, fixedBytes, keccak256, toBytes, toHex, utf8ToBytes, type Hex } from './bytes.ts'

export interface TypedDataField {
  name: string
  type: string
}

export type TypedDataTypes = Readonly<Record<string, readonly TypedDataField[]>>

export interface TypedData {
  types: TypedDataTypes
  primaryType: string
  domain: Readonly<Record<string, unknown>>
  message: Readonly<Record<string, unknown>>
}

const IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/

const ARRAY = /^(.+)\[([1-9][0-9]*)?\]$/

const INTEGER = /^(u?)int([1-9][0-9]{0,2})$/

const FIXED_BYTES = /^bytes([1-9][0-9]?)$/

const WORD = 2n ** 256n

export function hashTypedData(typedData: TypedData): Hex {
  const { types, primaryType, domain, message } = typedData
  validateTypes(types)
  if (!isStruct(types, 'EIP712Domain')) throw new Error('types must include EIP712Domain')
  if (primaryType === 'EIP712Domain' || !isStruct(types, primaryType)) throw new Error('invalid primary type')
  const domainSeparator = hashStruct(types, 'EIP712Domain', domain)
  const messageHash = hashStruct(types, primaryType, message)
  return toHex(keccak256(concatBytes(Uint8Array.of(0x19, 0x01), domainSeparator, messageHash)))
}

export function hashStruct(types: TypedDataTypes, primaryType: string, data: unknown): Uint8Array {
  return keccak256(encodeData(types, primaryType, data))
}

export function encodeData(types: TypedDataTypes, primaryType: string, data: unknown): Uint8Array {
  const record = asRecord(data)
  const values = fields(types, primaryType).map(field => encodeValue(types, field.type, fieldValue(record, field.name)))
  return concatBytes(typeHash(types, primaryType), ...values)
}

export function typeHash(types: TypedDataTypes, primaryType: string): Uint8Array {
  return keccak256(utf8ToBytes(encodeType(types, primaryType)))
}

export function encodeType(types: TypedDataTypes, primaryType: string): string {
  const found = new Set<string>()
  collect(types, primaryType, found)
  found.delete(primaryType)
  return [primaryType, ...[...found].sort()]
    .map(name => `${name}(${fields(types, name).map(field => `${field.type} ${field.name}`).join(',')})`)
    .join('')
}

function validateTypes(types: TypedDataTypes): void {
  if (typeof types !== 'object' || types === null || Array.isArray(types)) throw new Error('types must be an object')
  for (const name of Object.keys(types)) {
    if (!IDENTIFIER.test(name) || isPrimitive(name)) throw new Error(`invalid struct name ${name}`)
    const members = types[name]
    if (!Array.isArray(members)) throw new Error(`fields of ${name} must be an array`)
    const seen = new Set<string>()
    for (const member of members) {
      if (typeof member !== 'object' || member === null) throw new Error(`invalid field in ${name}`)
      if (typeof member.name !== 'string' || !IDENTIFIER.test(member.name) || seen.has(member.name)) {
        throw new Error(`invalid field name in ${name}`)
      }
      seen.add(member.name)
      if (typeof member.type !== 'string' || !isKnown(types, member.type)) throw new Error(`unknown type in ${name}`)
    }
  }
}

function encodeValue(types: TypedDataTypes, type: string, value: unknown): Uint8Array {
  const array = ARRAY.exec(type)
  if (array) {
    if (!Array.isArray(value)) throw new Error(`expected an array for ${type}`)
    const length = array[2]
    if (length !== undefined && value.length !== Number(length)) throw new Error(`expected ${length} elements for ${type}`)
    const element = array[1] ?? ''
    return keccak256(concatBytes(...value.map(item => encodeValue(types, element, item))))
  }
  if (isStruct(types, type)) return hashStruct(types, type, value)
  if (type === 'string') {
    if (typeof value !== 'string') throw new Error('expected a string')
    return keccak256(utf8ToBytes(value))
  }
  if (type === 'bytes') return keccak256(toBytes(value))
  return encodeAtomic(type, value)
}

function encodeAtomic(type: string, value: unknown): Uint8Array {
  if (type === 'address') {
    const out = new Uint8Array(32)
    out.set(parseAddress(value), 12)
    return out
  }
  if (type === 'bool') {
    if (typeof value !== 'boolean') throw new Error('expected a boolean')
    return fixedBytes(value ? 1n : 0n, 32)
  }
  const bytesMatch = FIXED_BYTES.exec(type)
  if (bytesMatch && isFixedBytes(type)) {
    const bytes = toBytes(value)
    if (bytes.length !== Number(bytesMatch[1])) throw new Error(`expected exactly ${bytesMatch[1]} bytes for ${type}`)
    const out = new Uint8Array(32)
    out.set(bytes)
    return out
  }
  const integerMatch = INTEGER.exec(type)
  if (integerMatch && isInteger(type)) {
    const bits = BigInt(integerMatch[2] ?? '0')
    const signed = integerMatch[1] === ''
    const min = signed ? -(2n ** (bits - 1n)) : 0n
    const max = signed ? 2n ** (bits - 1n) : 2n ** bits
    const number = asInteger(value)
    if (number < min || number >= max) throw new Error(`${type} value is out of range`)
    return fixedBytes(number < 0n ? WORD + number : number, 32)
  }
  throw new Error(`unsupported type ${type}`)
}

function asInteger(value: unknown): bigint {
  if (typeof value === 'bigint') return value
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('expected a safe integer')
    return BigInt(value)
  }
  if (typeof value === 'string' && (/^-?[0-9]+$/.test(value) || /^0x[0-9a-fA-F]+$/.test(value))) return BigInt(value)
  throw new Error('expected an integer')
}

function collect(types: TypedDataTypes, type: string, found: Set<string>): void {
  const base = elementType(type)
  if (found.has(base) || !isStruct(types, base)) return
  found.add(base)
  for (const field of fields(types, base)) collect(types, field.type, found)
}

function elementType(type: string): string {
  let current = type
  for (let match = ARRAY.exec(current); match; match = ARRAY.exec(current)) current = match[1] ?? ''
  return current
}

function isKnown(types: TypedDataTypes, type: string): boolean {
  const base = elementType(type)
  return isStruct(types, base) || isPrimitive(base)
}

function isPrimitive(type: string): boolean {
  return type === 'address' || type === 'bool' || type === 'string' || type === 'bytes' || isFixedBytes(type) || isInteger(type)
}

function isFixedBytes(type: string): boolean {
  const match = FIXED_BYTES.exec(type)
  return match !== null && Number(match[1]) <= 32
}

function isInteger(type: string): boolean {
  const match = INTEGER.exec(type)
  if (match === null) return false
  const bits = Number(match[2])
  return bits % 8 === 0 && bits <= 256
}

function isStruct(types: TypedDataTypes, name: string): boolean {
  return Object.hasOwn(types, name)
}

function fields(types: TypedDataTypes, name: string): readonly TypedDataField[] {
  const members = Object.hasOwn(types, name) ? types[name] : undefined
  if (!Array.isArray(members)) throw new Error(`unknown struct ${name}`)
  return members
}

function asRecord(value: unknown): Readonly<Record<string, unknown>> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('expected an object')
  return value as Readonly<Record<string, unknown>>
}

function fieldValue(record: Readonly<Record<string, unknown>>, name: string): unknown {
  const value = Object.hasOwn(record, name) ? record[name] : undefined
  if (value === undefined || value === null) throw new Error(`missing value for ${name}`)
  return value
}
