export interface WorkerRequest {
  id: string
  origin: string
  method: string
  params: readonly unknown[]
}

export interface WorkerResponse {
  id: string
  result?: unknown
  error?: { code: number; message: string }
}

export const AUTO_LOCK_DEFAULT_MS = 300_000

export const AUTO_LOCK_MIN_MS = 60_000

export const AUTO_LOCK_MAX_MS = 1_800_000

export async function handle(request: WorkerRequest): Promise<WorkerResponse> {
  void request
  throw new Error('background.handle not implemented')
}

export function lock(): void {
  throw new Error('background.lock not implemented')
}
