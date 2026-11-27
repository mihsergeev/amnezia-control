const TOKEN_KEY = 'acontrol_token'
// Этот маркер сообщает о cookie HttpOnly. Сам токен запомненного входа живёт только в памяти вкладки.
const REMEMBERED_KEY = 'acontrol_remembered_session'
const SESSION_LOCK = 'acontrol-auth-session'
const RETRY_DELAY = 15_000

export const SESSION_HEADER = { 'X-Acontrol-Session': '1' }

type Claims = { sid?: string; exp?: number; iat?: number }

let rememberedToken: { token: string; id: string; refreshAt: number } | null = null
let refreshInFlight: Promise<string | null> | null = null
let lockQueue = Promise.resolve()
let refreshTimer: ReturnType<typeof setTimeout> | undefined
let generation = 0
const sessionEnded = new Set<() => void>()

function claims(token: string): Claims {
  try {
    const payload = token.split('.')[1].replaceAll('-', '+').replaceAll('_', '/')
    return JSON.parse(atob(payload)) as Claims
  } catch {
    return {}
  }
}

export function canRememberLogin(): boolean {
  return location.protocol === 'https:'
}

function rememberedId(): string | null {
  return canRememberLogin() ? localStorage.getItem(REMEMBERED_KEY) : null
}

export function hasRememberedLogin(): boolean {
  return rememberedId() !== null
}

export function getToken(): string | null {
  const id = rememberedId()
  if (id) return rememberedToken?.id === id ? rememberedToken.token : null
  return localStorage.getItem(TOKEN_KEY)
}

export function getSessionGeneration(): string {
  return `${generation}:${rememberedId() ?? ''}`
}

function refreshWhenVisible() {
  if (!document.hidden && rememberedToken && hasRememberedLogin()) {
    void refreshSession().catch(() => {
      if (rememberedToken && hasRememberedLogin()) scheduleRefresh(RETRY_DELAY)
    })
  }
}

function scheduleRefresh(delay: number) {
  clearTimeout(refreshTimer)
  refreshTimer = setTimeout(refreshWhenVisible, delay)
}

function storeRememberedToken(token: string, id: string, payload: Claims) {
  const expires = payload.exp ?? 0
  const lead = Math.min(30, Math.max(1, (expires - (payload.iat ?? expires)) / 5))
  const refreshAt = Number.isFinite(expires) && expires > 0
    ? (expires - lead) * 1000
    : Infinity
  rememberedToken = { token, id, refreshAt }
  if (Number.isFinite(refreshAt)) scheduleRefresh(Math.max(1_000, refreshAt - Date.now()))
}

function resetRememberedToken() {
  generation += 1
  rememberedToken = null
  clearTimeout(refreshTimer)
}

export function setToken(token: string | null) {
  resetRememberedToken()
  const payload = token ? claims(token) : {}
  if (token && typeof payload.sid === 'string' && payload.sid && canRememberLogin()) {
    storeRememberedToken(token, payload.sid, payload)
    localStorage.setItem(REMEMBERED_KEY, payload.sid)
    localStorage.removeItem(TOKEN_KEY)
    return
  }
  if (token) localStorage.setItem(TOKEN_KEY, token)
  else localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(REMEMBERED_KEY)
  if (!token) sessionEnded.forEach((listener) => listener())
}

export function watchSessionEnd(listener: () => void): () => void {
  sessionEnded.add(listener)
  function storageChanged(event: StorageEvent) {
    const current = rememberedId()
    if (event.key === REMEMBERED_KEY && event.oldValue && event.oldValue !== current
      && rememberedToken?.id !== current) {
      resetRememberedToken()
      listener()
    }
  }
  window.addEventListener('storage', storageChanged)
  document.addEventListener('visibilitychange', refreshWhenVisible)
  return () => {
    sessionEnded.delete(listener)
    window.removeEventListener('storage', storageChanged)
    document.removeEventListener('visibilitychange', refreshWhenVisible)
  }
}

export function withSessionLock<T>(operation: () => Promise<T>): Promise<T> {
  if (navigator.locks) return navigator.locks.request(SESSION_LOCK, operation)
  const result = lockQueue.then(operation)
  lockQueue = result.then(() => undefined, () => undefined)
  return result
}

export function waitForSessionRefresh(): Promise<string | null> | null {
  return refreshInFlight
}

export function refreshSession(force = false): Promise<string | null> {
  const id = rememberedId()
  if (!id) return Promise.resolve(getToken())
  if (refreshInFlight) return refreshInFlight
  if (!force && rememberedToken?.id === id && Date.now() < rememberedToken.refreshAt) {
    return Promise.resolve(rememberedToken.token)
  }

  const version = generation
  const sameSession = () => rememberedId() === id && generation === version
  refreshInFlight = withSessionLock(async () => {
    for (const delay of [0, 150, 350, 750]) {
      if (delay) await new Promise((resolve) => setTimeout(resolve, delay))
      if (!sameSession()) return null
      const response = await fetch('/api/auth/refresh', {
        method: 'POST',
        headers: SESSION_HEADER,
        credentials: 'same-origin',
        signal: AbortSignal.timeout(10_000),
      })
      if (!sameSession()) return null
      if (response.status === 409) continue
      if (response.status === 401) {
        setToken(null)
        return null
      }
      if (!response.ok) break
      const { access_token } = await response.json() as { access_token: string }
      if (!sameSession()) return null
      const payload = claims(access_token)
      if (payload.sid !== id) {
        setToken(null)
        return null
      }
      storeRememberedToken(access_token, id, payload)
      return access_token
    }
    throw new Error('Session refresh unavailable')
  }).finally(() => { refreshInFlight = null })
  return refreshInFlight
}
