import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError, checkPanelUpdate, getPanelUpdateInfo, type PanelUpdateInfo } from './api'

export function usePanelUpdates(authed: boolean, onUnauthorized: () => void) {
  const [info, setInfo] = useState<PanelUpdateInfo | null>(null)
  const [checking, setChecking] = useState(false)
  const [failed, setFailed] = useState(false)
  const request = useRef<AbortController | null>(null)

  const check = useCallback(async (manual = false) => {
    if (!authed || request.current) return
    const controller = new AbortController()
    request.current = controller
    setChecking(true)
    try {
      const next = await (manual ? checkPanelUpdate : getPanelUpdateInfo)(controller.signal)
      if (!controller.signal.aborted) {
        setInfo(next)
        setFailed(false)
      }
    } catch (err) {
      if (controller.signal.aborted) return
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
      else setFailed(true)
    } finally {
      if (!controller.signal.aborted) {
        request.current = null
        setChecking(false)
      }
    }
  }, [authed, onUnauthorized])

  useEffect(() => {
    if (!authed) {
      setInfo(null)
      setChecking(false)
      setFailed(false)
      return
    }
    // React Strict Mode discards the first setup before the scheduled check.
    const initialCheck = window.setTimeout(() => { void check() }, 0)
    return () => {
      window.clearTimeout(initialCheck)
      request.current?.abort()
      request.current = null
    }
  }, [authed, check])

  return { info, checking, failed, check }
}
