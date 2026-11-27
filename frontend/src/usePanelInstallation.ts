import { useEffect, useRef, useState } from 'react'
import { ApiError, getPanelInstallation, startPanelInstallation, type PanelInstallation } from './api'

const ACTIVE_PHASES = ['queued', 'verifying', 'backing_up', 'installing', 'checking', 'rolling_back']

export function isInstallationActive(phase: PanelInstallation['phase']) {
  return ACTIVE_PHASES.includes(phase)
}

export function usePanelInstallation(onUnauthorized: () => void) {
  const [status, setStatus] = useState<PanelInstallation | null>(null)
  const [reachable, setReachable] = useState<boolean | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [revision, setRevision] = useState(0)
  const polling = useRef<AbortController | null>(null)

  useEffect(() => {
    if (submitting) return
    const controller = new AbortController()
    polling.current = controller
    let timer: number

    async function poll() {
      let delay = 2_000
      try {
        const next = await getPanelInstallation(AbortSignal.any([controller.signal, AbortSignal.timeout(8_000)]))
        if (controller.signal.aborted) return
        setStatus(next)
        setReachable(true)
        if (!isInstallationActive(next.phase)) delay = 10_000
      } catch (err) {
        if (controller.signal.aborted) return
        if (err instanceof ApiError && err.status === 401) {
          onUnauthorized()
          return
        }
        setReachable(false)
      }
      timer = window.setTimeout(() => { void poll() }, delay)
    }

    timer = window.setTimeout(() => { void poll() }, 0)
    return () => {
      controller.abort()
      window.clearTimeout(timer)
    }
  }, [onUnauthorized, revision, submitting])

  async function install(version: string, password: string, otp: string) {
    polling.current?.abort()
    setSubmitting(true)
    try {
      const accepted = await startPanelInstallation(version, password, otp, AbortSignal.timeout(15_000))
      setStatus(accepted)
      setReachable(true)
    } catch (err) {
      setReachable(null)
      throw err
    } finally {
      setSubmitting(false)
      setRevision((value) => value + 1)
    }
  }

  function refresh() {
    setReachable(null)
    setRevision((value) => value + 1)
  }

  return { status, reachable, submitting, install, refresh }
}
