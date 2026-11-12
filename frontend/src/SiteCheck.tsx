import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError, checkServerSites, type Server, type CascadeRouteHttpResult, type SiteCheckScheme } from './api'
import { countryFlag } from './format'
import { useI18n } from './i18n'
import { SiteCheckResult } from './SiteCheckResult'
import { useModalDismiss } from './useModalDismiss'

type Props = { server: Server; onClose: () => void; onUnauthorized: () => void }
export function SiteCheckModal(props: Props) {
  return <SiteCheckEditor key={`${props.server.id}:${props.server.host}:${props.server.ssh_port}:${props.server.ssh_user}`} {...props} />
}
function SiteCheckEditor({ server, onClose, onUnauthorized }: Props) {
  const { t } = useI18n()
  const [destination, setDestination] = useState('')
  const [scheme, setScheme] = useState<SiteCheckScheme>('https')
  const [checking, setChecking] = useState(false)
  const [result, setResult] = useState<CascadeRouteHttpResult | undefined>()
  const [error, setError] = useState('')
  const [limits, setLimits] = useState<{ timeout: number; budget: number } | null>(null)
  const active = useRef<AbortController | null>(null)
  const alive = useRef(true)
  useEffect(() => { alive.current = true; return () => { alive.current = false; active.current?.abort() } }, [])
  const dismiss = useModalDismiss(onClose)
  function clear() {
    active.current?.abort()
    active.current = null
    setChecking(false)
    setResult(undefined)
    setError('')
    setLimits(null)
  }
  async function check(event: FormEvent) {
    event.preventDefault()
    if (active.current || !destination.trim()) return
    const controller = new AbortController()
    active.current = controller
    setChecking(true)
    setError('')
    setResult(undefined)
    setLimits(null)
    try {
      const response = await checkServerSites(server.id, [destination.trim()], scheme, controller.signal)
      if (!alive.current || active.current !== controller || controller.signal.aborted) return
      if (response.source.server_id !== server.id || response.results.length !== 1) {
        setError(t('Контекст HTTP-проверки изменился. Повторите проверку.')); return
      }
      setResult(response.results[0])
      setLimits({ timeout: response.timeout_seconds, budget: response.budget_seconds })
    } catch (err) {
      if (!alive.current || active.current !== controller || controller.signal.aborted) return
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
      setError(err instanceof ApiError && err.status === 429 ? t('HTTP-проверка уже выполняется. Повторите попытку чуть позже.') : t('Не удалось выполнить HTTP-проверку. Повторите попытку.'))
    } finally {
      if (alive.current && active.current === controller) { active.current = null; setChecking(false) }
    }
  }
  return <div className="modal-backdrop cascade-routes-backdrop" onClick={dismiss}>
    <form className="card modal site-check-modal" role="dialog" aria-modal="true" aria-labelledby="site-check-title" onSubmit={check} onClick={(event) => event.stopPropagation()}>
      <div className="clients-head"><h3 id="site-check-title">{t('Проверить сайт')}</h3><button type="button" className="ghost" onClick={onClose}>{t('Закрыть')}</button></div>
      <div className="site-check-body">
        <p className="site-check-source"><span className="server-flag" aria-hidden="true">{countryFlag(server.country || '')}</span>{t('Проверка с сервера: {source}', { source: server.name || server.host })}</p>
        <p className="muted small">{t('Проверяется доступ к сайту из сети сервера. Это не проверка подключения клиента по VPN.')}</p>
        <div className="site-check-inputs"><label>{t('Домен или IPv4')}<input autoFocus value={destination} maxLength={1024} placeholder="example.com" onChange={(event) => { clear(); setDestination(event.target.value) }} autoComplete="off" spellCheck={false} /></label>
          <label>{t('Протокол HTTP-проверки')}<select value={scheme} onChange={(event) => { clear(); setScheme(event.target.value as SiteCheckScheme) }}><option value="https">HTTPS</option><option value="http">HTTP</option></select></label></div>
        <p className="muted small">{t('Введите только домен или IPv4, без пути и порта. Проверяется главная страница; протокол не переключается автоматически.')}</p>
        {(checking || result) && <section className="site-check-output" aria-live="polite" aria-label={t('Результат проверки сайта')}>
          <strong className="mono">{result?.destination || destination.trim()}</strong>
          <SiteCheckResult result={result} pending={checking} scheme={scheme} detailed />
          {limits && <p className="muted small">{t('До {n} с на адрес', { n: limits.timeout })}</p>}
        </section>}
        {error && <p className="err-text small" role="alert">{error}</p>}
      </div>
      <div className="modal-actions"><button type="submit" disabled={checking || !destination.trim()}>{checking ? t('Проверяем…') : t('Проверить сайт')}</button></div>
    </form>
  </div>
}
