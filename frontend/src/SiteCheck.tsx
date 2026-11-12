import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ApiError, checkServerSites, type Server, type CascadeRouteHttpResult } from './api'
import { countryFlag } from './format'
import { useI18n } from './i18n'
import { SiteCheckResult, SiteCheckTimings } from './SiteCheckResult'
import { MAX_SITE_CHECK_LINES, siteCheckDuration, siteCheckInputRows, siteCheckMarkDuplicates, siteCheckMergeRetry, siteCheckResultKey, siteCheckRetryUrls, type SiteCheckRow } from './siteCheckUi'
import { useModalDismiss } from './useModalDismiss'

type Props = { server: Server; onClose: () => void; onUnauthorized: () => void }
export function SiteCheckModal(props: Props) {
  return <SiteCheckEditor key={`${props.server.id}:${props.server.host}:${props.server.ssh_port}:${props.server.ssh_user}`} {...props} />
}
function SiteCheckEditor({ server, onClose, onUnauthorized }: Props) {
  const { t } = useI18n()
  const [text, setText] = useState('')
  const [rows, setRows] = useState<SiteCheckRow[] | null>(null)
  const [pending, setPending] = useState<Set<number>>(new Set())
  const [checking, setChecking] = useState(false)
  const [error, setError] = useState('')
  const [limits, setLimits] = useState<{ timeout: number; budget: number } | null>(null)
  const active = useRef<AbortController | null>(null)
  const alive = useRef(true)
  const inputs = siteCheckInputRows(text)
  const overLimit = inputs.length > MAX_SITE_CHECK_LINES
  const retryUrls = rows ? siteCheckRetryUrls(rows) : []
  const unique = rows?.filter((row) => row.duplicateOf === undefined) ?? []
  const completed = unique.filter((row) => row.result && row.result.status !== 'not_checked' && !pending.has(row.line)).length
  const duplicates = (rows?.length ?? 0) - unique.length
  useEffect(() => { alive.current = true; return () => { alive.current = false; active.current?.abort() } }, [])
  const dismiss = useModalDismiss(onClose)
  function clear() {
    active.current?.abort()
    active.current = null
    setChecking(false)
    setPending(new Set())
    setRows(null)
    setError('')
    setLimits(null)
  }
  async function check(retry = false) {
    if (active.current || !inputs.length || overLimit) return
    const current = retry && rows ? rows : inputs
    const requested = retry ? retryUrls : current.filter((row) => !row.result).map((row) => row.raw)
    const indices = retry ? [] : current.flatMap((row, index) => !row.result ? [index] : [])
    const pendingLines = new Set(current.filter((row) => retry ? requested.includes(siteCheckResultKey(row.result) || '') : !row.result).map((row) => row.line))
    setError('')
    setRows(current)
    if (!requested.length) { setRows(siteCheckMarkDuplicates(current)); return }
    const controller = new AbortController()
    active.current = controller
    setChecking(true)
    setPending(pendingLines)
    if (!retry) setLimits(null)
    try {
      const response = await checkServerSites(server.id, requested, undefined, controller.signal)
      if (!alive.current || active.current !== controller || controller.signal.aborted) return
      if (response.source.server_id !== server.id || response.source.via != null || response.results.length !== requested.length) {
        setError(t('Контекст HTTP-проверки изменился. Повторите проверку.')); return
      }
      if (retry) setRows(siteCheckMergeRetry(current, requested, response.results))
      else {
        const results = new Map(indices.map((index, position) => [index, response.results[position]]))
        setRows(siteCheckMarkDuplicates(current.map((row, index) => results.has(index) ? { ...row, result: results.get(index) } : row)))
      }
      setLimits({ timeout: response.timeout_seconds, budget: response.budget_seconds })
    } catch (err) {
      if (!alive.current || active.current !== controller || controller.signal.aborted) return
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
      setError(err instanceof ApiError && err.status === 429 ? t('HTTP-проверка уже выполняется. Повторите попытку чуть позже.') : t('Не удалось выполнить HTTP-проверку. Повторите попытку.'))
    } finally {
      if (alive.current && active.current === controller) { active.current = null; setChecking(false); setPending(new Set()) }
    }
  }
  function submit(event: FormEvent) { event.preventDefault(); void check() }
  function rowContent(row: SiteCheckRow) {
    const result = pending.has(row.line) ? undefined : row.result
    const url = siteCheckResultKey(row.result) || row.raw
    const duration = siteCheckDuration(result)
    return <>
      <span className="site-check-line muted">{row.line}</span>
      <span className="site-check-address mono">{url}</span>
      <span className="site-check-row-status">{row.duplicateOf !== undefined
        ? <span className="site-check-duplicate">{t('Повтор строки {n}', { n: row.duplicateOf })}</span>
        : result?.reason === 'input_too_long' ? <span className="err-text">{t('Не больше 1024 символов в строке')}</span>
          : <SiteCheckResult result={result} pending={pending.has(row.line)} scheme={result?.scheme || 'https'} compact />}</span>
      <span className="site-check-duration muted">{duration === null || row.duplicateOf !== undefined ? '—' : t('{n} мс', { n: duration })}</span>
    </>
  }
  function canExpand(result?: CascadeRouteHttpResult) { return !!result && ['response', 'error', 'timeout'].includes(result.status) }
  return <div className="modal-backdrop cascade-routes-backdrop" onClick={dismiss}>
    <form className="card modal site-check-modal" role="dialog" aria-modal="true" aria-labelledby="site-check-title" onSubmit={submit} onClick={(event) => event.stopPropagation()}>
      <div className="clients-head"><h3 id="site-check-title">{t('Проверка сайтов')}</h3><button type="button" className="ghost" onClick={onClose}>{t('Закрыть')}</button></div>
      <p className="site-check-source"><span className="server-flag" aria-hidden="true">{countryFlag(server.country || '')}</span><span>{t('Проверка с сервера: {source}', { source: server.name || server.host })}</span></p>
      <div className="site-check-body">
        <div className="site-check-editor">
          <label htmlFor="site-check-addresses">{t('Адреса сайтов')}<span className="muted small">{inputs.length} / {MAX_SITE_CHECK_LINES}</span></label>
          <textarea id="site-check-addresses" aria-label={t('Адреса сайтов')} autoFocus rows={4} value={text} placeholder={'example.com\nhttp://example.net'} onChange={(event) => { clear(); setText(event.target.value) }} autoComplete="off" spellCheck={false} />
          <p className="muted small">{t('По одному адресу на строку. Без протокола добавим https://. Для HTTP укажите http://.')}</p>
          <p className="muted small">{t('Только домен или IPv4, без пути, порта и параметров. Проверка из сети сервера, без подключения клиента по VPN.')}</p>
          {overLimit && <p className="err-text small" role="alert">{t('Лимит 100 строк. Уменьшите список, адреса не будут обрезаны.')}</p>}
        </div>
        {rows && <section className="site-check-output" aria-label={t('Результат проверки сайта')}>
          <div className="site-check-list-head muted small"><span>{t('Адрес')}</span><span>{t('Результат')}</span><span>{t('Время')}</span></div>
          <div className="site-check-list">{rows.map((row) => row.duplicateOf === undefined && !pending.has(row.line) && canExpand(row.result)
            ? <details className="site-check-row" key={row.line} data-line={row.line}><summary aria-label={t('Подробности строки {n}', { n: row.line })}>{rowContent(row)}</summary><SiteCheckTimings result={row.result!} /></details>
            : <div className="site-check-row" key={row.line} data-line={row.line}><div className="site-check-row-summary">{rowContent(row)}</div></div>)}</div>
        </section>}
        {error && <p className="err-text small" role="alert">{error}</p>}
      </div>
      <div className="site-check-footer">
        <div className="site-check-progress muted small" role="status" aria-live="polite">{rows ? <>
          <span>{checking ? t('Проверка адресов: {n}', { n: unique.filter((row) => pending.has(row.line)).length }) : t('Обработано: {done} из {total}', { done: completed, total: unique.length })}</span>
          {duplicates > 0 && <span>{t('Повторов: {n}', { n: duplicates })}</span>}
          {limits && <span>{t('До {n} с на адрес', { n: limits.timeout })} · {t('До {n} с на пакет', { n: limits.budget })}</span>}
        </> : t('До 100 адресов за одну проверку')}</div>
        <div className="modal-actions">
          <button type="button" className="ghost" disabled={!text && !rows} onClick={() => { clear(); setText('') }}>{t('Очистить')}</button>
          {retryUrls.length > 0 && <button type="button" className="ghost" disabled={checking} onClick={() => { void check(true) }}>{t('Повторить непроверенные ({n})', { n: retryUrls.length })}</button>}
          <button type="submit" disabled={checking || !inputs.length || overLimit}>{checking ? t('Проверяем…') : t('Проверить список')}</button>
        </div>
      </div>
    </form>
  </div>
}
