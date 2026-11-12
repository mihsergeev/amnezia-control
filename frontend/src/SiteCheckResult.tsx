import type { CascadeRouteHttpResult, SiteCheckScheme } from './api'
import { siteCheckTone, siteTimingValue } from './siteCheckUi'
import { useI18n } from './i18n'

export function SiteCheckResult({ result, pending = false, scheme, detailed = false, compact = false }: {
  result?: CascadeRouteHttpResult
  pending?: boolean
  scheme: SiteCheckScheme
  detailed?: boolean
  compact?: boolean
}) {
  const { t } = useI18n()
  function text() {
    if (!result) return pending ? t('Проверяется…') : t('HTTP не проверен')
    if (result.status === 'response' && Number.isInteger(result.http_status)) return `HTTP ${result.http_status}`
    if (result.status === 'timeout') return t('Таймаут ответа сайта')
    if (result.status === 'node_unreachable') return t('Сервер проверки недоступен по SSH')
    if (result.status === 'not_applicable') return t('Не применимо к подсети')
    if (result.status === 'blocked') return t('Проверка недоступна для этого адреса')
    if (result.status === 'invalid') return t('Неверный адрес для HTTP-проверки')
    if (result.status === 'unavailable') return t('HTTP-проверка недоступна на сервере')
    if (result.status === 'not_checked') return result.reason === 'batch_deadline' ? t('Не проверен: истекло время пакета') : t('HTTP не проверен')
    if (result.reason === 'dns_failed') return t('Не удалось разрешить DNS-имя')
    if (result.reason === 'tls_error') return t('Ошибка TLS')
    if (result.reason === 'connect_error') return t('Не удалось установить TCP-соединение')
    return t('Ошибка HTTP-проверки')
  }
  const tone = !result && !pending ? 'muted' : siteCheckTone(result)
  return <div className="site-check-result">
    <span className={`cascade-route-http cascade-route-http-${tone}`} data-http-status={result?.status || (pending ? 'checking' : 'not_checked')}>{text()}{!compact && <span className="site-check-scheme">{(result?.scheme || scheme).toUpperCase()}</span>}</span>
    {detailed && result && <SiteCheckTimings result={result} />}
  </div>
}

export function SiteCheckTimings({ result }: { result: CascadeRouteHttpResult }) {
  const { t } = useI18n()
  const timings = result.timings_ms
  return <dl className="site-check-timings">
    {([['DNS', timings?.dns], ['TCP', timings?.tcp], ['TLS', timings?.tls], [t('Всего'), timings?.total]] as const).map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{siteTimingValue(value) === null ? '—' : t('{n} мс', { n: siteTimingValue(value)! })}</dd></div>)}
  </dl>
}
