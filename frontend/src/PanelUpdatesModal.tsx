import { useId } from 'react'
import { PROJECT_URL } from './AboutModal'
import type { PanelUpdateInfo } from './api'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

const LABELS = {
  available: 'Доступно обновление панели.',
  up_to_date: 'Установлена последняя стабильная версия.',
  ahead: 'Установленная версия новее последнего стабильного релиза.',
  unavailable: 'Не удалось проверить обновления.',
  disabled: 'Проверка обновлений отключена в конфигурации панели.',
  unknown: 'Не удалось сравнить установленную версию со стабильным релизом.',
  stale: 'Не удалось обновить сведения о релизе. Показана ранее полученная версия.',
  checking: 'Проверяем обновления…',
}

export function PanelUpdatesModal({ info, version, checking, failed, onCheck, onClose }: {
  info: PanelUpdateInfo | null
  version: string | null
  checking: boolean
  failed: boolean
  onCheck: () => void
  onClose: () => void
}) {
  const { lang, t } = useI18n()
  const title = useId()
  const dismiss = useModalDismiss(onClose)
  const latest = info?.latest_version
  const checkedAt = info?.checked_at
  const timestamp = checkedAt ? Date.parse(checkedAt) : NaN
  const expectedUrl = latest && /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/.test(latest)
    ? `${PROJECT_URL}/releases/tag/${latest}`
    : null
  const releaseUrl = expectedUrl === info?.release_url ? expectedUrl : null

  let status: keyof typeof LABELS = info?.status ?? 'unavailable'
  if (failed) status = latest ? 'stale' : 'unavailable'
  if (info?.stale) status = 'stale'
  if (checking) status = 'checking'

  return (
    <div className="modal-backdrop" onClick={dismiss}>
      <section className="card modal panel-updates-modal" role="dialog" aria-modal="true" aria-labelledby={title}>
        <div className="clients-head">
          <h3 id={title}>{t('Обновления')}</h3>
          <button className="ghost" onClick={onClose}>{t('Закрыть')}</button>
        </div>
        <dl className="panel-update-details">
          <dt>{t('Установленная версия')}</dt>
          <dd><code>{info?.current_version || version || '—'}</code></dd>
          <dt>{t('Последняя стабильная версия')}</dt>
          <dd><code>{latest || '—'}</code></dd>
          <dt>{t('Последняя проверка')}</dt>
          <dd>{Number.isFinite(timestamp)
            ? <time dateTime={checkedAt ?? undefined}>{new Intl.DateTimeFormat(lang, { dateStyle: 'medium', timeStyle: 'short' }).format(timestamp)}</time>
            : '—'}</dd>
        </dl>
        <p className="muted" role="status">{t(LABELS[status] ?? LABELS.unavailable)}</p>
        <div className="modal-actions">
          {releaseUrl && <a href={releaseUrl} target="_blank" rel="noopener noreferrer">{t('Открыть релиз')}</a>}
          <button className="primary" onClick={onCheck} disabled={checking || info?.status === 'disabled'}>{t('Проверить')}</button>
        </div>
      </section>
    </div>
  )
}
