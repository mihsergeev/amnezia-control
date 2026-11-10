import { useEffect, useRef, useState } from 'react'
import { ApiError, previewCascadeEntryRecovery, recoverCascadeEntry, type CascadeEntryRecovery, type Server } from './api'
import { cascadeTransportLabel } from './cascadeUi'
import { useI18n } from './i18n'
import { useModalDismiss } from './useModalDismiss'

export function CascadeRecoveryModal({ entry, onClose, onRecovered, onUnauthorized }: {
  entry: Server
  onClose: () => void
  onRecovered: (result: CascadeEntryRecovery) => void
  onUnauthorized: () => void
}) {
  const { t } = useI18n()
  const [preview, setPreview] = useState<CascadeEntryRecovery | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const applying = useRef(false)
  const unauthorized = useRef(onUnauthorized)
  useEffect(() => { unauthorized.current = onUnauthorized }, [onUnauthorized])
  useModalDismiss(() => { if (!applying.current) onClose() })

  useEffect(() => {
    const controller = new AbortController()
    void previewCascadeEntryRecovery(entry.id, controller.signal).then(setPreview).catch((err: unknown) => {
      if (controller.signal.aborted) return
      if (err instanceof ApiError && err.status === 401) unauthorized.current()
      else setError(err instanceof Error ? err.message : 'Ошибка')
    })
    return () => controller.abort()
  }, [entry.id])

  async function recover() {
    if (!preview || applying.current) return
    applying.current = true
    setBusy(true)
    try {
      onRecovered(await recoverCascadeEntry(entry.id, preview.token))
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) onUnauthorized()
      else {
        setPreview(null)
        setError(err instanceof Error ? err.message : 'Ошибка')
      }
    } finally {
      applying.current = false
      setBusy(false)
    }
  }

  return <div className="modal-backdrop">
    <div className="card modal" role="dialog" aria-modal="true" aria-labelledby="cascade-recovery-title">
      <h3 id="cascade-recovery-title">{t('Восстановление входа каскада')}</h3>
      <p><strong>{entry.name}</strong>{preview && <> · {cascadeTransportLabel(preview.transport)}</>}</p>
      {!preview && !error && <p className="muted small" role="status">{t('Проверяем шлюз на входе…')}</p>}
      {preview && <>
        <p>{t('Панель снимет старый шлюз только на входе. VPN-клиенты и их конфигурации сохранятся.')}</p>
        <p className="muted small">{t('До установки нового каскада трафик клиентов может идти напрямую через вход.')}</p>
        <p className="muted small">{t(preview.resume
          ? 'Затем можно повторить установку на уже выбранный выход.'
          : 'Затем мастер предложит выбрать новый выход.')}</p>
      </>}
      {error && <p className="small err-text" role="alert">{t(error)}</p>}
      <div className="modal-actions">
        <button className="ghost" disabled={busy} onClick={onClose}>{t('Закрыть')}</button>
        {preview && <button disabled={busy} onClick={() => void recover()}>
          {t(busy ? 'Снимаем шлюз…' : 'Снять старый шлюз')}
        </button>}
      </div>
    </div>
  </div>
}
