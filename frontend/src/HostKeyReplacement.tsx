import { useEffect, useState } from 'react'
import { api, type Server } from './api'
import { useI18n } from './i18n'
import { keyFileType } from './sshAccess'
import { StepUpModal } from './StepUpModal'
import { useModalLayer } from './useModalDismiss'

type Preview = {
  host: string
  port: number
  previous_fingerprints: string[]
  fingerprint: string
  key_type: string
}

type Props = { server: Server; onClose: () => void; onReplaced: () => void }

export function HostKeyReplacement({ server, onClose, onReplaced }: Props) {
  const { t } = useI18n()
  const [preview, setPreview] = useState<Preview | null>(null)
  const [error, setError] = useState('')
  const [trusted, setTrusted] = useState('')
  const [confirm, setConfirm] = useState(false)
  const path = `/api/servers/${server.id}/host-key/replacement`

  useModalLayer(!confirm, onClose)
  useEffect(() => {
    const controller = new AbortController()
    api<Preview>(`${path}/preview`, { method: 'POST', signal: controller.signal })
      .then((next) => { if (!controller.signal.aborted) setPreview(next) })
      .catch((err: Error) => { if (!controller.signal.aborted) setError(err.message) })
    return () => controller.abort()
  }, [path])

  if (confirm && preview) {
    return <StepUpModal
      text={t('Заменить закрепленный ключ SSH сервера «{name}»', { name: server.name })}
      onCancel={() => setConfirm(false)}
      onSubmit={async (password) => {
        await api<void>(path, { method: 'POST', body: JSON.stringify({
          host: preview.host, port: preview.port, previous_fingerprints: preview.previous_fingerprints,
          fingerprint: trusted.trim(), password,
        }) })
        onReplaced()
      }}
    />
  }

  return (
    <div className="modal-backdrop">
      <form className="card modal" role="dialog" aria-modal="true" aria-labelledby="replace-host-key-title"
        onSubmit={(e) => { e.preventDefault(); if (preview && trusted.trim() === preview.fingerprint) setConfirm(true) }}>
        <h3 id="replace-host-key-title">{t('Заменить ключ SSH')}</h3>
        <p>{server.name} · <span className="mono">{server.host}:{server.ssh_port}</span></p>
        {error && <p className="form-error" role="alert">{error}</p>}
        {!error && !preview && <p role="status">{t('Получаем отпечаток ключа SSH…')}</p>}
        {preview && <>
          <p>{t('Закрепленные отпечатки')}</p>
          {preview.previous_fingerprints.map((fp) => <div className="mono" key={fp}>{fp}</div>)}
          <p>{t('Отпечаток, полученный от сервера')}</p>
          <div className="mono">{preview.fingerprint}</div>
          <p className="muted small">{t('Получите отпечаток через доверенную консоль хостинга и вставьте его сюда.')}</p>
          <p><code>ssh-keygen -lf /etc/ssh/ssh_host_{keyFileType(preview.key_type)}_key.pub</code></p>
          <label>
            {t('Отпечаток из доверенной консоли')}
            <input className="mono" value={trusted} onChange={(e) => setTrusted(e.target.value)} autoComplete="off"
              spellCheck={false} maxLength={128} placeholder="SHA256:…" />
          </label>
        </>}
        <div className="modal-actions">
          <button type="button" className="ghost" onClick={onClose}>{t('Закрыть')}</button>
          <button type="submit" disabled={!preview || trusted.trim() !== preview.fingerprint}>{t('Продолжить')}</button>
        </div>
      </form>
    </div>
  )
}
