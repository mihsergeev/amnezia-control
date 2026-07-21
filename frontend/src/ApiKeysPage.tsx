import { useCallback, useEffect, useState } from 'react'
import { ApiError, createApiKey, listApiKeys, revokeApiKey, type ApiKey } from './api'
import { useI18n } from './i18n'

type Props = { onUnauthorized: () => void }

export function ApiKeysPage({ onUnauthorized }: Props) {
  const { t, lang } = useI18n()
  const [items, setItems] = useState<ApiKey[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [name, setName] = useState('')
  const [creating, setCreating] = useState(false)
  // Полный ключ существует только здесь и только до перезагрузки страницы —
  // на бэкенде лежит лишь хэш, повторно показать его невозможно.
  const [fresh, setFresh] = useState<{ name: string; key: string } | null>(null)
  const [copied, setCopied] = useState(false)

  const load = useCallback(async () => {
    try {
      setItems(await listApiKeys())
      setError(null)
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return onUnauthorized()
      setError(t('не удалось загрузить ключи'))
    }
  }, [onUnauthorized, t])

  useEffect(() => {
    void load()
  }, [load])

  async function create() {
    if (!name.trim() || creating) return
    setCreating(true)
    try {
      const created = await createApiKey(name.trim())
      setFresh({ name: created.name, key: created.key })
      setCopied(false)
      setName('')
      await load()
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return onUnauthorized()
      setError(t('не удалось создать ключ'))
    } finally {
      setCreating(false)
    }
  }

  async function revoke(item: ApiKey) {
    if (!confirm(t('Отозвать ключ «{name}»? Интеграция сразу перестанет работать.').replace('{name}', item.name))) {
      return
    }
    try {
      await revokeApiKey(item.id)
      await load()
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return onUnauthorized()
      setError(t('не удалось отозвать ключ'))
    }
  }

  function fmt(iso: string | null) {
    if (!iso) return '—'
    return new Date(iso).toLocaleString(lang === 'en' ? 'en-GB' : 'ru-RU', {
      dateStyle: 'medium',
      timeStyle: 'short',
    })
  }

  return (
    <section>
      <div className="page-head">
        <h2>{t('API-ключи')}</h2>
        <div className="page-head-actions">
          <a className="ghost" href="/api/docs" target="_blank" rel="noreferrer">
            {t('Документация API')}
          </a>
          <button className="ghost" onClick={load}>
            {t('Обновить')}
          </button>
        </div>
      </div>

      <div className="card">
        <p className="muted">
          {t(
            'Ключи нужны для интеграции внешних систем с панелью через /api/v1: выдавать и отзывать клиентов AmneziaWG, забирать конфиги, читать список серверов. Управлять серверами (разворачивать, удалять, брать полный доступ) ключ НЕ может.',
          )}
        </p>
        <p className="muted small">
          {t('Передавайте ключ в заголовке X-API-Key.')}
        </p>
      </div>

      {error && <p className="form-error">{error}</p>}

      {fresh && (
        <div className="card">
          <h3>{t('Ключ создан')}</h3>
          <p className="form-error">
            {t('Скопируйте его сейчас — панель хранит только хэш и показать ключ повторно не сможет.')}
          </p>
          <div className="key-reveal">
            <code className="mono">{fresh.key}</code>
            <button
              onClick={() => {
                void navigator.clipboard.writeText(fresh.key)
                setCopied(true)
              }}
            >
              {copied ? t('Скопировано ✓') : t('Копировать')}
            </button>
          </div>
          <button className="ghost" onClick={() => setFresh(null)}>
            {t('Я сохранил ключ')}
          </button>
        </div>
      )}

      <div className="card">
        <h3>{t('Новый ключ')}</h3>
        <div className="row">
          <input
            value={name}
            maxLength={120}
            placeholder={t('Кому выдан (напр. billing-panel)')}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void create()}
          />
          <button onClick={create} disabled={!name.trim() || creating}>
            {creating ? t('Создаю…') : t('Создать ключ')}
          </button>
        </div>
      </div>

      {items === null ? (
        <p className="muted">{t('загрузка…')}</p>
      ) : items.length === 0 ? (
        <div className="card">
          <p className="muted">{t('Ключей пока нет.')}</p>
        </div>
      ) : (
        <div className="table-card">
          <table>
            <thead>
              <tr>
                <th>{t('Название')}</th>
                <th>{t('Ключ')}</th>
                <th>{t('Создан')}</th>
                <th>{t('Последнее использование')}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((k) => (
                <tr key={k.id} className={k.revoked ? 'row-muted' : undefined}>
                  <td>{k.name}</td>
                  <td className="mono muted">ack_{k.prefix}_…</td>
                  <td className="muted small">{fmt(k.created_at)}</td>
                  <td className="muted small">
                    {k.last_used_at ? fmt(k.last_used_at) : t('не использовался')}
                  </td>
                  <td>
                    {k.revoked ? (
                      <span className="muted small">{t('отозван')}</span>
                    ) : (
                      <button className="ghost danger" onClick={() => revoke(k)}>
                        {t('Отозвать')}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
