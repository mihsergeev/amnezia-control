import { useEffect, useRef, useState, type ReactNode } from 'react'
import { createShareLink, getShareServices, type ShareService } from './api'
import { copyText } from './clipboard'
import { useI18n } from './i18n'
import { Menu } from './Menu'

// список сервисов грузим один раз на вкладку; окно настроек сбрасывает кэш
let cache: Promise<ShareService[]> | null = null

export function resetShareServices() {
  cache = null
}

function loadServices(): Promise<ShareService[]> {
  // сбой не запоминаем: иначе кнопка не появится до перезагрузки страницы
  if (!cache)
    cache = getShareServices().catch(() => {
      cache = null
      return []
    })
  return cache
}

/** Кнопка «Ссылка» для окна конфига: кладет текст в сервис секретов и
 * показывает одноразовую ссылку. Без настроенных сервисов кнопки нет.
 * control - кнопку ставить рядом с «Скопировать», result - под кнопками. */
export function useShareLink(
  text: string,
  target: string,
  groupName = '',
): { control: ReactNode; result: ReactNode } {
  const { t } = useI18n()
  const [services, setServices] = useState<ShareService[]>([])
  const [busy, setBusy] = useState(false)
  const [link, setLink] = useState<{ url: string; days: number; via: string } | null>(null)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const request = useRef(0)

  useEffect(() => {
    let alive = true
    loadServices().then((s) => alive && setServices(s))
    return () => {
      alive = false
    }
  }, [])

  // другой конфиг (формат, вариант) - старая ссылка к нему не относится
  useEffect(() => {
    setLink(null)
    setError(null)
    setCopied(false)
    setBusy(false)
    // Поздний ответ старого конфига не должен показывать и копировать ссылку
    // в новом окне. Инвалидируем и при закрытии окна.
    return () => { request.current += 1 }
  }, [text, target, groupName])

  async function share(svc: ShareService) {
    const seq = ++request.current
    setBusy(true)
    setError(null)
    setLink(null)
    try {
      const r = await createShareLink(svc.id, text, target)
      if (seq !== request.current) return
      setLink({ url: r.url, days: r.ttl_days, via: svc.name })
      const copied = await copyText(r.url)
      if (seq === request.current) setCopied(copied)
    } catch (err) {
      if (seq === request.current) setError(err instanceof Error ? err.message : t('Ошибка'))
    } finally {
      if (seq === request.current) setBusy(false)
    }
  }

  if (services.length === 0) return { control: null, result: null }

  // сервис с именем как у группы сервера - первым (у каждой организации свой)
  const g = groupName.trim().toLowerCase()
  const ordered = [...services].sort(
    (a, b) => Number(b.name.toLowerCase() === g) - Number(a.name.toLowerCase() === g),
  )
  const label = busy ? t('Создаю ссылку…') : t('Ссылка')
  const control =
    ordered.length === 1 ? (
      <button
        className="ghost"
        disabled={busy}
        title={t('Одноразовая ссылка через {name}', { name: ordered[0].name })}
        onClick={() => share(ordered[0])}
      >
        {label}
      </button>
    ) : (
      <Menu
        label={label}
        fixed
        placement="above"
        items={ordered.map((s) => ({ label: s.name, onClick: () => share(s), disabled: busy }))}
      />
    )

  const result = error ? (
    <p className="small err-text">{error}</p>
  ) : link ? (
    <div className="share-link">
      {/* текстом с переносом, а не input: длинная ссылка видна целиком */}
      <div className="share-link-url">{link.url}</div>
      <div className="share-link-row">
        <p className="muted small">
          {t('Ссылка через {name}: откроется один раз, через {n} дн. сгорит сама.', {
            name: link.via,
            n: link.days,
          })}
        </p>
        <button className="ghost" onClick={async () => setCopied(await copyText(link.url))}>
          {copied ? t('Скопировано ✓') : t('Скопировать')}
        </button>
      </div>
    </div>
  ) : null

  return { control, result }
}
