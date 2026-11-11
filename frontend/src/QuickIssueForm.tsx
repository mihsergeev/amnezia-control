import { ExpirySelect } from './Expiry'
import { useI18n } from './i18n'

type Props = {
  name: string
  onName: (value: string) => void
  expiry: string | null
  onExpiry: (value: string | null) => void
  group: string
  onGroup: (value: string) => void
  device: string
  onDevice: (value: string) => void
  note?: string
  onNote?: (value: string) => void
  creating: boolean
  metadataOnly?: boolean
  onCreate: () => void
  onCancel: () => void
}

// Один короткий путь выдачи для всех протоколов. Срок и учетные поля не
// обязательны; они не меняют формат экспортируемого VPN-конфига.
export function QuickIssueForm(props: Props) {
  const { t } = useI18n()
  const metadataFields = <>
    <label>
      <span>{t('Клиент / человек')}</span>
      <input autoFocus={props.metadataOnly} disabled={props.creating} maxLength={128} value={props.group}
        placeholder={t('Необязательно')}
        onChange={(event) => props.onGroup(event.target.value)} />
    </label>
    <label>
      <span>{t('Устройство')}</span>
      <input disabled={props.creating} maxLength={128} value={props.device}
        placeholder={t('Например, ноутбук или рабочий компьютер')}
        onChange={(event) => props.onDevice(event.target.value)} />
    </label>
  </>
  return (
    <form className="add-form quick-issue-form" onSubmit={(event) => {
      event.preventDefault()
      props.onCreate()
    }}>
      {props.metadataOnly ? <>
        <h4>{t('Клиент и устройство')} · {props.name}</h4>
        {metadataFields}
      </> : <><label>
        <span>{t('Имя клиента')}</span>
        <input autoFocus required disabled={props.creating}
          placeholder={t('Имя клиента (например, phone-max)')}
          value={props.name} onChange={(event) => props.onName(event.target.value)} />
      </label>
      <span className="muted small">{props.expiry ? t('Срок задан') : t('Бессрочно')}</span>
      <details>
        <summary>{t('Дополнительно')}</summary>
        <div className="quick-issue-fields">
          {metadataFields}
          {props.onNote && <label>
            <span>{t('Заметка')}</span>
            <input disabled={props.creating} value={props.note ?? ''}
              onChange={(event) => props.onNote?.(event.target.value)} />
          </label>}
          <label className="expiry-row">
            <span className="muted small">{t('Срок действия:')}</span>
            <ExpirySelect value={props.expiry} onChange={props.onExpiry} />
          </label>
        </div>
      </details></>}
      <div className="add-form-actions">
        <button type="button" className="ghost" disabled={props.creating} onClick={props.onCancel}>{t('Отмена')}</button>
        <button type="submit" disabled={props.creating || (!props.metadataOnly && !props.name.trim())}>
          {props.metadataOnly ? props.creating ? t('Сохранение…') : t('Сохранить') : props.creating ? t('Создание…') : t('Создать конфиг')}
        </button>
      </div>
    </form>
  )
}
