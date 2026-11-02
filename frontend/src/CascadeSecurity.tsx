import type { CascadeEncryption } from './api'
import { cascadeSecurityState } from './cascadeUi'
import { useI18n } from './i18n'

export function CascadeSecurity({ encrypted, encryption }: { encrypted?: boolean | null; encryption?: CascadeEncryption }) {
  const { t } = useI18n()
  const state = cascadeSecurityState({ encrypted, encryption })
  return <span className={`cas-security cas-security-${state}`} title={t('По последней проверке сервера')}>
    {state === 'confirmed' ? t('Шифрование канала подтверждено')
      : state === 'plain' ? t('Межсерверный канал без шифрования')
        : t('Шифрование пока не подтверждено')}
  </span>
}
