import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import QRCode from 'qrcode'
import {
  api,
  ApiError,
  pauseClient,
  renameClient,
  setClientLimit,
  type AwgClient,
  type AwgState,
  type CreatedClient,
  type Protocol,
  type Server,
  type VersionInfo,
  type DeployProtocol,
  type NativeCreatedClient,
  type NativeClientConfig,
} from './api'
import { copyText } from './clipboard'
import { formatBytes, formatHandshake, isOnline } from './format'
import { Menu } from './Menu'
import { RollbackMenu } from './RollbackMenu'
import { OpenVpnClients } from './OpenVpnClients'
import { XrayClients } from './XrayClients'
import { AmneziaQr } from './AmneziaQr'
import { ExpiryCell, ExpirySelect } from './Expiry'
import { ClientStatsModal } from './ClientStatsModal'
import { BulkRevokeBar, SelectAllCell, SelectCell } from './BulkActions'
import { useSelection } from './useSelection'
import { useShareLink } from './ShareLink'
import { TorrentBadge } from './Torrent'
import { useTorrentHits } from './useTorrentHits'
import { useI18n } from './i18n'
import { useModalDismiss, useModalLayer } from './useModalDismiss'
import { configFilename } from './clientExports'

type Props = {
  server: Server
  protocols: Protocol[]
  onClose: () => void
  onUnauthorized: () => void
  // без него кнопок обновления протокола нет (окно открыто из поиска)
  onRequestUpdate?: (protocol: DeployProtocol) => void
  onRequestUpgrade31?: () => void
  onRequestAdopt?: () => void
  // вкладка, открытая сразу; без нее - первая (самый новый протокол)
  initialProtocol?: Protocol['key']
  // карточка одного клиента (открыт из поиска): показываем только его
  focusClient?: string
}

type SortKey = 'name' | 'handshake' | 'traffic'
type CfgFormat = 'conf' | 'amnezia'
type ConfigView = { name: string; config: string; amnezia: string; native: boolean; filename?: string }

export function ClientsModal({
  server,
  protocols,
  onClose,
  onUnauthorized,
  onRequestUpdate,
  onRequestUpgrade31,
  onRequestAdopt,
  initialProtocol,
  focusClient,
}: Props) {
  const { t } = useI18n()
  const dismiss = useModalDismiss(onClose)
  const [focus, setFocus] = useState<string | null>(focusClient ?? null)
  const [proto, setProto] = useState<Protocol['key']>(
    initialProtocol && protocols.some((p) => p.key === initialProtocol)
      ? initialProtocol
      : (protocols[0]?.key ?? 'awg'),
  )
  // 'awglegacy' — старый AmneziaWG (wg0) рядом с новым; путь /awg-legacy
  // 'awg3' — AmneziaWG 3.0, отдельный контейнер и свой путь /awg3
  const nativeWireguard = proto === 'wireguard'
  const isAwg = proto === 'awg' || proto === 'awglegacy' || proto === 'awg3' || nativeWireguard
  const awgBase =
    proto === 'wireguard' ? 'wireguard' : proto === 'awglegacy' ? 'awg-legacy' : proto === 'awg3' ? 'awg3' : 'awg'
  // ключ протокола для сроков и истории трафика: бэкенд хранит их отдельно для
  // 2.0, 3.1 и Legacy, а раньше сюда всегда уходило 'awg'
  const limitProto: 'awg' | 'awg3' | 'awglegacy' | 'wireguard' =
    proto === 'wireguard' ? 'wireguard' : proto === 'awg3' ? 'awg3' : proto === 'awglegacy' ? 'awglegacy' : 'awg'
  const [state, setState] = useState<AwgState | null>(null)
  const torrentHits = useTorrentHits(server.id)
  const [version, setVersion] = useState<VersionInfo | null>(null)
  // /awg/version падает, если недоступен Docker Hub; откат и пересборка при
  // этом нужны как раз сильнее всего, поэтому блок показываем и без версии
  const [versionFailed, setVersionFailed] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [addOpen, setAddOpen] = useState(false)
  const [newName, setNewName] = useState('')
  const [newNote, setNewNote] = useState('')
  const [newExpiry, setNewExpiry] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [busyKey, setBusyKey] = useState<string | null>(null)

  const [statsFor, setStatsFor] = useState<AwgClient | null>(null)
  const [view, setView] = useState<ConfigView | null>(null)
  // Escape в окне конфига закрывает его, а не все окно клиентов
  useModalLayer(view !== null, () => setView(null))
  // по умолчанию открываем формат «Для приложения AmneziaVPN» (vpn://) — он нужен
  // чаще; .conf вторичен (для WireGuard/AmneziaWG-приложений)
  const [cfgFormat, setCfgFormat] = useState<CfgFormat>('amnezia')
  const [qr, setQr] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const configGeneration = useRef(0)
  useEffect(() => () => { configGeneration.current += 1 }, [])

  const [search, setSearch] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('name')
  const [sortAsc, setSortAsc] = useState(true)

  const [editKey, setEditKey] = useState<string | null>(null)
  const [draft, setDraft] = useState('')
  const escaping = useRef(false)
  // номер последней загрузки: поздний ответ прошлой вкладки (2.0/3.1/Legacy) не
  // должен перетирать текущую, иначе "Отозвать" ушел бы не в тот протокол
  const loadSeq = useRef(0)
  // защита от двойного Enter: флаг creating в состоянии обновляется не сразу,
  // и второй запрос успевал уйти, выдав двум клиентам один IP
  const creatingRef = useRef(false)

  const handleError = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized()
        return
      }
      setError(err instanceof Error ? err.message : t('Неизвестная ошибка'))
    },
    [onUnauthorized, t],
  )

  const load = useCallback(async () => {
    setLoading(true)
    // Сбрасываем состояние ДО запроса: иначе при переключении вкладки протокола
    // (или при неудачном запросе) на экране остаются данные ПРЕДЫДУЩЕГО протокола
    // — вкладка «AmneziaWG 3.0» показывала endpoint, подсеть и клиентов от 2.0
    // вместе с ошибкой «не развёрнут», и выглядело это так, будто 3.0 стоит.
    setState(null)
    const seq = ++loadSeq.current
    try {
      const st = await api<AwgState>(`/api/servers/${server.id}/${awgBase}`)
      if (seq !== loadSeq.current) return
      setState(st)
      setError(null)
    } catch (err) {
      if (seq !== loadSeq.current) return
      handleError(err)
    } finally {
      if (seq === loadSeq.current) setLoading(false)
    }
  }, [server.id, awgBase, handleError])
  // действия (отзыв, пауза, переименование) перезагружают список через ref: если
  // за время запроса переключили вкладку 2.0/3.1/Legacy, load из замыкания
  // загрузил бы клиентов старого протокола на новую вкладку
  const loadRef = useRef(load)
  loadRef.current = load

  useEffect(() => {
    if (!isAwg) return
    void load()
    // версия/обновление — только у нового AmneziaWG; legacy панель не пересобирает.
    // Сбрасываем перед запросом, чтобы версия 2.0 не «переезжала» на другую вкладку.
    setVersion(null)
    setVersionFailed(false)
    if (proto === 'awg') {
      api<VersionInfo>(`/api/servers/${server.id}/awg/version`)
        .then(setVersion)
        .catch(() => {
          setVersion(null)
          setVersionFailed(true)
        })
    }
  }, [load, server.id, isAwg, proto])

  function showConfig(name: string, config: string, amnezia: string | undefined, filename?: string) {
    setView({ name, config, amnezia: amnezia || '', native: nativeWireguard, filename })
    setCfgFormat(nativeWireguard ? 'conf' : 'amnezia')
    setCopied(false)
  }

  const currentText = view
    ? view.native || cfgFormat === 'conf'
      ? view.config
      : view.amnezia
    : ''
  const shareLink = useShareLink(currentText, view?.name ?? '', server.group_name)

  // обычный QR только для .conf (amnezia-формат рисует AmneziaQr — анимированный)
  useEffect(() => {
    if (!view || cfgFormat !== 'conf') {
      setQr(null)
      return
    }
    let alive = true
    QRCode.toDataURL(view.config, { margin: 1, width: 360 })
      .then((url) => {
        if (alive) setQr(url)
      })
      .catch(() => {
        if (alive) setQr(null)
      })
    return () => {
      alive = false
    }
  }, [view, cfgFormat])

  function openAdd() {
    setNewName('')
    setNewNote('')
    setNewExpiry(null)
    setAddOpen(true)
  }

  async function addClient() {
    if (!newName.trim() || creatingRef.current) return
    creatingRef.current = true
    setCreating(true)
    setError(null)
    const generation = configGeneration.current
    try {
      const result = await api<CreatedClient | NativeCreatedClient<AwgClient>>(
        `/api/servers/${server.id}/${awgBase}/clients`,
        {
          method: 'POST',
          body: JSON.stringify({
            name: newName.trim(),
            note: newNote.trim(),
            expires_at: newExpiry,
          }),
        },
      )
      if (generation !== configGeneration.current) return
      setAddOpen(false)
      showConfig(result.client.name, result.config, 'config_amnezia' in result ? result.config_amnezia : undefined, 'filename' in result ? result.filename : undefined)
      await loadRef.current()
    } catch (err) {
      if (generation === configGeneration.current) handleError(err)
    } finally {
      creatingRef.current = false
      setCreating(false)
    }
  }

  function startEdit(client: AwgClient) {
    escaping.current = false
    setDraft(client.note || '')
    setEditKey(client.public_key)
  }

  function cancelEdit() {
    escaping.current = true
    setEditKey(null)
  }

  async function commitNote(client: AwgClient) {
    if (escaping.current) {
      escaping.current = false
      return
    }
    const value = draft.trim()
    setEditKey(null)
    if (value === (client.note || '')) return
    try {
      await api<void>(`/api/servers/${server.id}/${awgBase}/note`, {
        method: 'POST',
        body: JSON.stringify({ public_key: client.public_key, note: value }),
      })
      await loadRef.current()
    } catch (err) {
      handleError(err)
    }
  }

  async function viewConfig(client: AwgClient) {
    setBusyKey(client.public_key)
    setError(null)
    const generation = configGeneration.current
    try {
      const result = await api<NativeClientConfig | {
        config: string
        config_amnezia: string
        name: string
      }>(`/api/servers/${server.id}/${awgBase}/config`, {
        method: 'POST',
        body: JSON.stringify({ public_key: client.public_key }),
      })
      if (generation !== configGeneration.current) return
      showConfig(result.name, result.config, 'config_amnezia' in result ? result.config_amnezia : undefined, 'filename' in result ? result.filename : undefined)
    } catch (err) {
      if (generation === configGeneration.current) handleError(err)
    } finally {
      if (generation === configGeneration.current) setBusyKey(null)
    }
  }

  async function reissue(client: AwgClient) {
    if (
      !window.confirm(
        t('Перевыпустить конфиг для «{name}»? Старый ключ перестанет работать.', {
          name: client.name,
        }),
      )
    )
      return
    setBusyKey(client.public_key)
    setError(null)
    const generation = configGeneration.current
    try {
      const result = await api<CreatedClient | NativeCreatedClient<AwgClient>>(
        `/api/servers/${server.id}/${awgBase}/reissue`,
        { method: 'POST', body: JSON.stringify({ public_key: client.public_key }) },
      )
      if (generation !== configGeneration.current) return
      showConfig(result.client.name, result.config, 'config_amnezia' in result ? result.config_amnezia : undefined, 'filename' in result ? result.filename : undefined)
      await loadRef.current()
    } catch (err) {
      if (generation === configGeneration.current) handleError(err)
    } finally {
      if (generation === configGeneration.current) setBusyKey(null)
    }
  }

  async function togglePause(client: AwgClient) {
    const resume = !!client.paused
    if (
      !resume &&
      !window.confirm(
        t('Поставить «{name}» на паузу? Клиент не сможет подключиться, но его можно вернуть без пересоздания.', {
          name: client.name,
        }),
      )
    )
      return
    setBusyKey(client.public_key)
    try {
      await pauseClient(server.id, awgBase, client.public_key, resume)
      await loadRef.current()
    } catch (err) {
      handleError(err)
    } finally {
      setBusyKey(null)
    }
  }

  async function rename(client: AwgClient) {
    const next = window.prompt(t('Новое имя клиента'), client.name)?.trim()
    if (!next || next === client.name) return
    setBusyKey(client.public_key)
    try {
      await renameClient(server.id, limitProto, client.public_key, next)
      await loadRef.current()
    } catch (err) {
      handleError(err)
    } finally {
      setBusyKey(null)
    }
  }

  async function revoke(client: AwgClient) {
    if (
      !window.confirm(
        t('Отозвать клиента «{name}»? Он потеряет доступ.', { name: client.name }),
      )
    )
      return
    setBusyKey(client.public_key)
    try {
      await api<void>(`/api/servers/${server.id}/${awgBase}/revoke`, {
        method: 'POST',
        body: JSON.stringify({ public_key: client.public_key }),
      })
      await loadRef.current()
    } catch (err) {
      handleError(err)
    } finally {
      setBusyKey(null)
    }
  }

  async function changeLimit(client: AwgClient, iso: string | null) {
    try {
      await setClientLimit(server.id, limitProto, client.public_key, client.name, iso)
      await loadRef.current()
    } catch (err) {
      handleError(err)
    }
  }

  async function copyConfig() {
    if (!view) return
    setCopied(await copyText(currentText))
  }

  function downloadConfig() {
    if (!view) return
    const ext = view.native || cfgFormat === 'conf' ? 'conf' : 'txt'
    const blob = new Blob([currentText], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = configFilename(view.name, ext, view.native ? view.filename : undefined)
    a.click()
    URL.revokeObjectURL(url)
  }

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortAsc((v) => !v)
    } else {
      setSortKey(key)
      setSortAsc(true)
    }
  }

  const visibleClients = useMemo(() => {
    if (!state) return []
    const q = search.trim().toLowerCase()
    const filtered = focus
      ? state.clients.filter((c) => c.public_key === focus)
      : q
      ? state.clients.filter(
          (c) =>
            c.name.toLowerCase().includes(q) || c.address.toLowerCase().includes(q),
        )
      : state.clients.slice()
    filtered.sort((a, b) => {
      let cmp = 0
      if (sortKey === 'name') cmp = a.name.localeCompare(b.name, 'ru')
      else if (sortKey === 'handshake')
        cmp = (a.latest_handshake ?? 0) - (b.latest_handshake ?? 0)
      else cmp = a.rx_bytes + a.tx_bytes - (b.rx_bytes + b.tx_bytes)
      return sortAsc ? cmp : -cmp
    })
    return filtered
  }, [state, search, sortKey, sortAsc, focus])

  const sel = useSelection(useMemo(() => visibleClients.map((c) => c.public_key), [visibleClients]))
  const current = protocols.find((p) => p.key === proto)

  const arrow = (key: SortKey) =>
    sortKey === key ? (sortAsc ? ' ▲' : ' ▼') : ''

  return (
    <div className="modal-backdrop" onClick={dismiss}>
      <div
        className="card modal modal-wide modal-clients"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="clients-head">
          <h3>{t('Клиенты')} · {server.name}</h3>
          <button className="ghost" onClick={onClose}>
            {t('Закрыть')}
          </button>
        </div>

        {protocols.length > 1 && (
          <div className="tabs">
            {protocols.map((p) => (
              <button
                key={p.key}
                className={proto === p.key ? 'tab tab-active' : 'tab'}
                onClick={() => {
                  configGeneration.current += 1
                  setView(null)
                  setAddOpen(false)
                  setBusyKey(null)
                  setProto(p.key)
                  setFocus(null)
                }}
              >
                {p.label}
              </button>
            ))}
          </div>
        )}

        {focus && (
          <div className="focus-line">
            <span className="muted small">{t('Показан один клиент из поиска')}</span>
            <button className="link-btn" onClick={() => setFocus(null)}>
              {t('Показать всех клиентов сервера')}
            </button>
          </div>
        )}

        {(proto === 'openvpn' || proto === 'openvpn-native') && (
          <OpenVpnClients
            key={`${server.id}:${proto}`}
            serverId={server.id}
            serverName={server.name}
            protocol={proto}
            groupName={server.group_name}
            onUnauthorized={onUnauthorized}
            onRequestUpdate={onRequestUpdate && (() => onRequestUpdate(proto))}
            focusClient={focus}
          />
        )}

        {proto === 'xray' && (
          <XrayClients
            serverId={server.id}
            serverName={server.name}
            groupName={server.group_name}
            onUnauthorized={onUnauthorized}
            onRequestUpdate={onRequestUpdate && (() => onRequestUpdate('xray'))}
            focusClient={focus}
          />
        )}

        {isAwg && (
          <>
        {state && (
          <div className="info-chips">
            <span className="info-chip">
              <span className="info-label">{t('интерфейс')}</span>
              <span className="mono">{state.interface}</span>
            </span>
            <span className="info-chip">
              <span className="info-label">endpoint</span>
              <span className="mono">{state.endpoint}</span>
            </span>
            <span className="info-chip">
              <span className="info-label">{t('подсеть')}</span>
              <span className="mono">{state.address}</span>
            </span>
          </div>
        )}

        {proto === 'awg' && !focus && (version || versionFailed) && (
          <div className="version-line">
            <span className="muted small">
              AmneziaWG:{' '}
              <span className="mono">
                {version?.current_version ?? version?.current_awg_go ?? t('не удалось узнать')}
              </span>
              {/* после обновления на месте версии 2.x к контейнеру не относятся */}
              {state?.params_v31 !== true && version?.deployed && version?.update_available && (
                <span className="update-badge">
                  {t('есть')} {version?.latest_version ?? t('новее')}
                </span>
              )}
              {state?.params_v31 !== true && version?.deployed && !version?.update_available && (
                <span className="version-ok"> {t('актуальна')}</span>
              )}
              {state?.params_v31 === true && (
                <span className="muted"> · {t('протокол обновлён до 3.1')}</span>
              )}
              {version?.foreign_container ? (
                <span className="muted">
                  {' '}·{' '}
                  {version?.adoptable
                    ? t('образ собран не панелью')
                    : t('внешний образ (не AmneziaWG) — перенос недоступен')}
                </span>
              ) : (
                version && !version.deployed && (
                  <span className="muted">
                    {' '}· {t('базовый образ не считывается')}
                  </span>
                )
              )}
            </span>
            <div className="version-actions">
              {/* откат к снимку, снятому перед пересборкой (страховка) */}
              <RollbackMenu
                serverId={server.id}
                serverName={server.name}
                proto="awg"
                onRestored={load}
                onUnauthorized={onUnauthorized}
              />
              {/* Внешний AmneziaWG-контейнер (собран клиентом, awg0.conf) —
                  предлагаем «Взять под управление»: панель перечитает конфиг из
                  живого контейнера, сохранит порт/ключи и заменит его своим.
                  Несовместимый внешний образ (напр. plain-WireGuard) не трогаем —
                  ни adopt, ни пересборка, иначе потеряли бы клиентов. Панельный
                  контейнер (в т.ч. без читаемого дайджеста) пересобираем — конфиг
                  переносится из живого контейнера. */}
              {/* Обновление 2.0 → 3.1 ВНУТРИ amnezia-awg2. Приложение узнаёт
                  версию не по имени контейнера, а по protocol_version, поэтому
                  «полный доступ» покажет 3.1 только после такого обновления —
                  отдельный amnezia-awg3 приложение вообще не видит. */}
              {onRequestUpgrade31 && state?.params_v31 === false && (
                <button className="ghost" onClick={onRequestUpgrade31}>
                  {t('Обновить до 3.1')}
                </button>
              )}
              {version?.foreign_container ? (
                version?.adoptable
                  ? onRequestAdopt && (
                      <button className="ghost" onClick={onRequestAdopt}>
                        {t('Взять под управление')}
                      </button>
                    )
                  : null
              ) : (
                // на 3.1 бэкенд пересобирает движком 3.1 с тем же конфигом
                onRequestUpdate && (
                <button className="ghost" onClick={() => onRequestUpdate('awg')}>
                  {state?.params_v31 === true
                    ? t('Пересобрать')
                    : version?.deployed && version?.update_available
                      ? t('Обновить версию')
                      : t('Переустановить')}
                </button>
                )
              )}
            </div>
          </div>
        )}

        {proto === 'awg3' && state && !focus && (
          <div className="version-line">
            <span className="muted small">
              {state.params_v31 === false
                ? t('На этой ноде развёрнута AmneziaWG 3.0. Нажмите «Пересобрать» — конфиг мигрирует до 3.1, после чего клиентов нужно перевыпустить.')
                : t('AmneziaWG 3.1 — собирается на ноде из закреплённых версий исходников')}
            </span>
            <div className="version-actions">
              {/* откат к снимку, снятому перед пересборкой (страховка) */}
              <RollbackMenu
                serverId={server.id}
                serverName={server.name}
                proto="awg3"
                onRestored={load}
                onUnauthorized={onUnauthorized}
              />
              {onRequestUpdate && (
                <button className="ghost" onClick={() => onRequestUpdate('awg3')}>
                  {t('Пересобрать')}
                </button>
              )}
            </div>
          </div>
        )}

        {nativeWireguard && state && !focus && <div className="version-line">
          <span className="muted small">{t('WireGuard — обычный протокол, без параметров AmneziaWG.')}{state.version && <> · <span className="mono">{state.version}</span></>}</span>
          <div className="version-actions">
            {state.capabilities?.config_restore === true && <RollbackMenu serverId={server.id} serverName={server.name} proto="wireguard" onRestored={load} onUnauthorized={onUnauthorized} />}
            {onRequestUpdate && state.capabilities?.update === true && <button className="ghost" onClick={() => onRequestUpdate('wireguard')}>{t('Переустановить')}</button>}
          </div>
        </div>}

        {error && <p className="form-error">{error}</p>}
        {loading && <p className="muted">{t('загрузка…')}</p>}

        {state && !loading && (
          <>
            {addOpen ? (
              <div className="add-form">
                <input
                  autoFocus
                  placeholder={t('Имя клиента (например, phone-max)')}
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && addClient()}
                />
                <input
                  placeholder={t('Заметка (необязательно): кому выдан, устройство…')}
                  value={newNote}
                  onChange={(e) => setNewNote(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && addClient()}
                />
                <label className="expiry-row">
                  <span className="muted small">{t('Срок действия:')}</span>
                  <ExpirySelect value={newExpiry} onChange={setNewExpiry} />
                </label>
                <div className="add-form-actions">
                  <button className="ghost" onClick={() => setAddOpen(false)}>
                    {t('Отмена')}
                  </button>
                  <button onClick={addClient} disabled={creating || !newName.trim()}>
                    {creating ? t('Создание…') : t('Создать конфиг')}
                  </button>
                </div>
              </div>
            ) : (
              <div className="toolbar">
                <button onClick={openAdd}>{t('+ Выдать конфиг')}</button>
                {state.clients.length > 0 && (
                  <input
                    className="search-box"
                    placeholder={t('Поиск по имени или адресу…')}
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                )}
              </div>
            )}

            <BulkRevokeBar
              serverId={server.id}
              serverName={server.name}
              protocol={limitProto}
              protocolLabel={current?.label ?? limitProto}
              sel={sel}
              onDone={load}
              onUnauthorized={onUnauthorized}
            />

            {state.clients.length === 0 ? (
              <p className="muted">{t('Клиентов пока нет.')}</p>
            ) : (
              <div className="table-card clients-scroll">
                <table>
                  <thead>
                    <tr>
                      <SelectAllCell sel={sel} />
                      <th className="sortable" onClick={() => toggleSort('name')}>
                        {t('Имя')}{arrow('name')}
                      </th>
                      <th>{t('Адрес')}</th>
                      <th className="sortable" onClick={() => toggleSort('handshake')}>
                        {t('Последний хендшейк')}{arrow('handshake')}
                      </th>
                      <th className="sortable" onClick={() => toggleSort('traffic')}>
                        {t('Трафик (↓ / ↑)')}{arrow('traffic')}
                      </th>
                      <th>{t('Срок')}</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {visibleClients.map((c) => {
                      const busy = busyKey === c.public_key
                      const editing = editKey === c.public_key
                      return (
                        <tr key={c.public_key}>
                          <SelectCell sel={sel} id={c.public_key} />
                          <td className="name-cell">
                            <div className="client-row-name">
                              <span
                                className={`dot ${
                                  c.paused
                                    ? 'dot-unknown'
                                    : isOnline(c.latest_handshake)
                                      ? 'dot-ok'
                                      : 'dot-unknown'
                                }`}
                              />
                              <span
                                className="cname"
                                title={c.name}
                                style={c.paused ? { opacity: 0.6 } : undefined}
                              >
                                {c.name}
                              </span>
                              {c.paused && (
                                <span className="pause-badge">{t('⏸ пауза')}</span>
                              )}
                              <TorrentBadge hit={torrentHits.get(`${limitProto}:${c.public_key}`)} />
                              {!editing && (
                                <button
                                  className="note-edit"
                                  title={t('Заметка')}
                                  onClick={() => startEdit(c)}
                                >
                                  ✎
                                </button>
                              )}
                            </div>
                            {editing ? (
                              <input
                                className="note-input"
                                autoFocus
                                value={draft}
                                placeholder={t('заметка…')}
                                onChange={(e) => setDraft(e.target.value)}
                                onKeyDown={(e) => {
                                  if (e.key === 'Enter') commitNote(c)
                                  if (e.key === 'Escape') {
                                    // иначе Escape закроет и окно клиентов
                                    e.preventDefault()
                                    cancelEdit()
                                  }
                                }}
                                onBlur={() => commitNote(c)}
                              />
                            ) : (
                              c.note && (
                                <div
                                  className="note-line"
                                  title={c.note}
                                  onClick={() => startEdit(c)}
                                >
                                  {c.note}
                                </div>
                              )
                            )}
                          </td>
                          <td className="mono">{c.address}</td>
                          <td className="muted">
                            {formatHandshake(c.latest_handshake)}
                          </td>
                          <td className="muted mono traffic-cell">
                            <div>↓ {formatBytes(c.tx_bytes)}</div>
                            <div>↑ {formatBytes(c.rx_bytes)}</div>
                          </td>
                          <td>
                            <ExpiryCell
                              value={c.expires_at}
                              disabled={busy}
                              onSave={(iso) => changeLimit(c, iso)}
                            />
                          </td>
                          <td className="row-actions">
                            {c.paused ? (
                              <button
                                disabled={busy}
                                onClick={() => togglePause(c)}
                                title={t('Вернуть клиента на сервер')}
                              >
                                {busy ? '…' : t('Возобновить')}
                              </button>
                            ) : c.has_config ? (
                              <button
                                className="ghost"
                                disabled={busy}
                                onClick={() => viewConfig(c)}
                              >
                                {busy ? '…' : t('Конфиг')}
                              </button>
                            ) : (
                              <button
                                className="ghost"
                                disabled={busy}
                                onClick={() => reissue(c)}
                              >
                                {busy ? '…' : t('Перевыпустить')}
                              </button>
                            )}
                            <Menu
                              fixed
                              align="right"
                              className="ghost icon-btn"
                              caret={false}
                              title={t('Ещё')}
                              label="⋯"
                              items={
                                c.paused
                                  ? [
                                      {
                                        label: t('Переименовать'),
                                        onClick: () => rename(c),
                                      },
                                      {
                                        label: t('Отозвать'),
                                        danger: true,
                                        onClick: () => revoke(c),
                                      },
                                    ]
                                  : [
                                      ...(c.has_config
                                        ? [
                                            {
                                              label: t('Перевыпустить'),
                                              onClick: () => reissue(c),
                                            },
                                          ]
                                        : []),
                                      {
                                        label: t('Трафик клиента'),
                                        onClick: () => setStatsFor(c),
                                      },
                                      {
                                        label: t('Переименовать'),
                                        onClick: () => rename(c),
                                      },
                                      {
                                        label: t('Пауза'),
                                        onClick: () => togglePause(c),
                                      },
                                      { divider: true },
                                      {
                                        label: t('Отозвать'),
                                        danger: true,
                                        onClick: () => revoke(c),
                                      },
                                    ]
                              }
                            />
                          </td>
                        </tr>
                      )
                    })}
                    {visibleClients.length === 0 && (
                      <tr>
                        <td colSpan={7} className="muted">
                          {t('Ничего не найдено.')}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}

        {view && (
          <div className="modal-backdrop">
            <div className="card modal modal-config" onClick={(e) => e.stopPropagation()}>
              <h3>{t('Конфиг клиента «{name}»', { name: view.name })}</h3>
              <div className="modal-config-body">

              {!view.native && <div className="tabs">
                <button
                  className={cfgFormat === 'amnezia' ? 'tab tab-active' : 'tab'}
                  onClick={() => {
                    setCfgFormat('amnezia')
                    setCopied(false)
                  }}
                >
                  {t('Для приложения AmneziaVPN')}
                </button>
                <button
                  className={cfgFormat === 'conf' ? 'tab tab-active' : 'tab'}
                  onClick={() => {
                    setCfgFormat('conf')
                    setCopied(false)
                  }}
                >
                  {t('AmneziaWG (.conf)')}
                </button>
              </div>}

              <p className="muted small">
                {view.native ? t('Обычная конфигурация WireGuard. Импортируйте .conf или отсканируйте QR в приложении WireGuard.') : cfgFormat === 'conf'
                  ? t('Конфигурация для приложения AmneziaWG. Для обычного WireGuard используйте отдельный протокол WireGuard.')
                  : t('Ссылка vpn:// — вставьте её в приложение AmneziaVPN («+» → вставить из буфера) или отсканируйте QR.')}
              </p>

              <div className="qr-wrap">
                {!view.native && cfgFormat === 'amnezia' ? (
                  <AmneziaQr text={view.amnezia} format="vpn" />
                ) : qr ? (
                  <img src={qr} alt={t('QR конфига')} width={240} height={240} />
                ) : (
                  <span className="muted small">{t('генерация QR…')}</span>
                )}
              </div>
              <pre className="script-box">{currentText}</pre>
              {shareLink.result}
              </div>
              <div className="modal-actions">
                <button className="ghost" onClick={() => setView(null)}>
                  {t('Готово')}
                </button>
                <button className="ghost" onClick={downloadConfig}>
                  {t('Скачать')} {view.native || cfgFormat === 'conf' ? '.conf' : '.txt'}
                </button>
                {shareLink.control}
                <button onClick={copyConfig}>
                  {copied ? t('Скопировано ✓') : t('Скопировать')}
                </button>
              </div>
            </div>
          </div>
        )}

        {statsFor && (
          <ClientStatsModal
            serverId={server.id}
            protocol={limitProto}
            clientId={statsFor.public_key}
            name={statsFor.name}
            onClose={() => setStatsFor(null)}
            onUnauthorized={onUnauthorized}
          />
        )}
          </>
        )}

      </div>
    </div>
  )
}
