import {
  createContext,
  useCallback,
  useContext,
  useState,
  type ReactNode,
} from 'react'

export type Lang = 'ru' | 'en'

// Ключ = русская строка (дефолт). Значение = английский перевод.
// Отсутствующий ключ → возвращается русский (мягкий фолбэк).
const EN: Record<string, string> = {
  // --- шапка / навигация ---
  'Серверы': 'Servers',
  'Обзор': 'Overview',
  'Журнал': 'Log',
  'Журнал действий': 'Action log',
  'Бэкап': 'Backup',
  'Бэкап…': 'Backup…',
  'Выйти': 'Log out',
  'На главную': 'Home',
  'Тема': 'Theme',
  'Язык': 'Language',
  'Скачать бэкап': 'Download backup',
  'Авто-бэкапы…': 'Auto backups…',
  'Восстановить из файла…': 'Restore from file…',

  // --- вход ---
  'Вход в панель': 'Sign in',
  'Войти': 'Log in',
  'Не удалось войти': 'Sign in failed',
  'Неизвестная ошибка': 'Unknown error',
  'Логин': 'Login',
  'Пароль': 'Password',

  // --- серверы ---
  'Импорт': 'Import',
  '+ Добавить сервер': '+ Add server',
  'Серверов пока нет — добавьте первый: имя, хост и SSH-доступ.':
    'No servers yet — add the first one: name, host and SSH access.',
  'Клиенты': 'Clients',
  'Проверить': 'Check',
  'Проверка…': 'Checking…',
  'Ещё': 'More',
  'Развернуть AmneziaWG': 'Deploy AmneziaWG',
  'Развернуть XRay / REALITY': 'Deploy XRay / REALITY',
  'Скрипт настройки': 'Setup script',
  'Изменить': 'Edit',
  'Удалить сервер': 'Delete server',
  'Генерация…': 'Generating…',
  'онлайн': 'online',
  'ошибка': 'error',
  'ошибка (см. лог)': 'error (see log)',
  'не проверялся': 'not checked',
  '· docker недоступен': '· docker unavailable',

  // --- форма сервера ---
  'Новый сервер': 'New server',
  'Изменить сервер': 'Edit server',
  'Имя': 'Name',
  'Хост (IP или домен)': 'Host (IP or domain)',
  'Заметка': 'Note',
  'Сохранить': 'Save',
  'Сохранение…': 'Saving…',
  'Отмена': 'Cancel',
  'Подключаюсь и настраиваю…': 'Connecting and configuring…',
  'Настроить автоматически по SSH-паролю':
    'Configure automatically via SSH password',
  'SSH-пароль': 'SSH password',
  'пользователь sudo (обычно есть)': 'sudo user (usually present)',

  // --- удаление ---
  'Удалить сервер «{name}»?': 'Delete server “{name}”?',
  'Сервер и VPN не тронутся — он только пропадёт из панели. Все выданные клиентские конфиги останутся рабочими.':
    'The server and VPN are untouched — it just disappears from the panel. All issued client configs keep working.',
  'Также убрать SSH-ключ панели с сервера (панель зайдёт по SSH)':
    'Also remove the panel SSH key from the server (panel will connect over SSH)',
  'Удалить': 'Delete',
  'Удаление…': 'Deleting…',

  // --- клиенты (общее) ---
  '+ Выдать конфиг': '+ Issue config',
  'Создать конфиг': 'Create config',
  'Создание…': 'Creating…',
  'Имя клиента (например, phone-max)': 'Client name (e.g. phone-max)',
  'Заметка (необязательно): кому выдан, устройство…':
    'Note (optional): who it is for, device…',
  'Клиентов пока нет.': 'No clients yet.',
  'Конфиг': 'Config',
  'Перевыпустить': 'Reissue',
  'Отозвать': 'Revoke',
  'Готово': 'Done',
  'Закрыть': 'Close',
  'Скачать .txt': 'Download .txt',
  'Скопировать': 'Copy',
  'Скопировано ✓': 'Copied ✓',
  'QR конфига': 'Config QR',
  'генерация QR…': 'generating QR…',
  'QR {n}/{total} · кадры меняются — держите камеру приложения':
    'QR {n}/{total} · frames cycle — hold your app camera on it',
  'Ссылка vpn:// — вставьте её в приложение AmneziaVPN («+» → вставить из буфера) или отсканируйте QR.':
    'A vpn:// link — paste it into the AmneziaVPN app (“+” → paste from clipboard) or scan the QR.',
  'заметка…': 'note…',
  'Поиск по имени или адресу…': 'Search by name or address…',
  'Адрес': 'Address',
  'Последний хендшейк': 'Last handshake',
  'Трафик (↓ / ↑)': 'Traffic (↓ / ↑)',
  'Создан': 'Created',
  'Ничего не найдено.': 'Nothing found.',

  // --- срок действия клиента ---
  'Срок': 'Expiry',
  'Срок действия:': 'Expiry:',
  'Бессрочно': 'No expiry',
  '7 дней': '7 days',
  '30 дней': '30 days',
  '90 дней': '90 days',
  'Своя дата…': 'Custom date…',
  'Задать срок': 'Set expiry',
  'Изменить срок': 'Change expiry',
  'истёк': 'expired',
  'до {date}': 'until {date}',

  // --- ресурсы нод ---
  'Средняя загрузка (1 мин) / ядер': 'Load average (1 min) / cores',
  'Память': 'Memory',
  'Диск /': 'Disk /',
  'Диск': 'Disk',
  'Аптайм': 'Uptime',

  // --- 2FA ---
  'Двухфакторная аутентификация': 'Two-factor authentication',
  'Код из приложения (2FA)': 'Code from the app (2FA)',
  'Неверный код 2FA': 'Invalid 2FA code',
  'Неверный логин или пароль': 'Wrong login or password',
  'Неверный код': 'Invalid code',
  '2FA включена. Вход требует код из приложения.':
    '2FA is on. Login requires a code from the app.',
  'Чтобы отключить, введите текущий код из приложения-аутентификатора.':
    'To turn it off, enter the current code from your authenticator app.',
  'Отключить 2FA': 'Disable 2FA',
  'Отсканируйте QR в приложении-аутентификаторе (Google Authenticator, Aegis, 1Password) или введите ключ вручную, затем подтвердите кодом.':
    'Scan the QR in an authenticator app (Google Authenticator, Aegis, 1Password) or enter the key manually, then confirm with a code.',
  'Ключ:': 'Key:',
  'Включить': 'Enable',
  'Добавьте второй фактор к входу в панель — одноразовый код из приложения-аутентификатора (TOTP).':
    'Add a second factor to panel login — a one-time code from an authenticator app (TOTP).',
  'Включить 2FA': 'Enable 2FA',

  'Открыть клиентов': 'Open clients',
  'Исходный код (AGPL-3.0)': 'Source code (AGPL-3.0)',
  'Без группы': 'Ungrouped',
  'Группа (папка)': 'Group (folder)',
  'необязательно — компания, локация…': 'optional — company, location…',

  // --- топ клиентов ---
  'Топ клиентов по трафику': 'Top clients by traffic',
  'Клиент': 'Client',
  'Протокол': 'Protocol',
  'Всего': 'Total',

  // --- стата по клиенту ---
  'Стата': 'Stats',
  'Трафик клиента': 'Client traffic',
  'Трафик клиента «{name}»': 'Traffic of client “{name}”',
  'Накоплено с последнего перевыпуска:': 'Accumulated since last reissue:',
  'Скорость (трафик за интервал сбора)': 'Rate (traffic per collection interval)',
  'Данные копятся со сбором метрик — загляните позже.':
    'Data accumulates with metrics collection — check back later.',

  // --- алерты ---
  'Алерты': 'Alerts',
  'Алерты о падении серверов': 'Server-down alerts',
  'Панель следит за доступностью серверов и присылает уведомление, когда сервер пропадает или снова становится онлайн. Проверка идёт вместе со сбором метрик.':
    'The panel watches server availability and notifies you when a server goes down or comes back online. Checks run together with metrics collection.',
  'Создайте бота через @BotFather, вставьте его токен и chat_id (свой ID узнаете у @userinfobot).':
    'Create a bot via @BotFather, paste its token and chat_id (get your ID from @userinfobot).',
  'Токен бота': 'Bot token',
  'Вебхук': 'Webhook',
  'POST с JSON {"text": "…"} на указанный URL (Slack, Mattermost, свой сервис).':
    'POST with JSON {"text": "…"} to the given URL (Slack, Mattermost, your own service).',
  'Сохранено.': 'Saved.',
  'Не отправлено: {err}': 'Not sent: {err}',
  'Тестовый алерт отправлен — проверьте канал.':
    'Test alert sent — check the channel.',
  'Отправка…': 'Sending…',
  'Конфиг не сохранён в панели — перевыпустить':
    'Config not stored in the panel — reissue',
  'Конфиг клиента «{name}»': 'Config for client “{name}”',
  'AmneziaWG (.conf)': 'AmneziaWG (.conf)',
  'Для приложения AmneziaVPN': 'For the AmneziaVPN app',
  'Оригинальный AmneziaWG — импортируется в приложение AmneziaWG или WireGuard.':
    'Original AmneziaWG — imports into the AmneziaWG or WireGuard app.',

  // --- клиенты · тексты протоколов ---
  'OpenVPN поверх Cloak (маскировка под HTTPS). Конфиг выдаётся ссылкой vpn:// «Для приложения AmneziaVPN».':
    'OpenVPN over Cloak (masked as HTTPS). The config is issued as a vpn:// link “For the AmneziaVPN app”.',
  'XRay VLESS + REALITY (маскировка под TLS к настоящему сайту). Конфиг — ссылка vpn:// «Для приложения AmneziaVPN». Выдача/отзыв перезапускают xray (~2 сек, активные клиенты переподключатся).':
    'XRay VLESS + REALITY (masked as TLS to a real site). The config is a vpn:// link “For the AmneziaVPN app”. Issuing/revoking restarts xray (~2 s, active clients reconnect).',
  'XRay-core:': 'XRay-core:',
  'Обновить ядро': 'Update core',
  'Переустановить': 'Reinstall',
  'актуальна': 'up to date',
  'есть {ver}': '{ver} available',

  // --- версия / обновление / деплой ---
  'Пересобрать': 'Rebuild',
  'Обновить': 'Refresh',
  'есть': 'available',
  'образ собран не панелью': 'image not built by the panel',
  '· образ собран не панелью': '· image not built by the panel',
  'Установка XRay': 'Installing XRay',
  'Установка AmneziaWG': 'Installing AmneziaWG',
  'Обновление XRay': 'Updating XRay',
  'Обновление AmneziaWG': 'Updating AmneziaWG',
  'Сервер собирает образ Xray-core (alpine) и запускает VLESS+REALITY на 443. Это займёт 1–3 минуты.':
    'The server builds the Xray-core image (alpine) and starts VLESS+REALITY on 443. Takes 1–3 minutes.',
  'Сервер собирает образ из amneziavpn/amneziawg-go:latest и запускает AmneziaWG. Это займёт 1–3 минуты.':
    'The server builds the image from amneziavpn/amneziawg-go:latest and starts AmneziaWG. Takes 1–3 minutes.',
  'Сервер тянет свежий базовый образ и пересобирает контейнер. Клиенты и ключи сохраняются.':
    'The server pulls a fresh base image and rebuilds the container. Clients and keys are preserved.',
  '● выполняется…': '● running…',
  '✓ готово': '✓ done',
  '✗ ошибка (см. лог)': '✗ error (see log)',
  'запуск…': 'starting…',
  'Можно закрыть окно — процесс продолжится на сервере.':
    'You can close this window — the process continues on the server.',

  // --- полный доступ ---
  'Полный доступ': 'Full access',
  'Полный доступ · {name}': 'Full access · {name}',
  'Вставьте эту ссылку в приложении AmneziaVPN (на компьютере или телефоне): «+» → «Настроить свой сервер» → вставить из буфера. Сервер добавится как управляемый — можно выдавать конфиги и ставить протоколы прямо из приложения. Подключение пойдёт по SSH под пользователем':
    'Paste this link into the AmneziaVPN app (on desktop or phone): “+” → “Set up your own server” → paste from clipboard. The server is added as managed — you can issue configs and install protocols from the app. It connects over SSH as user',
  '(нужен доступ к docker — группа docker или sudo).':
    '(needs docker access — the docker group or sudo).',
  '⚠️ Ссылка содержит приватный SSH-ключ управления сервером — не публикуйте её и не пересылайте. Панель поставила отдельный ключ для этого доступа; при повторной генерации прежний перестаёт работать.':
    '⚠️ The link contains a private SSH key that manages the server — do not publish or forward it. The panel installed a dedicated key for this access; regenerating invalidates the previous one.',

  // --- импорт ---
  'Импорт серверов': 'Import servers',
  'Из Amnezia (vpn://)': 'From Amnezia (vpn://)',
  'Списком': 'As a list',
  'Импортировать': 'Import',
  'Импорт…': 'Importing…',
  'Результат': 'Result',
  'хост[:порт] пользователь пароль': 'host[:port] user password',
  'Откройте «Скрипт» для ручной установки.': 'Open “Script” for manual setup.',
  'В клиенте Amnezia: на сервере «Поделиться» → ':
    'In the Amnezia client, on a server: “Share” → ',
  ' → скопируйте ссылку ': ' → copy the link ',
  ' и вставьте сюда (можно несколько, по одной в строке). Панель извлечёт адрес и SSH-доступ и сама настроит сервер.':
    ' and paste it here (several allowed, one per line). The panel extracts the address and SSH access and configures the server for you.',
  'По одной строке на сервер: ': 'One server per line: ',
  '. Пароль нужен для автонастройки; без него сервер добавится, но ключ поставите скриптом. Пример:':
    '. The password is for auto-setup; without it the server is added, but you install the key via a script. Example:',
  '(за каждый интервал ~{min} мин)': '(per interval ~{min} min)',

  // --- бэкапы ---
  'Авто-бэкапы БД': 'Database auto backups',
  'Панель сама делает копии БД по расписанию и хранит последние. Файлы лежат на сервере в data/backups; можно скачать любую или восстановить через «Бэкап → Восстановить из файла».':
    'The panel makes scheduled database copies and keeps the most recent ones. Files live on the server in data/backups; download any or restore via “Backup → Restore from file”.',
  'Сделать бэкап сейчас': 'Back up now',
  'Пока нет ни одной копии.': 'No copies yet.',
  'Дата': 'Date',
  'Размер': 'Size',
  'Скачать': 'Download',
  'не удалось загрузить список': 'failed to load the list',
  'не удалось сделать бэкап': 'failed to create a backup',
  'Восстановить панель из «{name}»?\n\nВСЕ текущие серверы, конфиги, заметки и SSH-ключ панели будут ЗАМЕНЕНЫ данными из архива. Действие необратимо.':
    'Restore the panel from “{name}”?\n\nALL current servers, configs, notes and the panel SSH key will be REPLACED with the archive data. This cannot be undone.',
  'Восстановлено записей: {n}. Страница перезагрузится.':
    'Restored {n} records. The page will reload.',
  'Ошибка восстановления: {msg}': 'Restore error: {msg}',

  // --- журнал ---
  'Когда': 'When',
  'Кто': 'Who',
  'Действие': 'Action',
  'Объект': 'Target',
  'Пока пусто — действия появятся здесь.':
    'Empty so far — actions will appear here.',
  'не удалось загрузить журнал': 'failed to load the log',
  'Выдан AmneziaWG': 'AmneziaWG issued',
  'Отозван AmneziaWG': 'AmneziaWG revoked',
  'Перевыпущен AmneziaWG': 'AmneziaWG reissued',
  'Развёрнут AmneziaWG': 'AmneziaWG deployed',
  'Обновлён AmneziaWG': 'AmneziaWG updated',
  'Выдан OpenVPN': 'OpenVPN issued',
  'Отозван OpenVPN': 'OpenVPN revoked',
  'Перевыпущен OpenVPN': 'OpenVPN reissued',
  'Выдан XRay': 'XRay issued',
  'Отозван XRay': 'XRay revoked',
  'Развёрнут XRay': 'XRay deployed',
  'Обновлён XRay': 'XRay updated',
  'Добавлен сервер': 'Server added',
  'Удалён сервер': 'Server deleted',
  'Экспорт полного доступа': 'Full-access export',
  'Восстановление из бэкапа': 'Restore from backup',

  // --- дашборд ---
  'серверов онлайн': 'servers online',
  'клиентов онлайн': 'clients online',
  'суммарный трафик': 'total traffic',
  'Клиентов онлайн за 24 ч': 'Clients online (24h)',
  'Трафик за 24 ч': 'Traffic (24h)',
  'пока недостаточно данных для графика':
    'not enough data for the chart yet',
  'нет данных': 'no data',
  'Сервер': 'Server',
  'Статус': 'Status',

  // --- интерполируемые (подтверждения/уведомления) ---
  'Сервер «{name}» настроен и подключён.':
    'Server “{name}” configured and connected.',
  'Сервер «{name}» убран из панели.': 'Server “{name}” removed from the panel.',
  'Сервер создан, но автонастройка не удалась: {msg}. ':
    'Server created, but auto-setup failed: {msg}. ',
  'Отозвать клиента «{name}»? Он потеряет доступ.':
    'Revoke client “{name}”? It will lose access.',
  'Отозвать OpenVPN-клиента «{name}»? Он потеряет доступ.':
    'Revoke OpenVPN client “{name}”? It will lose access.',
  'Отозвать XRay-клиента «{name}»? Он потеряет доступ.':
    'Revoke XRay client “{name}”? It will lose access.',
  'Перевыпустить конфиг для «{name}»? Старый ключ перестанет работать.':
    'Reissue the config for “{name}”? The old key will stop working.',
  'Перевыпустить конфиг для «{name}»? Старый ключ перестанет работать — клиенту нужно будет заново импортировать конфиг.':
    'Reissue the config for “{name}”? The old key will stop working — the client must re-import the config.',
  'Установка {label}': 'Installing {label}',
  'Обновление {label}': 'Updating {label}',

  // --- скрипт настройки / форма сервера ---
  'Подготовка сервера «{name}»': 'Setting up server “{name}”',
  'Выполните этот скрипт под root на сервере. Он добавит SSH-ключ панели пользователю':
    'Run this script as root on the server. It adds the panel SSH key for user',
  ', разрешит SSH-порт только для IP панели (ufw / firewalld / hosts.allow; ничего лишнего наружу не открывает) и ответит':
    ', allows the SSH port only for the panel IP (ufw / firewalld / hosts.allow; nothing extra is exposed) and responds with',
  '. После этого нажмите «Проверить».': '. Then click “Check”.',
  'SSH-порт': 'SSH port',
  'SSH-пользователь': 'SSH user',
  'SSH-пароль пользователя {user}': 'SSH password for {user}',
  'Отдельный пароль для sudo?': 'Separate sudo password?',
  'Пароль для sudo (если отличается)': 'sudo password (if different)',
  'Автоматически по SSH-паролю': 'Automatically, via SSH password',
  'Панель сама зайдёт по паролю и всё настроит':
    'The panel connects with the password and sets everything up',
  'Скриптом — запущу на сервере сам': 'With a script — I run it on the server',
  'Панель даст скрипт: создаст юзера, ключ, откроет фаервол':
    'The panel gives a script: creates the user, key, opens the firewall',
  'После «Сохранить» панель покажет скрипт. Зайдите на сервер по SSH под root и вставьте его — он создаст пользователя «{user}», добавит ключ панели и откроет фаервол (если есть). Затем нажмите «Проверить» на карточке сервера — он подключится.':
    'After “Save”, the panel shows a script. SSH into the server as root and paste it — it creates the “{user}” user, adds the panel key and opens the firewall (if any). Then click “Check” on the server card — it will connect.',
  'Панель один раз зайдёт по паролю, установит свой ключ и откроет SSH-порт только для IP панели. Пароль не сохраняется.':
    'The panel connects once via password, installs its key and opens the SSH port only for the panel IP. The password is not stored.',
  '⚠️ Если на сервере включён фаервол и он блокирует SSH с IP панели — подключиться не получится (будет таймаут). В этом случае снимите галку и запустите ручной скрипт прямо на сервере — он откроет доступ панели.':
    '⚠️ If the server has a firewall that blocks SSH from the panel IP, connecting will fail (timeout). In that case uncheck the box and run the manual script on the server — it opens access for the panel.',
  'После создания панель покажет скрипт для ручного запуска на сервере.':
    'After creation, the panel shows a script to run manually on the server.',
  'подсеть': 'subnet',
  'Ошибка': 'Error',

  // --- общее / мелочи ---
  'загрузка…': 'loading…',
  'необязательно': 'optional',
  'неизвестно': 'unknown',
  'новее': 'newer',
}

type Ctx = {
  lang: Lang
  setLang: (l: Lang) => void
  t: (s: string, params?: Record<string, string | number>) => string
}

const I18nContext = createContext<Ctx>({
  lang: 'ru',
  setLang: () => {},
  t: (s) => s,
})

function fill(s: string, params?: Record<string, string | number>): string {
  if (!params) return s
  return s.replace(/\{(\w+)\}/g, (_, k) =>
    k in params ? String(params[k]) : `{${k}}`,
  )
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(
    () => (localStorage.getItem('acontrol_lang') as Lang) || 'ru',
  )
  const setLang = useCallback((l: Lang) => {
    localStorage.setItem('acontrol_lang', l)
    setLangState(l)
  }, [])
  const t = useCallback(
    (s: string, params?: Record<string, string | number>) =>
      fill(lang === 'en' ? EN[s] ?? s : s, params),
    [lang],
  )
  return (
    <I18nContext.Provider value={{ lang, setLang, t }}>
      {children}
    </I18nContext.Provider>
  )
}

// eslint-disable-next-line react-refresh/only-export-components
export const useI18n = () => useContext(I18nContext)
