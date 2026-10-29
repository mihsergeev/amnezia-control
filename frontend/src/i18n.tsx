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
  // --- фильтр "Обзора" по серверам ---
  'Все серверы': 'All servers',
  'Серверов: {n} из {total}': '{n} of {total} servers',
  'Найти сервер или группу': 'Find a server or group',
  'Ничего не найдено': 'Nothing found',
  'Показать статистику только по выбранным серверам':
    'Show statistics for the selected servers only',
  'Показаны все серверы: {n}': 'Showing all {n} servers',
  'Выбрано {n} из {total}': '{n} of {total} selected',
  'Сбросить': 'Reset',
  'только': 'only',
  // --- графики ---
  '↓ скачивание': '↓ download',
  '↑ отдача': '↑ upload',
  'по серверам': 'by server',
  'остальные ({n})': 'others ({n})',
  'Скорость, наведите курсор, чтобы увидеть значения':
    'Speed, hover to see the values',
  'Журнал': 'Log',
  'Журнал действий': 'Action log',
  'На этой ноде развёрнута AmneziaWG 3.0. Нажмите «Пересобрать» — конфиг мигрирует до 3.1, после чего клиентов нужно перевыпустить.':
    'This node runs AmneziaWG 3.0. Press "Rebuild" — the config migrates to 3.1, after which clients need reissuing.',
  'Поиск': 'Search',
  'Поиск клиентов': 'Client search',
  'Имя клиента, заметка или ключ': 'Client name, note or key',
  'По всем серверам и протоколам сразу. Найденное можно отозвать одним действием.':
    'Across every server and protocol at once. Revoke what you find in one action.',
  'Найти': 'Search',
  'Ищу…': 'Searching…',
  'Найдено: {n}': 'Found: {n}',
  'На паузе: {n}': 'Paused: {n}',
  '⏸ На паузе': '⏸ Paused',
  'Все клиенты на паузе по всем серверам; запрос в поле сужает список':
    'All paused clients across all servers; the query in the field narrows the list',
  'Клиентов на паузе нет.': 'No paused clients.',
  'на паузе с {at}': 'paused since {at}',
  'Возобновляю…': 'Resuming…',
  'выбрано: {n}': 'selected: {n}',
  'Выбрать все': 'Select all',
  'Снять все': 'Clear selection',
  'Отозвать выбранные': 'Revoke selected',
  'Переименовать': 'Rename',
  'Новое имя клиента': 'New client name',
  'Удалить протокол {proto}…': 'Remove protocol {proto}…',
  'Проверка каскада': 'Cascade check',
  'Шлюз на входе запущен': 'Gateway on the entry is running',
  'Клиенты идут через шлюз': 'Clients go through the gateway',
  'клиенты идут мимо шлюза': 'clients bypass the gateway',
  'пропало правило маршрутизации в шлюз': 'the routing rule into the gateway is gone',
  'Клиенты выходят с адреса выхода': 'Clients go out from the exit address',
  'клиенты выходят в интернет мимо выхода': 'clients reach the internet bypassing the exit',
  'из контейнера спросить нечем': 'nothing to ask with inside the container',
  'GRE-туннель до выхода поднят': 'GRE tunnel to the exit is up',
  'Интернет через выход': 'Internet through the exit',
  'Интернет': 'Internet',
  'Сайты страны входа напрямую': "Entry country's sites go directly",
  'адрес {ip}': 'address {ip}',
  'GRE-туннель выключен': 'GRE tunnel is down',
  'Каскад работает': 'Cascade works',
  'Каскад не работает': 'Cascade is down',
  'Каскад не работает: {reason}': 'Cascade is down: {reason}',
  'Вход не ответил: {err}': 'The entry did not answer: {err}',
  'Удалить {proto} с сервера «{server}» вместе со ВСЕМИ его клиентами? Их конфиги перестанут работать. Перед удалением на ноде сохраняется снимок конфига.':
    'Remove {proto} from "{server}" together with ALL its clients? Their configs will stop working. A config snapshot is saved on the node first.',
  'Удаление {proto} с сервера «{server}». Все клиенты протокола потеряют доступ.':
    'Removing {proto} from "{server}". Every client of this protocol loses access.',
  'Протокол удален с сервера «{name}», снимок конфига остался на ноде.':
    'Protocol removed from "{name}". A config snapshot stays on the node.',
  'Отозвать {n} доступ(ов)? Клиенты будут удалены с серверов — подключиться по старым конфигам станет нельзя. Отменить это нельзя.':
    'Revoke {n} access(es)? The clients are removed from the servers — old configs will stop connecting. This cannot be undone.',
  'Да, отозвать': 'Yes, revoke',
  'Отзываю…': 'Revoking…',
  'Результат отзыва': 'Revocation result',
  'Отозвано: {n}': 'Revoked: {n}',
  'не удалось: {n}': 'failed: {n}',
  'Клиенты, которых не удалось отозвать, остались в поиске — повторите, когда нода станет доступна.':
    'Clients that could not be revoked are still listed — retry once the node is reachable.',
  'без имени': 'unnamed',
  'Развернуть AmneziaWG 3.1': 'Deploy AmneziaWG 3.1',
  'AmneziaWG 3.1 — собирается на ноде из закреплённых версий исходников':
    'AmneziaWG 3.1 — built on the node from pinned source versions',
  'Сервер собирает AmneziaWG 3.1 из исходников (движок + утилиты закреплённых версий) и запускает его. Готового образа с бинарями 3.x пока нет, поэтому первая сборка занимает 3–7 минут.':
    'The server builds AmneziaWG 3.1 from source (engine + tools at pinned versions) and starts it. No prebuilt image with 3.x binaries exists yet, so the first build takes 3-7 minutes.',
  'Порт для установки': 'Port to install on',
  'Развернуть на этом порту': 'Deploy on this port',
  'API-ключи': 'API keys',
  'Документация API': 'API docs',
  'Ключ': 'Key',
  'Ключ создан': 'Key created',
  'Ключей пока нет.': 'No keys yet.',
  'Ключи нужны для интеграции внешних систем с панелью через /api/v1: выдавать и отзывать клиентов AmneziaWG, забирать конфиги, читать список серверов. Управлять серверами (разворачивать, удалять, брать полный доступ) ключ НЕ может.':
    'Keys let external systems integrate with the panel over /api/v1: issue and revoke AmneziaWG clients, fetch configs, list servers. A key canNOT manage servers (deploy, delete, or take full access).',
  'Кому выдан (напр. billing-panel)': 'Issued to (e.g. billing-panel)',
  'Копировать': 'Copy',
  'Название': 'Name',
  'Новый ключ': 'New key',
  'Отозван API-ключ': 'API key revoked',
  'Изменен API-ключ': 'API key changed',
  'Отозвать ключ «{name}»? Интеграция сразу перестанет работать.':
    'Revoke the key "{name}"? The integration will stop working immediately.',
  'Передавайте ключ в заголовке X-API-Key.': 'Send the key in the X-API-Key header.',
  'Последнее использование': 'Last used',
  'Скопируйте его сейчас — панель хранит только хэш и показать ключ повторно не сможет.':
    'Copy it now — the panel stores only a hash and cannot show the key again.',
  'Создан API-ключ': 'API key created',
  'Создать ключ': 'Create key',
  'Создаю…': 'Creating…',
  'Я сохранил ключ': 'I saved the key',
  'не использовался': 'never used',
  'не удалось загрузить ключи': 'failed to load keys',
  'не удалось отозвать ключ': 'failed to revoke the key',
  'не удалось создать ключ': 'failed to create the key',
  'отозван': 'revoked',
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
  'Развернуть OpenVPN / Cloak': 'Deploy OpenVPN / Cloak',
  'Сменить пароль': 'Change password',
  'Меню': 'Menu',
  'Откатить': 'Roll back',
  '{n} клиентов': '{n} clients',
  'Откатить конфиг «{name}» к снимку от {ts} ({n} клиентов)? Текущий конфиг будет заменён.':
    'Roll back the config on “{name}” to the {ts} snapshot ({n} clients)? The current config will be replaced.',
  'Пересобрать образ на «{name}»? Текущие клиенты и ключи сохраняются.':
    'Rebuild the image on “{name}”? Current clients and keys are preserved.',

  // --- пауза клиента / adopt / xray-перевыпуск ---
  'Пауза': 'Pause',
  'Возобновить': 'Resume',
  '⏸ пауза': '⏸ paused',
  'Вернуть клиента на сервер': 'Return the client to the server',
  'Поставить «{name}» на паузу? Клиент не сможет подключиться, но его можно вернуть без пересоздания.':
    'Pause “{name}”? The client will not be able to connect, but you can resume it later without recreating it.',
  'Взять под управление': 'Take under management',
  'Взятие под управление · {label}': 'Take under management · {label}',
  'внешний образ (не AmneziaWG) — перенос недоступен':
    'external image (not AmneziaWG) — cannot be taken over',
  'базовый образ не считывается': 'base image cannot be read',
  'Панель перечитывает конфиг из текущего контейнера, сохраняет его порт и ключи и заменяет его своим образом. Клиенты остаются — туннель кратко перезапустится. Перед этим снят снимок для отката.':
    'The panel re-reads the config from the current container, keeps its port and keys, and replaces it with its own image. Clients stay — the tunnel restarts briefly. A snapshot is taken first for rollback.',
  'Взять AmneziaWG на «{name}» под управление панели?\n\nПанель перечитает текущий конфиг, сохранит порт и ключи и заменит контейнер своим. Клиенты остаются рабочими, туннель кратко перезапустится. Перед этим снимается снимок для отката.':
    'Take AmneziaWG on “{name}” under panel management?\n\nThe panel will re-read the current config, keep the port and keys, and replace the container with its own. Clients keep working, the tunnel restarts briefly. A snapshot is taken first for rollback.',
  'Пересобрать образ (свежий alpine + cloak); клиенты и PKI сохраняются)':
    'Rebuild the image (fresh alpine + cloak); clients and PKI are preserved)',
  'Перевыпустить конфиг для «{name}»? Старый UUID перестанет работать.':
    'Reissue the config for “{name}”? The old UUID will stop working.',
  'Текущий пароль': 'Current password',
  'Новый пароль (мин. 8 символов)': 'New password (min. 8 characters)',
  'Повторите новый пароль': 'Repeat new password',
  'Пароль изменён. Все прежние сессии завершены.':
    'Password changed. All previous sessions have been ended.',
  'Смена пароля завершит все другие активные сессии.':
    'Changing the password ends all other active sessions.',
  'Пароль должен быть не короче 8 символов':
    'Password must be at least 8 characters',
  'Пароли не совпадают': 'Passwords do not match',
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
  // --- страница серверов: список и выбранный сервер ---
  'Имя, IP, заметка, протокол': 'Name, IP, note, protocol',
  'Все': 'All',
  'Проблемы': 'Problems',
  'онлайн / всего клиентов': 'online / total clients',
  '{n} онлайн': '{n} online',
  'проблем: {n}': 'problems: {n}',
  'Клиенты онлайн': 'Clients online',
  'аптайм {t}': 'uptime {t}',
  'load {l}, ядер {n}': 'load {l}, cores {n}',
  'выход в интернет: {ip}': 'internet exit: {ip}',
  'этот сервер': 'this server',
  'GRE-туннель до {ip}': 'GRE tunnel to {ip}',
  // --- одноразовые ссылки на конфиг ---
  'Ссылка': 'Link',
  'Создаю ссылку…': 'Creating link…',
  'Одноразовая ссылка через {name}': 'One-time link via {name}',
  'Ссылка через {name}: откроется один раз, через {n} дн. сгорит сама.':
    'Link via {name}: opens once, expires by itself in {n} days.',
  'Ссылки на конфиги': 'Config links',
  'Вместо файла в мессенджере - одноразовая ссылка: панель кладет конфиг в сервис секретов, ссылка открывается один раз и через 7 дней сгорит сама. Подходят sup3rS3cretMes5age и Password Pusher: поставьте любой у себя и укажите его адрес. В окне конфига появится кнопка «Ссылка».':
    'Instead of a file in a messenger, a one-time link: the panel puts the config into a secret-sharing service, the link opens once and expires by itself in 7 days. sup3rS3cretMes5age and Password Pusher work: host either one and enter its address. A "Link" button then appears in the config window.',
  'Добавить сервис': 'Add service',
  'Например, как группа серверов': 'For example, same as a server group',
  'Если название совпадает с группой сервера, этот сервис предлагается первым для его клиентов.':
    'If the name matches a server group, this service comes first for its clients.',
  'Проверяю…': 'Checking…',
  'Добавить': 'Add',
  'Конфиг отправлен ссылкой': 'Config sent as a link',
  'Добавлен сервис ссылок': 'Link service added',
  'Удален сервис ссылок': 'Link service removed',
  'выход в интернет': 'internet exit',
  'выход в интернет, {org}': 'internet exit, {org}',
  'Протоколы': 'Protocols',
  'Протоколы появятся после успешной проверки сервера.':
    'Protocols appear after a successful server check.',
  'Docker на сервере недоступен.': 'Docker is not available on the server.',
  'Протоколов нет. Развернуть можно в меню «Ещё».':
    'No protocols yet. Deploy one from the "More" menu.',

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
  'Перетащить': 'Drag to reorder',
  'Перетащить группу': 'Drag to reorder group',
  'Не удалось сохранить порядок': 'Could not save the order',
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
  'Панель присылает короткие алерты: сервер пропал или вернулся, каскад не работает, пропали клиенты, мало места на диске, события безопасности.':
    'The panel sends short alerts: a server went down or came back, a cascade stopped working, clients are gone, low disk space, security events.',
  'Создайте бота через @BotFather, вставьте его токен и chat_id (свой ID узнаете у @userinfobot).':
    'Create a bot via @BotFather, paste its token and chat_id (get your ID from @userinfobot).',
  'Токен бота': 'Bot token',
  'Адрес Bot API': 'Bot API address',
  'Оставьте пустым для api.telegram.org. Укажите зеркало/прокси, если Telegram заблокирован в регионе сервера (напр. https://api-tg.example.com).':
    'Leave empty for api.telegram.org. Set a mirror/proxy if Telegram is blocked in the server’s region (e.g. https://api-tg.example.com).',
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
  'XRay VLESS + REALITY (маскировка под TLS к настоящему сайту). Конфиг: ссылка vpn:// для AmneziaVPN или vless:// для Happ, v2rayN и других клиентов. Выдача/отзыв перезапускают xray (~2 сек, активные клиенты переподключатся).':
    'XRay VLESS + REALITY (masked as TLS to a real site). The config is a vpn:// link for AmneziaVPN or a vless:// link for Happ, v2rayN and other clients. Issuing/revoking restarts xray (~2 s, active clients reconnect).',
  'Ссылка vless://': 'vless:// link',
  'Ссылка vless:// для Happ, v2rayN, v2rayNG, INCY, Shadowrocket и других клиентов на Xray: импорт из буфера или по QR.':
    'A vless:// link for Happ, v2rayN, v2rayNG, INCY, Shadowrocket and other Xray-based clients: import from the clipboard or scan the QR.',
  'XHTTP - запасной вариант на том же порту: включайте, если Vision режут или он рвется.':
    'XHTTP is a fallback on the same port: use it if Vision is blocked or keeps dropping.',
  'XRay-core:': 'XRay-core:',
  'Обновить ядро': 'Update core',
  'Переустановить': 'Reinstall',
  'актуальна': 'up to date',
  'есть {ver}': '{ver} available',

  // --- версия / обновление / деплой ---
  'Пересобрать': 'Rebuild',
  'Выгрузить в файл': 'Export to file',
  'В файл уедет': 'The file will carry',
  'карточка сервера — адрес, доступ, группа': 'the server entry — address, access, group',
  'сохранённые конфиги клиентов': 'stored client configs',
  'заметки, сроки действия и паузы': 'notes, expiry dates and pauses',
  'Живых клиентов новая панель прочитает с самого сервера.':
    'Live clients are read from the server itself by the receiving panel.',
  'Внутри — приватные ключи клиентов. Храните файл как бэкап.':
    'It holds client private keys. Keep the file as safe as a backup.',
  'Включить историю трафика': 'Include traffic history',
  'На активной ноде это сотни тысяч строк: файл вырастет с килобайтов до сотен мегабайт. Новая панель наберёт историю заново.':
    'On a busy node that is hundreds of thousands of rows: the file grows from kilobytes to hundreds of megabytes. The receiving panel collects the history again by itself.',
  'Выбрать файл': 'Choose file',
  'файл не выбран': 'no file chosen',
  'Сначала выберите файл выгрузки': 'Choose an export file first',
  'Принято': 'Imported',
  'Что дальше': 'What is left',
  '«Ещё» → «Скрипт настройки» и выполнить его на сервере':
    'More → Setup script, then run it on the server',
  '«Ещё» → «Проверить» — панель подключится и покажет клиентов':
    'More → Check — the panel connects and shows the clients',
  // подписи таблиц в итоге импорта подставляются по ключу, поэтому
  // проверялкой не находятся — держим их здесь вручную
  'сохранённые конфиги': 'stored configs',
  'конфиги OpenVPN': 'OpenVPN configs',
  'заметки': 'notes',
  'сроки действия': 'expiry dates',
  'имена клиентов': 'client names',
  'клиенты на паузе': 'paused clients',
  'история трафика сервера': 'server traffic history',
  'история трафика клиентов': 'client traffic history',
  'Выгрузить сервер': 'Export server',
  'Из файла': 'From file',
  'Загрузить сервер из файла': 'Import a server from a file',
  'Загрузить': 'Import',
  'Загружаем…': 'Importing…',
  'Скачать файл': 'Download file',
  'Готовим…': 'Preparing…',
  'SSH-ключ панели в файл не попадает — он общий для всех ваших нод. Новая панель ходит своим ключом, её нужно будет пустить на сервер скриптом настройки.':
    'The panel SSH key is not included — one key serves all your nodes. The receiving panel uses its own key and has to be let onto the server with the setup script.',
  'Файл, выгруженный из другой панели через «Ещё» → «Выгрузить в файл». Существующие серверы не затрагиваются — добавится один новый.':
    'A file exported from another panel via More → Export to file. Existing servers are untouched — one new server is added.',
  'Сервер «{name}» ({host}) добавлен.': 'Server “{name}” ({host}) added.',
  'Не удалось принять таблицы (файл из более новой панели): {list}':
    'These tables could not be accepted (the file comes from a newer panel): {list}',
  'Обновить до 3.1': 'Upgrade to 3.1',
  'протокол обновлён до 3.1': 'protocol upgraded to 3.1',
  'Обновление до AmneziaWG 3.1': 'Upgrade to AmneziaWG 3.1',
  'Контейнер amnezia-awg2 обновляется до протокола 3.1 на месте: порт, ключ сервера и подсеть сохраняются, к конфигу добавляются параметры третьей версии. Клиенты 2.0 после этого не подключатся — их нужно перевыпустить. Перед обновлением снят снимок для отката.':
    'The amnezia-awg2 container is upgraded to protocol 3.1 in place: port, server key and subnet are kept, third-version parameters are added to the config. Existing 2.0 clients will stop connecting and must be reissued. A snapshot for rollback is taken beforehand.',
  'Обновить протокол на «{name}» до AmneziaWG 3.1?\n\nОбновление идёт внутри того же контейнера: порт, ключ сервера и подсеть сохраняются, приложение AmneziaVPN увидит 3.1 в «полном доступе».\n\nВАЖНО: выданные ранее конфиги 2.0 работать перестанут — всех клиентов придётся перевыпустить. Перед обновлением снимается снимок для отката.':
    'Upgrade the protocol on “{name}” to AmneziaWG 3.1?\n\nThe upgrade happens inside the same container: port, server key and subnet are kept, and the AmneziaVPN app will see 3.1 in “full access”.\n\nIMPORTANT: previously issued 2.0 configs will stop working — every client has to be reissued. A snapshot for rollback is taken beforehand.',
  'Обновить': 'Refresh',
  'есть': 'available',
  'образ собран не панелью': 'image not built by the panel',
  'образ собран не панелью — пересборка недоступна':
    'image not built by the panel — rebuild unavailable',
  '· образ собран не панелью': '· image not built by the panel',
  'Установка XRay': 'Installing XRay',
  'Установка AmneziaWG': 'Installing AmneziaWG',
  'Обновление XRay': 'Updating XRay',
  'Обновление AmneziaWG': 'Updating AmneziaWG',
  'Сервер собирает образ Xray-core (alpine) и запускает VLESS+REALITY на 443. Это займёт 1–3 минуты.':
    'The server builds the Xray-core image (alpine) and starts VLESS+REALITY on 443. Takes 1–3 minutes.',
  'Сервер собирает образ из amneziavpn/amneziawg-go:latest и запускает AmneziaWG. Это займёт 1–3 минуты.':
    'The server builds the image from amneziavpn/amneziawg-go:latest and starts AmneziaWG. Takes 1–3 minutes.',
  'Сервер собирает образ (openvpn + Cloak + shadowsocks) и генерирует PKI. Это займёт 1–3 минуты.':
    'The server builds the image (openvpn + Cloak + shadowsocks) and generates the PKI. Takes 1–3 minutes.',
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
  'Импортировать ещё': 'Import more',
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
  'не удалось скачать копию': 'failed to download the backup',
  'Не удалось скачать бэкап: {msg}': 'Failed to download backup: {msg}',
  'Подтвердите пароль': 'Confirm your password',
  'В бэкапе SSH-ключ панели ко всем нодам, секрет 2FA и ключи клиентов. Введите пароль от панели, чтобы скачать его.':
    'The backup holds the panel SSH key to every node, the 2FA secret and client keys. Enter your panel password to download it.',
  'Восстановление заменит все данные панели, включая учетную запись администратора. Введите пароль от панели, чтобы продолжить.':
    'Restoring replaces all panel data, including the admin account. Enter your panel password to continue.',
  'Продолжить': 'Continue',
  'Чтобы отключить, введите пароль от панели и текущий код из приложения-аутентификатора.':
    'To turn it off, enter your panel password and the current code from the authenticator app.',
  'не удалось узнать': 'unknown',
  'Подтвердить': 'Confirm',
  'Ссылка «Полного доступа» содержит SSH-ключ управления сервером (по сути root). Введите пароль от панели, чтобы продолжить.':
    'The full-access link contains the server management SSH key (effectively root). Enter your panel password to continue.',
  'Экспорт полного доступа отклонён': 'Full-access export denied',
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
  'AmneziaWG Legacy': 'AmneziaWG Legacy',
  'Выдан AmneziaWG Legacy': 'AmneziaWG Legacy issued',
  'Отозван AmneziaWG Legacy': 'AmneziaWG Legacy revoked',
  'Перевыпущен AmneziaWG Legacy': 'AmneziaWG Legacy reissued',
  'AmneziaWG Legacy на паузе': 'AmneziaWG Legacy paused',
  'AmneziaWG Legacy возобновлён': 'AmneziaWG Legacy resumed',
  'Развёрнут AmneziaWG': 'AmneziaWG deployed',
  'Обновлён AmneziaWG': 'AmneziaWG updated',
  'AmneziaWG взят под управление': 'AmneziaWG taken under management',
  'AmneziaWG на паузе': 'AmneziaWG paused',
  'AmneziaWG возобновлён': 'AmneziaWG resumed',
  'Выдан OpenVPN': 'OpenVPN issued',
  'Отозван OpenVPN': 'OpenVPN revoked',
  'Перевыпущен OpenVPN': 'OpenVPN reissued',
  'Развёрнут OpenVPN/Cloak': 'OpenVPN/Cloak deployed',
  'Пересобран OpenVPN/Cloak': 'OpenVPN/Cloak rebuilt',
  'OpenVPN на паузе': 'OpenVPN paused',
  'OpenVPN возобновлён': 'OpenVPN resumed',
  'Выдан XRay': 'XRay issued',
  'Отозван XRay': 'XRay revoked',
  'Перевыпущен XRay': 'XRay reissued',
  'XRay на паузе': 'XRay paused',
  'XRay возобновлён': 'XRay resumed',
  'Развёрнут XRay': 'XRay deployed',
  'Обновлён XRay': 'XRay updated',
  'Добавлен сервер': 'Server added',
  'Удалён сервер': 'Server deleted',
  'Экспорт полного доступа': 'Full-access export',
  'Восстановление из бэкапа': 'Restore from backup',
  'Вход выполнен': 'Signed in',
  'Неудачный вход': 'Failed login',
  'Неудачный вход (2FA)': 'Failed login (2FA)',
  'Вход заблокирован (лимит)': 'Login blocked (rate limit)',
  'Блокировка входа (брутфорс)': 'Login lockout (brute force)',
  'Смена пароля': 'Password change',
  'Host-ключ ноды изменился': "Node host key changed",
  'Откат конфига AmneziaWG': 'AmneziaWG config rollback',
  'Откат конфига XRay': 'XRay config rollback',
  'Откат конфига OpenVPN': 'OpenVPN config rollback',
  'Включена 2FA': '2FA enabled',
  'Отключена 2FA': '2FA disabled',

  // --- дашборд ---
  'серверов онлайн': 'servers online',
  'клиентов онлайн': 'clients online',
  'суммарный трафик': 'total traffic',
  'с запуска нод': 'since node start',
  'Сумма счётчиков всех нод с момента их последнего запуска (сбрасывается при рестарте контейнера) — равна сумме столбца «Трафик» ниже':
    'Sum of every node’s counters since it last started (resets on container restart) — equals the sum of the “Traffic” column below',
  'Клиентов онлайн за 24 ч': 'Clients online (24h)',
  'Трафик за 24 ч': 'Traffic (24h)',
  'Трафик': 'Traffic',
  'Клиентов онлайн': 'Clients online',
  'интервал': 'interval',
  'выделите период мышью для приближения': 'drag to zoom into a period',
  'Сбросить приближение': 'Reset zoom',
  'зум': 'zoom',
  'ч': 'h',
  'дн': 'd',
  'мин': 'min',
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
  'интерфейс': 'interface',
  'Ошибка': 'Error',

  // --- общее / мелочи ---
  'загрузка…': 'loading…',
  'необязательно': 'optional',
  'неизвестно': 'unknown',
  'новее': 'newer',
  // кнопка обновления версии контейнера (а не "Обновить" = Refresh у списков)
  'Обновить версию': 'Update',

  // --- format.ts: рукопожатие и аптайм ---
  'нет': 'never',
  'только что': 'just now',
  '{n} с назад': '{n}s ago',
  '{n} мин назад': '{n} min ago',
  '{n} ч назад': '{n} h ago',
  '{n} дн назад': '{n} d ago',
  '{d}д {h}ч': '{d}d {h}h',
  '{h}ч {m}м': '{h}h {m}m',
  '{m}м': '{m}m',
  // вкладки периода в окне трафика клиента
  '24ч': '24h',
  '7д': '7d',
  '14д': '14d',

  // --- установка / пересборка / откат ---
  'Не удалось получить статус, повторяем запрос...': 'Could not get the status, retrying...',
  'Не удалось получить статус, установка на ноде может продолжаться. Проверьте позже: {err}':
    'Could not get the status, the installation may still be running on the node. Check again later: {err}',
  'Пересобрать "{name}"? На ноде стоит AmneziaWG 3.0: конфиг мигрирует до 3.1, ключ сервера и порт сохраняются, но выданные конфиги клиентов работать перестанут, всех клиентов придется перевыпустить. Перед пересборкой снимается снимок для отката.':
    'Rebuild "{name}"? The node runs AmneziaWG 3.0: the config migrates to 3.1, the server key and port are kept, but issued client configs will stop working and all clients will need reissuing. A snapshot is taken before the rebuild for rollback.',
  'Не удалось скопировать, выделите ключ и скопируйте вручную':
    'Could not copy, select the key and copy it manually',

  // --- журнал действий: подписи действий ---
  'AmneziaWG обновлен до 3.1': 'AmneziaWG upgraded to 3.1',
  'Выдан AmneziaWG 3.1': 'AmneziaWG 3.1 issued',
  'Перевыпущен AmneziaWG 3.1': 'AmneziaWG 3.1 reissued',
  'Отозван AmneziaWG 3.1': 'AmneziaWG 3.1 revoked',
  'AmneziaWG 3.1 на паузе': 'AmneziaWG 3.1 paused',
  'AmneziaWG 3.1 возобновлен': 'AmneziaWG 3.1 resumed',
  'Развернут AmneziaWG 3.1': 'AmneziaWG 3.1 deployed',
  'Пересобран AmneziaWG 3.1': 'AmneziaWG 3.1 rebuilt',
  'Откат конфига AmneziaWG 3.1': 'AmneziaWG 3.1 config rollback',
  'Откат движка 3.1': '3.1 engine rollback',
  'Истек срок AmneziaWG': 'AmneziaWG expired',
  'Истек срок AmneziaWG 3.1': 'AmneziaWG 3.1 expired',
  'Истек срок AmneziaWG Legacy': 'AmneziaWG Legacy expired',
  'Истек срок OpenVPN': 'OpenVPN expired',
  'Истек срок XRay': 'XRay expired',
  'AmneziaWG на паузе за торренты': 'AmneziaWG paused for torrents',
  'AmneziaWG 3.1 на паузе за торренты': 'AmneziaWG 3.1 paused for torrents',
  'AmneziaWG Legacy на паузе за торренты': 'AmneziaWG Legacy paused for torrents',
  'OpenVPN на паузе за торренты': 'OpenVPN paused for torrents',
  'Изменена блокировка торрентов': 'Torrent blocking changed',
  'AmneziaWG и OpenVPN: торрент-трафик режется на сервере, у клиента в списке видна отметка, приходит алерт. Шифрованные торренты могут пройти, XRay не охвачен.':
    'AmneziaWG and OpenVPN: torrent traffic is dropped on the server, the client gets a mark in the list and an alert is sent. Encrypted torrents may get through, XRay is not covered.',
  'Блокировать торренты': 'Block torrents',
  'За сутки качали: {names}': 'Downloaded in the last day: {names}',
  'Правила на сервере не встали: {err}': 'Rules did not apply on the server: {err}',
  'Ставить на паузу того, кто качает': 'Pause whoever downloads them',
  'Торренты блокируются': 'Torrents are blocked',
  'Торренты блокируются, кто качает - на паузу': 'Torrents are blocked, downloaders get paused',
  'Торренты ловили {n} раз, последний раз {at}': 'Torrents caught {n} times, last at {at}',
  'и еще {n}': 'and {n} more',
  'торрент': 'torrent',
  'Задан срок клиента': 'Client expiry set',
  'Снят срок клиента': 'Client expiry cleared',
  'Массовый отзыв клиентов': 'Bulk client revoke',
  'Сервер выгружен в файл': 'Server exported to file',
  'Сервер загружен из файла': 'Server imported from file',
  'Изменены настройки алертов': 'Alert settings changed',
  'Тестовый алерт': 'Test alert',
  'Восстановление из бэкапа отклонено': 'Backup restore denied',
  'Скачан бэкап': 'Backup downloaded',
  'Скачивание бэкапа отклонено': 'Backup download denied',
  'Выход': 'Logout',
  'Аварийный сброс пароля из .env': 'Emergency password reset from .env',
  'Действует до': 'Valid until',
  'Ключ видит приватные конфиги клиентов. Кнопкой "Изменить" в списке ограничьте его нужными серверами и задайте срок.':
    'A key can read private client configs. Use "Edit" in the list to limit it to the servers it needs and set an expiry date.',
  'бессрочно': 'no expiry',
  'все серверы': 'all servers',
  'истек {date}': 'expired {date}',
  'не удалось сохранить ключ': 'failed to save the key',
  'ничего не отмечено = все серверы': 'nothing checked = all servers',
  'пусто = бессрочно': 'empty = no expiry',
  // --- каскад ---
  '+ Каскад': '+ Cascade',
  '1. Вход': '1. Entry',
  '2. Выход': '2. Exit',
  '3. Связь': '3. Link',
  '4. Установка': '4. Install',
  'Новый каскад': 'New cascade',
  'Уже в панели': 'Already in the panel',
  'Вход - сервер, к которому подключаются клиенты. Сайты его страны будут открываться с него напрямую, остальное пойдет через выход в другой стране.':
    'The entry is the server clients connect to. Sites of its country open from it directly, the rest goes through the exit in another country.',
  'Выход - сервер в другой стране, с его адреса клиенты будут выходить в интернет. Клиентов на нем не будет, можно взять пустой.':
    'The exit is a server in another country: clients reach the internet from its address. It has no clients of its own, an empty server will do.',
  'Свободных серверов на связи нет, добавьте новый.':
    'No free online servers, add a new one.',
  'Серверы, которые уже входят в каскад или не на связи, в списке не показаны.':
    'Servers already in a cascade or offline are not listed.',
  'Выполните скрипт на сервере под root: он создаст пользователя панели и поставит ее ключ. Потом нажмите «Дальше».':
    'Run the script on the server as root: it creates the panel user and installs the panel key. Then press "Next".',
  'Порт SSH': 'SSH port',
  'Скрипт': 'Script',
  'Пользователь': 'User',
  'Пароль нужен один раз: панель заходит по нему, ставит свой ключ и дальше работает по ключу.':
    'The password is used once: the panel logs in with it, installs its key and uses the key from then on.',
  'Панель добавит сервер и покажет скрипт, его надо выполнить на сервере под root.':
    'The panel adds the server and shows a script to run on it as root.',
  'Сервер пока не отвечает по ключу панели: скрипт выполнен под root ?':
    'The server does not accept the panel key yet: was the script run as root?',
  'Проверка канала: панель отправляет 20 мб со входа на выход':
    'Link test: the panel sends 20 MB from the entry to the exit',
  'Проверяю, это до минуты…': 'Testing, up to a minute…',
  'Обычный TCP': 'Plain TCP',
  '{size} за {secs} с, ~{mbps} Мбит/с': '{size} in {secs} s, ~{mbps} Mbit/s',
  'замерзает на {size}': 'stalls at {size}',
  'не проходит': 'does not pass',
  'Так режут фильтры у провайдера входа: в сеть выхода по TCP уходит только несколько десятков килобайт.':
    'This is how filters at the entry\'s provider behave: only a few dozen kilobytes of TCP get through to the exit\'s network.',
  'Ни один способ не прошел. Проверьте фаервол у провайдера выхода, собрать можно и так, но работать скорее всего не будет.':
    'Neither way passed. Check the firewall at the exit\'s provider. You can build anyway, but it will most likely not work.',
  'рекомендуется': 'recommended',
  'Шифрованный туннель, снаружи похож на обычный HTTPS. Подходит, когда TCP от входа к выходу проходит.':
    'Encrypted tunnel that looks like plain HTTPS from outside. Works when TCP from the entry to the exit passes.',
  'Голый туннель, такие фильтры его не трогают. Без шифрования: по дороге видны имена сайтов и незашифрованный трафик клиентов.':
    'Bare tunnel that such filters leave alone. No encryption: site names and clients\' unencrypted traffic are visible on the way.',
  'Собираю каскад': 'Building the cascade',
  'Каскад не собрался': 'Cascade build failed',
  'Выход: GRE-туннель и выпуск в интернет': 'Exit: GRE tunnel and internet access',
  'Выход: сервер VLESS Reality': 'Exit: VLESS Reality server',
  'маскарад, подрезка MSS, туннель принимается только от {ip}':
    'masquerade, MSS clamping, the tunnel is accepted only from {ip}',
  'порт открыт только для {ip}': 'the port is open only to {ip}',
  'Вход: шлюз каскада': 'Entry: cascade gateway',
  'сайты страны входа напрямую, остальное на выход; если выход пропадет, трафик клиентов никуда не уйдет':
    "sites of the entry's country go directly, the rest to the exit; if the exit goes down, clients' traffic goes nowhere",
  'Окно можно закрыть, установка продолжится. Ход виден в карточке входа.':
    'You can close the window, the install goes on. Progress is in the entry\'s card.',
  'Каскад собран': 'Cascade is ready',
  'Остальные сайты открываются с {ip}': 'Other sites open from {ip}',
  'Сайты страны входа идут напрямую с {ip}': "Sites of the entry's country go directly from {ip}",
  'Канал вход -> выход: ~{mbps} Мбит/с': 'Entry -> exit link: ~{mbps} Mbit/s',
  'Перезагрузку обоих серверов переживает: туннель и шлюз - службы systemd':
    'Survives a reboot of both servers: the tunnel and the gateway are systemd services',
  'Протоколов для клиентов на входе пока нет. Развернуть AmneziaWG или XRay можно в карточке сервера, меню «Ещё».':
    'The entry has no client protocols yet. Deploy AmneziaWG or XRay from the server card, "More" menu.',
  'Назад': 'Back',
  'Проверить еще раз': 'Test again',
  'Дальше': 'Next',
  'Подключаюсь…': 'Connecting…',
  'Собрать каскад': 'Build the cascade',
  'Запустить еще раз': 'Run again',
  'вход': 'entry',
  'выход': 'exit',
  'Свои клиенты этого сервера выходят в интернет с него напрямую, без каскада.':
    'Own clients of this server go to the internet from it directly, without the cascade.',
  'Чтобы завести здесь своих клиентов без каскада, разверните протокол в меню «Ещё».':
    'To have clients of its own here without the cascade, deploy a protocol from the More menu.',
  'Открыть сервер выхода': 'Open the exit server',
  'Открыть сервер входа': 'Open the entry server',
  'Проверить каскад': 'Check the cascade',
  'вход каскада': 'cascade entry',
  'вход каскада, {name}': 'cascade entry, {name}',
  'этот сервер, выход в интернет': 'this server, internet exit',
  'Проверка выхода клиентов': 'Client exit check',
  'Интернет из VPN-контейнера': 'Internet from the VPN container',
  'Клиенты выходят с этого сервера': 'Clients go out from this server',
  'Выход в интернет: {ip}': 'Internet exit: {ip}',
  'Сайты страны сервера': "Sites of the server's country",
  '{ms} мс': '{ms} ms',
  'Вход и выход за NAT хостера: на интерфейсах внутренние адреса. GRE через такой NAT обычно не проходит, это настройки сети хостера, а не панели.':
    "Both the entry and the exit are behind the host's NAT: their interfaces have private addresses. GRE usually does not pass such NAT; it is the host's network, not the panel.",
  'Выход за NAT хостера: на его интерфейсе внутренний адрес. GRE через такой NAT обычно не проходит, это настройки сети хостера, а не панели.':
    "The exit is behind the host's NAT: its interface has a private address. GRE usually does not pass such NAT; it is the host's network, not the panel.",
  'Вход за NAT хостера: на его интерфейсе внутренний адрес. GRE через такой NAT обычно не проходит, это настройки сети хостера, а не панели.':
    "The entry is behind the host's NAT: its interface has a private address. GRE usually does not pass such NAT; it is the host's network, not the panel.",
  'через выход, {ip}': 'through the exit, {ip}',
  'напрямую, {ip}': 'directly, {ip}',
  'не открывается': 'does not open',
  'Проверить не вышло: {err}': 'Could not check: {err}',
  'нет VPN-контейнеров': 'no VPN containers',
  'на сервере нет curl': 'no curl on the server',
  'Из VPN-контейнера интернет не открывается': 'No internet from the VPN container',
  'Не открывается: {list}': 'Does not open: {list}',
  'Выход работает': 'The exit works',
  'Сервер не ответил: {err}': 'The server did not respond: {err}',
  'Каскад не собрался: {err}': 'Cascade build failed: {err}',
  'Каскад собирается…': 'Cascade is being built…',
  'Подробнее': 'Details',
  'Выход {host} не отвечает: {err}': 'Exit {host} is not responding: {err}',
  'нет связи': 'no connection',
  'Язык алертов': 'Alert language',
  'шлюз на входе не запущен': 'the gateway on the entry is not running',
  'нет GRE-туннеля': 'no GRE tunnel',
  'клиенты идут мимо шлюза (tproxy выключен)': 'clients bypass the gateway (tproxy is off)',
  'Каскад не работает с {time}: {reason}': 'The cascade has been down since {time}: {reason}',
  'выход каскада не отвечает': 'cascade exit is not responding',
  'Сайты страны входа напрямую с этого сервера, остальное через выход.':
    "Sites of the entry's country go directly from this server, the rest through the exit.",
  'Весь трафик клиентов идет через выход: страна этого сервера неизвестна.':
    "All client traffic goes through the exit: this server's country is unknown.",
  'через выход интернет не открывается': 'no internet through the exit',
  'GRE-туннеля нет': 'no GRE tunnel',
  'Каскад разобран: клиенты входа снова выходят в интернет с него самого.':
    'Cascade removed: entry clients reach the internet from the entry itself again.',
  'Каскад: ход установки': 'Cascade: install progress',
  'Разобрать каскад…': 'Remove the cascade…',
  'Разобрать каскад?': 'Remove the cascade?',
  'Панель уберет шлюз и туннель с обоих серверов. Клиенты входа останутся подключенными, но в интернет пойдут с адреса самого входа.':
    'The panel removes the gateway and the tunnel from both servers. Entry clients stay connected but reach the internet from the entry\'s own address.',
  'Убрать только из панели': 'Remove from the panel only',
  'Разбираю…': 'Removing…',
  'Разобрать': 'Remove',
  'Каскад собран панелью': 'Cascade built',
  'Каскад разобран': 'Cascade removed',
  'Каскад: повторная установка': 'Cascade reinstalled',
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

function storedLang(): Lang {
  try {
    return (localStorage.getItem('acontrol_lang') as Lang) || 'ru'
  } catch {
    return 'ru'
  }
}

// текущий язык для кода вне React (format.ts). Обновляется провайдером при
// отрисовке, а компоненты с useI18n и так перерисовываются при смене языка
let currentLang: Lang = storedLang()

// eslint-disable-next-line react-refresh/only-export-components
export function getLang(): Lang {
  return currentLang
}

/** t() вне React: перевод по текущему языку (см. getLang). */
// eslint-disable-next-line react-refresh/only-export-components
export function translate(s: string, params?: Record<string, string | number>): string {
  return fill(currentLang === 'en' ? EN[s] ?? s : s, params)
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(storedLang)
  currentLang = lang
  const setLang = useCallback((l: Lang) => {
    localStorage.setItem('acontrol_lang', l)
    currentLang = l
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
