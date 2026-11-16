export function awgSettingsError(err: unknown, t: (text: string, values?: Record<string, string | number>) => string): string {
  const message = err instanceof Error ? err.message : t('Ошибка')
  const busy = message.match(/^Порт (\d+)\/(\w+) уже занят: (.*?)\. Выберите для AmneziaWG другой порт\.$/)
  if (busy) return t('Порт {port}/{protocol} уже занят: {owner}. Выберите для AmneziaWG другой порт.', { port: busy[1], protocol: busy[2], owner: busy[3] })
  const transaction = message.match(/^(.*операции )([a-f0-9]{32})$/)
  if (transaction) return t(`${transaction[1]}{transaction}`, { transaction: transaction[2] })
  const missing = message.match(/^Не заданы обязательные параметры AmneziaWG: (.*)$/)
  if (missing) return t('Не заданы обязательные параметры AmneziaWG: {keys}', { keys: missing[1] })
  const field = message.match(/^([A-Za-z][A-Za-z0-9]*): (.*)$/)
  if (field) {
    const bounds = field[2].match(/^допустимые границы (\d+)\.\.(\d+)$/)
    return `${field[1]}: ${bounds ? t('допустимые границы {min}..{max}', { min: bounds[1], max: bounds[2] }) : t(field[2])}`
  }
  return t(message)
}
