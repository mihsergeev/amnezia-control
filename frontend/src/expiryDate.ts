// ISO-строка через N дней от текущего момента.
export function daysFromNowIso(days: number): string {
  return new Date(Date.now() + days * 86_400_000).toISOString()
}
