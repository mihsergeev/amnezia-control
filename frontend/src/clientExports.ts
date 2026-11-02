export function configFilename(name: string, extension: 'conf' | 'ovpn' | 'txt', suggested?: string): string {
  if (suggested && /^[a-zA-Z0-9_-][a-zA-Z0-9_.-]{0,100}$/.test(suggested) && suggested.toLowerCase().endsWith('.' + extension)) return suggested
  const safe = name.replace(/[^a-zA-Z0-9_-]+/g, '_').replace(/^_+|_+$/g, '')
  return `${safe || 'client'}.${extension}`
}
