import { useState, type CSSProperties } from 'react'
import type { LogoSize } from './api'

export function PanelLogo({ src, className, alt = '', headerSize, loginSize }: {
  src: string | null | undefined
  className: string
  alt?: string
  headerSize?: LogoSize
  loginSize?: number
}) {
  const [failed, setFailed] = useState<string>()
  if (src === undefined) return <span className={className} aria-hidden="true" />
  const custom = src !== null && src !== failed
  return (
    <img
      className={`${className}${custom ? ' custom-logo' : ''}`}
      src={custom ? src : '/logo.png'}
      alt={alt}
      style={{
        ...(headerSize && {
          '--logo-desktop-scale': headerSize.desktop / 100,
          '--logo-mobile-scale': headerSize.mobile / 100,
        }),
        ...(loginSize !== undefined && { '--logo-login-scale': loginSize / 100 }),
      } as CSSProperties}
      onError={custom ? () => setFailed(src) : undefined}
    />
  )
}
