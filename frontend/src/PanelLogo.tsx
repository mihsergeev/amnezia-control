import { useState } from 'react'

export function PanelLogo({ src, className, alt = '' }: {
  src?: string
  className: string
  alt?: string
}) {
  const [failed, setFailed] = useState<string>()
  const custom = Boolean(src && src !== failed)
  return (
    <img
      className={`${className}${custom ? ' custom-logo' : ''}`}
      src={custom ? src : '/logo.png'}
      alt={alt}
      onError={custom ? () => setFailed(src) : undefined}
    />
  )
}
