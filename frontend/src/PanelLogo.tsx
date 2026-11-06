import { useState } from 'react'

export function PanelLogo({ src, className, alt = '' }: {
  src: string | null | undefined
  className: string
  alt?: string
}) {
  const [failed, setFailed] = useState<string>()
  if (src === undefined) return <span className={className} aria-hidden="true" />
  const custom = src !== null && src !== failed
  return (
    <img
      className={`${className}${custom ? ' custom-logo' : ''}`}
      src={custom ? src : '/logo.png'}
      alt={alt}
      onError={custom ? () => setFailed(src) : undefined}
    />
  )
}
