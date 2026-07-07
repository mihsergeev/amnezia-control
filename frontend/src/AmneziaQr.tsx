import { useEffect, useState } from 'react'
import QRCode from 'qrcode'
import { useI18n } from './i18n'

// Формат анимированного QR AmneziaVPN (реверс qrCodeUtils.cpp):
// данные бьются на чанки по 850 байт; каждый кадр QR кодирует
// base64url( QDataStream[ qint16 magic=1984, quint8 chunksCount, quint8 chunkId,
// QByteArray chunk ] ), ECC LOW. Приложение при скане собирает чанки обратно.
// Обычный vpn://-QR приложение НЕ принимает (проверяет magic), поэтому нужен
// именно этот формат — даже для мелких конфигов (тогда 1 кадр).
const MAGIC = 1984
const CHUNK = 850

function b64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

function bytesToB64url(bytes: Uint8Array): string {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function framesFromData(data: Uint8Array): string[] {
  const chunksCount = Math.max(1, Math.ceil(data.length / CHUNK))
  const frames: string[] = []
  for (let j = 0; j < chunksCount; j++) {
    const off = j * CHUNK
    const chunk = data.subarray(off, Math.min(off + CHUNK, data.length))
    const len = chunk.length
    const frame = new Uint8Array(8 + len)
    frame[0] = (MAGIC >> 8) & 0xff // 0x07
    frame[1] = MAGIC & 0xff // 0xC0
    frame[2] = chunksCount & 0xff
    frame[3] = j & 0xff
    frame[4] = (len >>> 24) & 0xff
    frame[5] = (len >>> 16) & 0xff
    frame[6] = (len >>> 8) & 0xff
    frame[7] = len & 0xff
    frame.set(chunk, 8)
    frames.push(bytesToB64url(frame))
  }
  return frames
}

type Props = {
  // текст конфига: vpn://-ссылка (format 'vpn') или .conf (format 'conf')
  text: string
  format: 'vpn' | 'conf'
  size?: number
}

export function AmneziaQr({ text, format, size = 240 }: Props) {
  const { t } = useI18n()
  const [images, setImages] = useState<string[]>([])
  const [idx, setIdx] = useState(0)

  useEffect(() => {
    let alive = true
    let data: Uint8Array
    try {
      data =
        format === 'vpn'
          ? b64urlToBytes(text.replace(/^vpn:\/\//, ''))
          : new TextEncoder().encode(text)
    } catch {
      setImages([])
      return
    }
    const frames = framesFromData(data)
    Promise.all(
      frames.map((f) =>
        QRCode.toDataURL(f, {
          errorCorrectionLevel: 'L',
          margin: 1,
          width: size * 1.5,
        }),
      ),
    )
      .then((urls) => {
        if (alive) {
          setImages(urls)
          setIdx(0)
        }
      })
      .catch(() => alive && setImages([]))
    return () => {
      alive = false
    }
  }, [text, format, size])

  useEffect(() => {
    if (images.length <= 1) return
    const timer = window.setInterval(
      () => setIdx((i) => (i + 1) % images.length),
      300,
    )
    return () => window.clearInterval(timer)
  }, [images])

  if (!images.length) {
    return <span className="muted small">{t('генерация QR…')}</span>
  }
  return (
    <div className="amnezia-qr">
      <img src={images[idx]} alt="QR" width={size} height={size} />
      {images.length > 1 && (
        <div className="muted small qr-anim-note">
          {t('QR {n}/{total} · кадры меняются — держите камеру приложения', {
            n: idx + 1,
            total: images.length,
          })}
        </div>
      )}
    </div>
  )
}
