export type LogoTheme = 'light' | 'dark'
export type LogoVariants = Record<LogoTheme, string>

export const logoThemes = ['light', 'dark'] as const
export const MAX_LOGO_BYTES = 5 * 1024 * 1024
export const LOGO_TYPES = 'image/png,image/jpeg,image/webp,image/svg+xml'

const OUTPUT_SIZE = 288
const ANALYSIS_SIZE = 768
const PNG_PREFIX = 'data:image/png;base64,'

// The light page is darker than its login card, and the dark card is lighter
// than its page. Use the less favorable background for each theme.
const BACKGROUND = { light: [228, 232, 239], dark: [23, 26, 35] }
const linear = Array.from({ length: 256 }, (_, i) => {
  const s = i / 255
  return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4
})

function luminance(r: number, g: number, b: number): number {
  return 0.2126 * linear[r] + 0.7152 * linear[g] + 0.0722 * linear[b]
}

export function logoSize(width: number, height: number, limit: number) {
  const scale = Math.min(1, limit / Math.max(width, height))
  return {
    width: Math.max(1, Math.round(width * scale)),
    height: Math.max(1, Math.round(height * scale)),
  }
}

export function logoBounds(data: Uint8ClampedArray, width: number, height: number) {
  let left = width
  let top = height
  let right = 0
  let bottom = 0
  let opaque = 0
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const alpha = data[(y * width + x) * 4 + 3]
      if (!alpha) continue
      left = Math.min(left, x)
      top = Math.min(top, y)
      right = Math.max(right, x + 1)
      bottom = Math.max(bottom, y + 1)
      if (alpha >= 250) opaque++
    }
  }
  if (!right) return null
  return { left, top, right, bottom, opaque: opaque === (right - left) * (bottom - top) }
}

export function adaptLogoColor(r: number, g: number, b: number, theme: LogoTheme) {
  const [br, bg, bb] = BACKGROUND[theme]
  const background = luminance(br, bg, bb)
  const dark = theme === 'dark'
  const limit = dark ? 3 * (background + 0.05) - 0.05 : (background + 0.05) / 3 - 0.05
  const isReadable = (value: number) => dark ? value >= limit : value <= limit
  if (isReadable(luminance(r, g, b))) return [r, g, b]

  // Mix with white or black only as much as needed, preserving hue and alpha.
  const target = dark ? 255 : 0
  const mix = (channel: number, amount: number) => Math.round(channel + (target - channel) * amount)
  let low = 0
  let high = 1
  for (let i = 0; i < 8; i++) {
    const mid = (low + high) / 2
    if (isReadable(luminance(mix(r, mid), mix(g, mid), mix(b, mid)))) high = mid
    else low = mid
  }
  return [mix(r, high), mix(g, high), mix(b, high)]
}

function canvas(width: number, height: number) {
  const element = document.createElement('canvas')
  element.width = width
  element.height = height
  const context = element.getContext('2d')
  if (!context) throw new Error('canvas_unavailable')
  return { element, context }
}

async function readLogo(file: File): Promise<HTMLImageElement> {
  // SVG is decoded as an image, never inserted as markup or uploaded as SVG.
  const src = await new Promise<string>((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result))
    reader.onerror = () => reject(reader.error)
    reader.readAsDataURL(file)
  })
  const image = new Image()
  image.src = src
  await image.decode()
  if (!image.naturalWidth || !image.naturalHeight) throw new Error('empty_image')
  return image
}

export async function prepareLogo(file: File): Promise<LogoVariants> {
  const image = await readLogo(file)
  const { naturalWidth, naturalHeight } = image
  if (naturalWidth > 8192 || naturalHeight > 8192 || naturalWidth * naturalHeight > 24_000_000) {
    throw new Error('image_dimensions')
  }

  const sample = logoSize(naturalWidth, naturalHeight, ANALYSIS_SIZE)
  const analysis = canvas(sample.width, sample.height)
  analysis.context.drawImage(image, 0, 0, sample.width, sample.height)
  const pixels = analysis.context.getImageData(0, 0, sample.width, sample.height)
  const bounds = logoBounds(pixels.data, sample.width, sample.height)
  if (!bounds) throw new Error('empty_image')

  const scaleX = naturalWidth / sample.width
  const scaleY = naturalHeight / sample.height
  const cropWidth = (bounds.right - bounds.left) * scaleX
  const cropHeight = (bounds.bottom - bounds.top) * scaleY
  // Keep the artwork intact. Only a fully opaque image gets a small frame.
  const size = logoSize(cropWidth, cropHeight, OUTPUT_SIZE - 12)
  const padding = bounds.opaque ? Math.min(6, Math.ceil(Math.min(size.width, size.height) / 8)) : 0
  const original = canvas(size.width, size.height)
  original.context.drawImage(
    image, bounds.left * scaleX, bounds.top * scaleY, cropWidth, cropHeight,
    0, 0, size.width, size.height,
  )
  const clean = original.context.getImageData(0, 0, size.width, size.height)

  function render(theme: LogoTheme): string {
    const output = canvas(size.width + 2 * padding, size.height + 2 * padding)
    if (padding) {
      output.context.fillStyle = theme === 'dark' ? '#303642' : '#cad0da'
      output.context.beginPath()
      output.context.roundRect(0, 0, output.element.width, output.element.height, padding)
      output.context.fill()
      output.context.drawImage(original.element, padding, padding)
    } else {
      const adjusted = output.context.createImageData(size.width, size.height)
      adjusted.data.set(clean.data)
      for (let i = 0; i < clean.data.length; i += 4) {
        if (clean.data[i + 3] === 0) continue
        const color = adaptLogoColor(clean.data[i], clean.data[i + 1], clean.data[i + 2], theme)
        adjusted.data.set(color, i)
      }
      output.context.putImageData(adjusted, 0, 0)
    }
    const encoded = output.element.toDataURL('image/png')
    if (!encoded.startsWith(PNG_PREFIX)) throw new Error('encode_failed')
    return encoded.slice(PNG_PREFIX.length)
  }

  return { light: render('light'), dark: render('dark') }
}
