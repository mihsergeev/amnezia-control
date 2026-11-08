export function attachmentFilename(header: string, fallback: string): string {
  const encoded = /(?:^|;)\s*filename\*\s*=\s*UTF-8'[^']*'([^;\s]+)/i.exec(header)?.[1]
  if (encoded) {
    try {
      return decodeURIComponent(encoded)
    } catch {
      // A malformed extended filename can still have a usable ASCII fallback.
    }
  }
  const plain = /(?:^|;)\s*filename\s*=\s*(?:"([^"]+)"|([^;\s"]+))/i.exec(header)
  return plain?.[1] || plain?.[2] || fallback
}

export async function downloadResponse(response: Response, fallback: string): Promise<void> {
  const url = URL.createObjectURL(await response.blob())
  const link = document.createElement('a')
  link.href = url
  link.download = attachmentFilename(response.headers.get('Content-Disposition') || '', fallback)
  link.click()
  URL.revokeObjectURL(url)
}
