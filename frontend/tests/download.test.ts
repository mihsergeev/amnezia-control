import assert from 'node:assert/strict'
import { test } from 'node:test'
import { attachmentFilename } from '../src/download.ts'

test('decodes UTF-8 filenames with precedence over ASCII', () => {
  const name = 'Тестовый-узел.acontrol-server.json'
  const header = `attachment; filename="server.acontrol-server.json"; filename*=UTF-8''${encodeURIComponent(name)}`
  assert.equal(attachmentFilename(header, 'fallback.json'), name)
})

test('keeps regular filenames and falls back from an invalid extension', () => {
  assert.equal(attachmentFilename('attachment; filename="backup.tar.gz"', 'fallback'), 'backup.tar.gz')
  assert.equal(attachmentFilename("attachment; filename=server.json; filename*=UTF-8''%XX", 'fallback'), 'server.json')
  assert.equal(attachmentFilename('attachment', 'fallback'), 'fallback')
})
