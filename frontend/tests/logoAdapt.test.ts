import assert from 'node:assert/strict'
import test from 'node:test'
import { adaptLogoColor, logoBounds, logoSize } from '../src/logoAdapt.ts'

test('logo dimensions fit the box without stretching or upscaling', () => {
  assert.deepEqual(logoSize(1600, 400, 288), { width: 288, height: 72 })
  assert.deepEqual(logoSize(400, 1600, 288), { width: 72, height: 288 })
  assert.deepEqual(logoSize(20, 8, 288), { width: 20, height: 8 })
})

test('logo bounds trim transparent margins and retain antialiased edges', () => {
  const pixels = new Uint8ClampedArray(4 * 3 * 4)
  assert.equal(logoBounds(pixels, 4, 3), null)
  pixels[(4 + 1) * 4 + 3] = 255
  pixels[(4 + 2) * 4 + 3] = 80
  assert.deepEqual(logoBounds(pixels, 4, 3), {
    left: 1, top: 1, right: 3, bottom: 2, opaque: false,
  })
  pixels[(4 + 2) * 4 + 3] = 255
  assert.equal(logoBounds(pixels, 4, 3)?.opaque, true)
})

test('theme adaptation changes only colors with insufficient contrast', () => {
  assert.deepEqual(adaptLogoColor(0, 0, 0, 'light'), [0, 0, 0])
  assert.deepEqual(adaptLogoColor(255, 255, 255, 'dark'), [255, 255, 255])
  assert.ok(adaptLogoColor(0, 0, 0, 'dark')[0] >= 95)
  assert.ok(adaptLogoColor(255, 255, 255, 'light')[0] <= 133)
})
