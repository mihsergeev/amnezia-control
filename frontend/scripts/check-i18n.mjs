// Проверка переводов: каждая РУССКАЯ строка, уходящая в t(), должна иметь
// EN-перевод в словаре EN (src/i18n.tsx). Иначе в английском UI она молча
// падает на русский ключ (ловили это не раз вручную). Запуск: npm run check-i18n
import { readdirSync, readFileSync } from 'node:fs'

const unesc = (s) => s.replace(/\\(['"\\])/g, '$1')
const hasCyrillic = (s) => /[а-яА-ЯёЁ]/.test(s)

const files = readdirSync('src', { recursive: true })
  .map((f) => String(f).replaceAll('\\', '/'))
  .filter((f) => /\.(ts|tsx)$/.test(f) && !f.endsWith('.d.ts'))
  .map((f) => 'src/' + f)

// ключи EN-словаря (левые части в блоке `const EN: Record<string,string> = {…}`)
const i18nSrc = readFileSync('src/i18n.tsx', 'utf8')
const enStart = i18nSrc.indexOf('const EN')
const enBlock = i18nSrc.slice(enStart, i18nSrc.indexOf('\n}', enStart))
const enKeys = new Set()
for (const m of enBlock.matchAll(/(?:^|\n)\s*(['"])((?:\\.|(?!\1).)*)\1\s*:/g)) {
  enKeys.add(unesc(m[2]))
}

// строки, реально уходящие в t(): литералы t('…') + значения LABELS-карт,
// которые тоже прогоняются через t() (AuditPage)
const used = new Set()
for (const file of files) {
  const src = readFileSync(file, 'utf8')
  for (const m of src.matchAll(/\bt\(\s*(['"])((?:\\.|(?!\1).)*)\1/g)) {
    used.add(unesc(m[2]))
  }
  const li = src.indexOf('const LABELS')
  if (li >= 0) {
    const block = src.slice(li, src.indexOf('\n}', li))
    for (const m of block.matchAll(/:\s*(['"])((?:\\.|(?!\1).)*)\1/g)) {
      used.add(unesc(m[2]))
    }
  }
}

// не хватает: русские строки из t(), которых нет в EN-словаре
const missing = [...used].filter((k) => hasCyrillic(k) && !enKeys.has(k)).sort()
const total = [...used].filter(hasCyrillic).length

if (missing.length) {
  console.error(`❌ i18n: ${missing.length} строк без EN-перевода (добавьте в EN в src/i18n.tsx):`)
  for (const k of missing) console.error('  • ' + k)
  process.exit(1)
}
console.log(`✓ i18n: все ${total} русских строк переведены на EN`)
