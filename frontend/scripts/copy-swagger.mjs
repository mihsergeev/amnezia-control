// Кладёт ассеты Swagger UI в public/swagger, чтобы страница /api/docs грузила их
// С НАШЕГО origin, а не с внешнего CDN. Так задумано: у панели строгая CSP
// (script-src 'self'), а сама она нередко живёт в сетях, где сторонний CDN
// недоступен. Файлы копируются на сборке из npm-пакета и не лежат в репозитории.
import { copyFileSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const src = join(root, 'node_modules', 'swagger-ui-dist')
const dst = join(root, 'public', 'swagger')

mkdirSync(dst, { recursive: true })
for (const f of ['swagger-ui.css', 'swagger-ui-bundle.js']) {
  copyFileSync(join(src, f), join(dst, f))
}
console.log('swagger: ассеты скопированы в public/swagger')
