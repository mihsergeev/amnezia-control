// Инициализация Swagger UI ОТДЕЛЬНЫМ файлом, а не инлайн-скриптом на странице:
// CSP панели — script-src 'self' без 'unsafe-inline', поэтому инлайн был бы
// заблокирован (именно на этом белела штатная страница доков FastAPI).
// BaseLayout выбран намеренно: он не требует swagger-ui-standalone-preset.js.
window.ui = SwaggerUIBundle({
  url: '/api/openapi.json',
  dom_id: '#swagger-ui',
  presets: [SwaggerUIBundle.presets.apis],
  layout: 'BaseLayout',
  deepLinking: true,
  persistAuthorization: true,
})
