FROM python:3.14-slim

WORKDIR /srv

# Зависимости ставим строго из lock-файла с хэшами: сборка образа повторяема, и
# новый мажор библиотеки не приезжает сам. Обновление lock - в README, раздел
# Development. Сам пакет панели потом без зависимостей.
COPY pyproject.toml requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY app ./app
RUN pip install --no-cache-dir --no-deps .

COPY alembic.ini ./
COPY alembic ./alembic

# пользователь панели: entrypoint отдает ему /data и запускает процесс от него
RUN useradd --system --uid 10001 --home-dir /data --no-create-home --shell /usr/sbin/nologin acontrol
COPY docker-entrypoint.sh /usr/local/bin/acontrol-entrypoint
RUN chmod 0755 /usr/local/bin/acontrol-entrypoint
ENTRYPOINT ["/usr/local/bin/acontrol-entrypoint"]

EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
