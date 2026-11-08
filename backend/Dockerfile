FROM python:3.14-slim

# Apply Debian's zlib security update when the upstream image still has the older package.
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade zlib1g \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv

# Зависимости ставим строго из lock-файла с хэшами: сборка образа повторяема, и
# новый мажор библиотеки не приезжает сам. Обновление lock - в README, раздел
# Development. Сам пакет панели потом без зависимостей.
COPY pyproject.toml requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY app ./app
RUN pip install --no-cache-dir --no-deps .

# The running panel needs only its installed dependencies, not the installer or
# its vendored libraries or bootstrap wheel. Keep build-only packages out of the
# runtime image.
RUN python -m pip uninstall --yes pip \
    && python -c "import pathlib, shutil, sysconfig; shutil.rmtree(pathlib.Path(sysconfig.get_path('stdlib')) / 'ensurepip')"

COPY alembic.ini ./
COPY alembic ./alembic

# пользователь панели: entrypoint отдает ему /data и запускает процесс от него
RUN useradd --system --uid 10001 --home-dir /data --no-create-home --shell /usr/sbin/nologin acontrol
COPY docker-entrypoint.sh /usr/local/bin/acontrol-entrypoint
RUN chmod 0755 /usr/local/bin/acontrol-entrypoint
ENTRYPOINT ["/usr/local/bin/acontrol-entrypoint"]

EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
