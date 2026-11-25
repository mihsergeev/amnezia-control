# Base image by digest: a tag on Docker Hub moves, so CI scan and release would
# otherwise build from different bases. Bump the digest deliberately.
#
# The panel wheel is built in its own stage by hatchling installed from a
# hash-locked file: with build isolation pip would fetch the latest hatchling
# and its dependencies without hashes, and they write the package that ships.
FROM python:3.14-slim@sha256:22eafb370920ad8b429e0aec3fff433e0669968519f5d60469d83729c138b28b AS wheel
WORKDIR /src
COPY requirements-build.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements-build.lock
COPY pyproject.toml ./
COPY app ./app
RUN pip wheel --no-cache-dir --no-deps --no-build-isolation -w /wheels .

FROM python:3.14-slim@sha256:22eafb370920ad8b429e0aec3fff433e0669968519f5d60469d83729c138b28b

# Apply Debian security updates the pinned base image does not have yet (zlib,
# zstd: CVE-2026-124851). Drop a package here once a newer base digest has it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade zlib1g libzstd1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv

# Зависимости ставим строго из lock-файла с хэшами: сборка образа повторяема, и
# новый мажор библиотеки не приезжает сам. Обновление lock - в README, раздел
# Development. Сам пакет панели потом без зависимостей.
COPY pyproject.toml requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY --from=wheel /wheels /tmp/wheels
RUN pip install --no-cache-dir --no-deps /tmp/wheels/*.whl && rm -rf /tmp/wheels

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
