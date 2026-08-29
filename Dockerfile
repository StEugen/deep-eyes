ARG PYTHON_VERSION=3.11

FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPYCACHEPREFIX=/tmp/pycache \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/home/deepeye \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        ca-certificates \
        libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY --chown=10001:10001 . /app

RUN groupadd --gid 10001 deepeye \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/deepeye deepeye \
    && mkdir -p /app/data /app/logs /app/reports /home/deepeye/.cache \
    && chown -R 10001:10001 /app/data /app/logs /app/reports /home/deepeye

USER 10001:10001

ENTRYPOINT ["python", "/app/deep_eye.py"]
CMD ["--help"]


FROM runtime AS browser

USER root
RUN python -m playwright install --with-deps chromium \
    && chmod -R a+rX /ms-playwright
USER 10001:10001
