# ── LukitaPort v2.0 Dockerfile ──────────────────────────────────────────────
# Base: python:3.11-slim
# Includes: nmap, chromium deps for Playwright, all Python packages.

FROM python:3.11-slim AS base

# ── System deps ───────────────────────────────────────────────────────────────
# nmap          — service fingerprinting
# Chromium deps — Playwright headless browser for web screenshots
# ca-certificates, curl — general networking
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        iputils-ping \
        ca-certificates \
        curl \
        wget \
        # Chromium / Playwright system deps
        libnss3 \
        libatk1.0-0 \
        libatk-bridge2.0-0 \
        libcups2 \
        libdrm2 \
        libxkbcommon0 \
        libxcomposite1 \
        libxdamage1 \
        libxfixes3 \
        libxrandr2 \
        libgbm1 \
        libasound2 \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libgtk-3-0 \
        fonts-liberation \
        xvfb \
    && rm -rf /var/lib/apt/lists/*

# ── Python packages ───────────────────────────────────────────────────────────
WORKDIR /app
COPY requirements.txt .

# Browsers go to a shared path readable by the unprivileged runtime user.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install chromium --with-deps

# ── Unprivileged runtime user ─────────────────────────────────────────────────
RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin lukita

# ── Application code ──────────────────────────────────────────────────────────
COPY --chown=root:root . .

# ── Runtime config ────────────────────────────────────────────────────────────
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp \
    LUKITA_HOST=0.0.0.0 \
    LUKITA_PORT=8000

USER lukita

EXPOSE 8000

# run.py refuses to listen on 0.0.0.0 unless LUKITA_API_TOKEN is set.
CMD ["python", "run.py"]
