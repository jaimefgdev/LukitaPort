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

RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install chromium --with-deps

# ── Application code ──────────────────────────────────────────────────────────
COPY . .

# ── Runtime config ────────────────────────────────────────────────────────────
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

# Uvicorn with 2 workers — single-process is fine for dev; bump for prod.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--log-level", "info"]
