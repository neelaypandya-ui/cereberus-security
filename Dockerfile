# Stage 1: Build Frontend
FROM node:20-alpine AS frontend-build
WORKDIR /app/frontend
COPY cereberus/frontend/package*.json ./
RUN npm ci
COPY cereberus/frontend/ ./
RUN npx vite build

# Stage 2: Python Backend + Frontend dist
FROM python:3.14-slim AS production
WORKDIR /app

# Install system dependencies (including YARA)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libyara-dev \
    yara \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt gunicorn uvicorn[standard]

# Copy backend
COPY cereberus/backend/ ./cereberus/backend/
COPY cereberus/__init__.py ./cereberus/

# Copy YARA rules
COPY cereberus/yara_rules/ ./cereberus/yara_rules/

# Copy scripts
COPY cereberus/scripts/ ./cereberus/scripts/

# Copy frontend build
COPY --from=frontend-build /app/frontend/dist ./cereberus/frontend/dist/

# Create data directories
RUN mkdir -p /app/data /app/exports /app/models /app/backups /app/quarantine_vault /app/logs

# Environment
ENV DATABASE_URL=sqlite+aiosqlite:///./data/cereberus.db
ENV AI_MODEL_DIR=/app/models
ENV EXPORT_DIR=/app/exports
ENV QUARANTINE_VAULT_DIR=/app/quarantine_vault
ENV LOG_DIR=/app/logs

EXPOSE 8000

CMD ["gunicorn", "cereberus.backend.main:app", \
     "-w", "1", \
     "-k", "uvicorn.workers.UvicornWorker", \
     "--bind", "0.0.0.0:8000", \
     "--timeout", "120"]
