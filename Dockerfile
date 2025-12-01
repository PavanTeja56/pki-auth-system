# -------------------------
# Stage 1: Builder
# -------------------------
FROM python:3.10-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency file
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt


# -------------------------
# Stage 2: Runtime
# -------------------------
FROM python:3.10-slim

# Set timezone to UTC
ENV TZ=UTC

WORKDIR /app

# Install system dependencies + cron
RUN apt-get update && apt-get install -y \
    cron \
    tzdata \
    && ln -fs /usr/share/zoneinfo/UTC /etc/localtime \
    && dpkg-reconfigure -f noninteractive tzdata \
    && rm -rf /var/lib/apt/lists/*

# Copy dependencies from builder
COPY --from=builder /usr/local/lib/python3.10 /usr/local/lib/python3.10
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY app/ app/
COPY scripts/ scripts/
COPY cron/ cron/
COPY student_private.pem .
COPY student_public.pem .
COPY instructor_public.pem .

# Create data + cron output directories
RUN mkdir -p /data /cron

# Install cron job
RUN chmod 0644 cron/2fa-cron && crontab cron/2fa-cron

# Expose API port
EXPOSE 8080

# Start cron + server
CMD service cron start && uvicorn app.main:app --host 0.0.0.0 --port 8080
