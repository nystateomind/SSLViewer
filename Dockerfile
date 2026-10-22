# SSL Viewer - Docker Container
# PHP with Apache, OpenSSL 3.5 (native PQC/ML-KEM), and SSLyze for SSL/TLS analysis
#
# Multi-stage build: compiler toolchain is used only in the builder stage
# and is never present in the final runtime image.

# ── Stage 1: Build OpenSSL 3.5.0 ────────────────────────────────────────────
FROM debian:bookworm-slim AS builder

# OpenSSL 3.5.0 - first release with native ML-KEM / X25519MLKEM768 support
# (3.4.x requires the external oqs-provider; 3.5+ has it built-in)
ARG OPENSSL_VERSION=3.5.0
ARG OPENSSL_SHA256=344d0a79f1a9b08029b0744e2cc401a43f9c90acd1044d09a530b4885a8e9fc0

RUN apt-get update && apt-get install -y \
    build-essential \
    ca-certificates \
    zlib1g-dev \
    wget \
    perl \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Download, verify checksum, build
RUN wget -nv "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" \
    && echo "${OPENSSL_SHA256}  openssl-${OPENSSL_VERSION}.tar.gz" | sha256sum -c - \
    && tar -xzf "openssl-${OPENSSL_VERSION}.tar.gz" \
    && cd "openssl-${OPENSSL_VERSION}" \
    && ./config --prefix=/usr/local/openssl --openssldir=/usr/local/openssl shared zlib \
    && make -j"$(nproc)" \
    && make install_sw \
    && cd .. \
    && rm -rf "openssl-${OPENSSL_VERSION}" "openssl-${OPENSSL_VERSION}.tar.gz"

# ── Stage 2: Runtime image ───────────────────────────────────────────────────
# PHP 8.5.12 - patches CVE-2026-109618 and CVE-2026-109619 (PHP2Shell)
FROM php:8.5.12-apache

# Copy only the compiled OpenSSL artifacts from builder (no compiler in final image)
COPY --from=builder /usr/local/openssl /usr/local/openssl

# Install runtime dependencies only (no build-essential, wget, perl, make)
RUN apt-get update && apt-get install -y \
    libcurl4-openssl-dev \
    python3 \
    python3-pip \
    python3-venv \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Register the new OpenSSL shared libs and make it the default CLI binary
RUN { \
        echo "/usr/local/openssl/lib"; \
        echo "/usr/local/openssl/lib64"; \
    } >> /etc/ld.so.conf.d/openssl-3.5.conf \
    && ldconfig \
    && update-alternatives --install /usr/bin/openssl openssl /usr/local/openssl/bin/openssl 100

# Rebuild PHP's curl extension against the new OpenSSL
RUN docker-php-ext-install curl

# Install SSLyze (pinned) in an isolated venv
ARG SSLYZE_VERSION=6.3.1
RUN python3 -m venv /opt/sslyze-env \
    && /opt/sslyze-env/bin/pip install --upgrade pip \
    && /opt/sslyze-env/bin/pip install "sslyze==${SSLYZE_VERSION}"

# Symlink sslyze into PATH
RUN ln -s /opt/sslyze-env/bin/sslyze /usr/local/bin/sslyze

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Suppress Apache ServerName warning
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf

# PHP security hardening + CVE-2026-109619 mitigation (session.upload_progress)
RUN { \
    echo "expose_php = Off"; \
    echo "display_errors = Off"; \
    echo "log_errors = On"; \
    echo "error_log = /var/log/apache2/php_errors.log"; \
    echo "session.upload_progress.enabled = Off"; \
} > /usr/local/etc/php/conf.d/security.ini

# Set working directory
WORKDIR /var/www/html

# Copy application files (key.pem, cert.pem, server.log excluded via .dockerignore)
COPY src/ .

# Remove any sensitive files that may have slipped through .dockerignore
RUN rm -f /var/www/html/key.pem \
          /var/www/html/cert.pem \
          /var/www/html/server.log

# Set proper permissions
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html \
    && chmod 640 /var/www/html/*.php

# Expose port 80
EXPOSE 80
