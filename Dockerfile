# SSL Viewer - Docker Container
# PHP with Apache, OpenSSL 3.4 (PQC support), and SSLyze for SSL/TLS certificate analysis

# PHP 8.5.12 - patches CVE-2026-109618 and CVE-2026-109619 (PHP2Shell)
FROM php:8.5.12-apache

# Install build dependencies for OpenSSL 3.4 + runtime deps
# OpenSSL 3.2+ is required for PQC key exchange groups (X25519MLKEM768)
# Debian Bookworm's default openssl package (3.0.x) does NOT support PQC
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    perl \
    libcurl4-openssl-dev \
    python3 \
    python3-pip \
    python3-venv \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Build and install OpenSSL 3.5 from source (first version with native ML-KEM / X25519MLKEM768)
# OpenSSL 3.4.x requires the external oqs-provider for PQC; 3.5+ has it built-in
RUN wget -q https://www.openssl.org/source/openssl-3.5.0.tar.gz \
    && tar -xzf openssl-3.5.0.tar.gz \
    && cd openssl-3.5.0 \
    && ./config --prefix=/usr/local/openssl --openssldir=/usr/local/openssl shared zlib \
    && make -j"$(nproc)" \
    && make install_sw \
    && cd .. \
    && rm -rf openssl-3.5.0 openssl-3.5.0.tar.gz \
    && ldconfig

# Make the new openssl the default for shell commands (used by pqc-scan.php)
RUN update-alternatives --install /usr/bin/openssl openssl /usr/local/openssl/bin/openssl 100

# Rebuild PHP's curl extension against the new OpenSSL
RUN docker-php-ext-install curl

# Create a virtual environment and install SSLyze
RUN python3 -m venv /opt/sslyze-env \
    && /opt/sslyze-env/bin/pip install --upgrade pip \
    && /opt/sslyze-env/bin/pip install sslyze

# Create symlink so sslyze is available in PATH
RUN ln -s /opt/sslyze-env/bin/sslyze /usr/local/bin/sslyze

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Set ServerName to suppress Apache warning
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf

# PHP security hardening + CVE-2026-109619 mitigation
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

# Remove any sensitive files that may have slipped through
RUN rm -f /var/www/html/key.pem \
          /var/www/html/cert.pem \
          /var/www/html/server.log

# Set proper permissions
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html \
    && chmod 640 /var/www/html/*.php

# Expose port 80
EXPOSE 80
