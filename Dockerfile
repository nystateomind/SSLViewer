# SSL Viewer - Docker Container
# PHP with Apache, OpenSSL, cURL, and SSLyze for SSL/TLS certificate analysis

FROM php:8.2-apache

# Install required system packages and PHP extensions
RUN apt-get update && apt-get install -y \
    openssl \
    libcurl4-openssl-dev \
    python3 \
    python3-pip \
    python3-venv \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Install PHP extensions
RUN docker-php-ext-install curl

# Create a virtual environment and install SSLyze
RUN python3 -m venv /opt/sslyze-env \
    && /opt/sslyze-env/bin/pip install --upgrade pip \
    && /opt/sslyze-env/bin/pip install sslyze

# Create symlink so sslyze is available in PATH
RUN ln -s /opt/sslyze-env/bin/sslyze /usr/local/bin/sslyze

# Enable Apache mod_rewrite (optional, for future URL rewriting needs)
RUN a2enmod rewrite

# Set ServerName to suppress Apache warning
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf

# Set working directory
WORKDIR /var/www/html

# Copy application files
COPY src/ .

# Set proper permissions
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

# Expose port 80
EXPOSE 80
