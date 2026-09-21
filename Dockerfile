FROM php:8.3-cli

# gmp: MadelineProto's MTProto crypto (Diffie-Hellman, the actual math behind
# the real key exchange this service exists to do correctly) needs it.
# pgsql/pdo_pgsql: the Postgres-backed session storage.
# sockets: MTProto's underlying transport.
RUN apt-get update && apt-get install -y \
    libgmp-dev libpq-dev unzip git \
    && docker-php-ext-install gmp sockets pgsql pdo_pgsql \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app
COPY composer.json ./
RUN composer install --no-dev --no-interaction --optimize-autoloader

COPY . .

EXPOSE 10000
CMD php -S 0.0.0.0:${PORT:-10000} -t public public/index.php
