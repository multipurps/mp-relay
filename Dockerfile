FROM php:8.3-cli

# gmp: MadelineProto's MTProto crypto (Diffie-Hellman, the actual math behind
# the real key exchange this service exists to do correctly) needs it.
# pgsql/pdo_pgsql: the Postgres-backed session storage.
# sockets: MTProto's underlying transport.
# ffmpeg + ffi: needed for /calls only - realtime audio conversion between
# Telegram's OGG Opus and the assistant bridge's raw PCM16 (see
# bin/server.php's CallBridge for exactly where each is used). Login-only
# routes do not touch either.
RUN apt-get update && apt-get install -y \
    libgmp-dev libpq-dev libffi-dev ffmpeg unzip git \
    && docker-php-ext-install gmp sockets pgsql pdo_pgsql \
    && docker-php-ext-configure ffi --with-ffi \
    && docker-php-ext-install ffi \
    && echo "ffi.enable=1" >> /usr/local/etc/php/conf.d/ffi.ini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app
COPY composer.json ./
RUN composer install --no-dev --no-interaction --optimize-autoloader \
    && echo '=====CLOSABLE=====' \
    && grep -rl 'interface Closable' vendor/amphp vendor/revolt 2>/dev/null | xargs cat \
    && echo '=====READABLEITERABLESTREAM=====' \
    && find vendor/amphp/byte-stream -iname 'ReadableIterableStream.php' | xargs cat \
    && echo '=====PIPELINEQUEUE=====' \
    && find vendor/amphp/pipeline -iname 'Queue.php' | xargs cat \
    && echo '=====DONE====='
COPY . .

EXPOSE 10000
CMD ["php", "bin/server.php"]
