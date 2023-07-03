FROM ubuntu:20.04

RUN apt update && apt install -y nginx php-fpm php-sqlite3 sqlite3 default-mysql-client unzip php-mysql php-dom

COPY www /service
RUN chown -R www-data:www-data /service

COPY nginx.conf /etc/nginx/nginx.conf

COPY entrypoint.sh /root
RUN chmod +x /root/entrypoint.sh

COPY php.ini /etc/php/7.4/fpm/php.ini

WORKDIR /service

ENV COMPOSER_ALLOW_SUPERUSER=1
COPY --from=composer /usr/bin/composer /usr/bin/composer
RUN composer install --no-dev --optimize-autoloader

RUN composer require erusev/parsedown

ENV TZ=UTC
RUN ln -sf /usr/share/zoneinfo/$TZ /etc/localtime
RUN echo $TZ > /etc/timezone

ENTRYPOINT /root/entrypoint.sh
