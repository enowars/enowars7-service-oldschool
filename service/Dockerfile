FROM php:8.0-apache

RUN apt-get update && \
    apt-get install -y zlib1g-dev libzip-dev sqlite3 default-mysql-client && \
    docker-php-ext-install zip pdo_mysql && \
    a2enmod rewrite && \
    ln -sfT /dev/stdout /var/log/apache2/access.log
# TODO Last line allows us to see the logs in the console, can be removed in production

COPY www /service

WORKDIR /service

COPY 000-default.conf /etc/apache2/sites-available/000-default.conf

COPY php.ini /usr/local/etc/php/php.ini

COPY --from=composer /usr/bin/composer /usr/bin/composer
RUN composer install --no-dev --optimize-autoloader

RUN composer require erusev/parsedown

RUN chown -R www-data:www-data /service

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]