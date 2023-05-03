FROM php:7.4-apache

RUN apt-get update && \
    apt-get install -y zlib1g-dev libzip-dev && \
    docker-php-ext-install zip pdo_mysql && \
    a2enmod rewrite && \
    ln -sfT /dev/stdout /var/log/apache2/access.log
# TODO Last line allows us to see the logs in the console, can be removed in production

COPY www /var/www/html

WORKDIR /var/www/html

COPY 000-default.conf /etc/apache2/sites-available/000-default.conf

COPY --from=composer /usr/bin/composer /usr/bin/composer
RUN composer install --no-dev --optimize-autoloader

RUN chown -R www-data:www-data /var/www/html