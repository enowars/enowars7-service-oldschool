#!/bin/bash

# wait for db server to start
while ! mysqladmin ping -h"db" --silent; do
    sleep 1
done

# init database
mysql -h db -u oldschool -poldschoolpassword oldschool < /service/init.sql

/etc/init.d/nginx start
/etc/init.d/php7.4-fpm start

while true; do
	/service/cleanup.sh
	sleep 60
done &

tail -f /var/log/nginx/error.log
