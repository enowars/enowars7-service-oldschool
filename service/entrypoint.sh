#!/bin/bash

# wait for db server to start
while ! mysqladmin ping -h"db" --silent; do
    sleep 1
done

# init database
mysql -h db -u oldschool -poldschoolpassword oldschool < /service/init.sql

# run cleanup script
while true; do
	/service/cleanup.sh
	sleep 60
done &

exec apache2-foreground
