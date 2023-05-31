#!/bin/bash

# wait for db server to start
while ! mysqladmin ping -h"db" --silent; do
    sleep 1
done

# init database
mysql -h db -u oldschool -poldschoolpassword oldschool < /service/init.sql

exec apache2-foreground
