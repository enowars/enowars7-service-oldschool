#!/bin/bash

# init database
touch /service/db/db.sqlite
chown www-data:www-data /service/db
chown www-data:www-data /service/db/db.sqlite
sqlite3 /service/db/db.sqlite < /service/init.sql

exec apache2-foreground