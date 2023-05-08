#!/bin/bash

# init database
touch /service/db.sqlite
chown www-data:www-data /service/db.sqlite
sqlite3 /service/db.sqlite < /service/src/init.sql

exec apache2-foreground