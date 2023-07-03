#!/bin/bash

DB_USERNAME="oldschool"
DB_PASSWORD="oldschoolpassword"
DB_HOST="db"
DB_NAME="oldschool"

mysql -u $DB_USERNAME -p$DB_PASSWORD -h $DB_HOST -D $DB_NAME -e \
"DELETE FROM course_enrollments WHERE course_id IN (SELECT id FROM courses WHERE created_at < NOW() - INTERVAL 10 MINUTE);"

mysql -u $DB_USERNAME -p$DB_PASSWORD -h $DB_HOST -D $DB_NAME -e \
"DELETE FROM users WHERE created_at < NOW() - INTERVAL 10 MINUTE;"

while IFS= read -r row; do
    path=$(realpath "/service/grades/$row")
    if [[ "$(dirname "$path")" = "/service/grades" ]]; then
        rm -rf "$path"
    fi
done < <(mysql -u $DB_USERNAME -p$DB_PASSWORD -h $DB_HOST -D $DB_NAME -e \
"SELECT filename FROM grades WHERE created_at < NOW() - INTERVAL 10 MINUTE;")

mysql -u $DB_USERNAME -p$DB_PASSWORD -h $DB_HOST -D $DB_NAME -e \
"DELETE FROM grades WHERE created_at < NOW() - INTERVAL 10 MINUTE;"

mysql -u $DB_USERNAME -p$DB_PASSWORD -h $DB_HOST -D $DB_NAME -e \
"UPDATE users SET admin_of = NULL WHERE admin_of IN (SELECT id FROM courses WHERE created_at < NOW() - INTERVAL 10 MINUTE);"

mysql -u $DB_USERNAME -p$DB_PASSWORD -h $DB_HOST -D $DB_NAME -e \
"DELETE FROM courses WHERE created_at < NOW() - INTERVAL 10 MINUTE;"
