#!/bin/bash

wait_for_database_to_be_reachable() {
    echo -n "Waiting for database to be reachable "
    failure_count=0
    DD_DATABASE_READINESS_TIMEOUT=${DD_DATABASE_READINESS_TIMEOUT:-30}
    until echo "select 1;" | python3 manage.py dbshell > /dev/null
    do 
        echo -n "."
        failure_count=$((failure_count + 1)) 
        sleep 1
        if [ $DD_DATABASE_READINESS_TIMEOUT = $failure_count ]; then
            exit 1
        fi
    done
    cat <<EOD | python manage.py shell
from django.db import connections
connections['default'].cursor()
EOD
    DB_TEST=$?
    if [[ $DB_TEST -ne 0 ]]; then
        echo "Simple database test failed with $DB_TEST"
    else
        echo "Simple database test was successful"
    fi
    return $DB_TEST 
}