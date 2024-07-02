#!/usr/bin/env bash
set -e  # needed to handle "exit" correctly
# Run available unittests with a simple setup
cd /app || exit
python manage.py makemigrations dojo
python manage.py migrate
python manage.py test unittests -v 2
