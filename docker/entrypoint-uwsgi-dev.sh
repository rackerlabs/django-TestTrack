#!/bin/sh

set -e  # needed to handle "exit" correctly

. /secret-file-loader.sh


cd /app || exit

# Full list of uwsgi options: https://uwsgi-docs.readthedocs.io/en/latest/Options.html
# --lazy-apps required for debugging --> https://uwsgi-docs.readthedocs.io/en/latest/articles/TheArtOfGracefulReloading.html?highlight=lazy-apps#preforking-vs-lazy-apps-vs-lazy

DD_UWSGI_LOGFORMAT_DEFAULT='[pid: %(pid)|app: -|req: -/-] %(addr) (%(dd_user)) {%(vars) vars in %(pktsize) bytes} [%(ctime)] %(method) %(uri) => generated %(rsize) bytes in %(msecs) msecs (%(proto) %(status)) %(headers) headers in %(hsize) bytes (%(switches) switches on core %(core))'

if [ "${DD_DEBUG}" = "True" ]; then
  echo "Debug mode enabled, reducing # of processes and threads to 1"
  DD_UWSGI_NUM_OF_PROCESSES=1
  DD_UWSGI_NUM_OF_THREADS=1
fi

exec uwsgi \
  "--${DD_UWSGI_MODE}" "${DD_UWSGI_ENDPOINT}" \
  --protocol uwsgi \
  --wsgi dojo.wsgi:application \
  --enable-threads \
  --processes "${DD_UWSGI_NUM_OF_PROCESSES:-2}" \
  --threads "${DD_UWSGI_NUM_OF_THREADS:-2}" \
  --reload-mercy 1 \
  --worker-reload-mercy 1 \
  --py-autoreload 1 \
  --buffer-size="${DD_UWSGI_BUFFER_SIZE:-8192}" \
  --lazy-apps \
  --touch-reload="/app/dojo/setting/settings.py" \
  --logformat "${DD_UWSGI_LOGFORMAT:-$DD_UWSGI_LOGFORMAT_DEFAULT}"
