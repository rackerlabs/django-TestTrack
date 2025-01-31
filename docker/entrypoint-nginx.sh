#!/bin/sh

set -e  # needed to handle "exit" correctly

umask 0002
if [ "${GENERATE_TLS_CERTIFICATE}" = true ]; then
  openssl req  \
      -x509 \
      -nodes \
      -days 365 \
      -newkey rsa:4096 \
      -keyout /etc/nginx/ssl/nginx.key \
      -out /etc/nginx/ssl/nginx.crt \
      -subj "/C=DE/ST=City/L=City/O=Global Security/OU=IT Department/CN=nginx"
fi

if [ "${USE_TLS}" = true ]; then
  NGINX_CONFIG="/etc/nginx/nginx_TLS.conf"
else
  NGINX_CONFIG="/etc/nginx/nginx.conf"
fi

if [ "${NGINX_METRICS_ENABLED}" = true ]; then
  sed -i "s/#stub_status/stub_status/g;" $NGINX_CONFIG
  echo "Nginx metrics are enabled"
fi

if [ "${METRICS_HTTP_AUTH_PASSWORD}" != "" ]; then
  sed -i "s/#auth_basic/auth_basic/g;" $NGINX_CONFIG
  rm -rf /etc/nginx/.htpasswd
  openssl_passwd=$(openssl passwd -apr1 "$METRICS_HTTP_AUTH_PASSWORD")
  echo "$METRICS_HTTP_AUTH_USER":"$openssl_passwd" >> /etc/nginx/.htpasswd
  echo "Basic auth is on for user ${HTTP_AUTH_LOGIN}..."
else
  echo "Basic auth is off (HTTP_AUTH_PASSWORD not provided)"
fi

echo "uwsgi_pass ${DD_UWSGI_PASS};" > /run/defectdojo/uwsgi_pass
echo "server ${DD_UWSGI_HOST}:${DD_UWSGI_PORT};" > /run/defectdojo/uwsgi_server

exec nginx -c $NGINX_CONFIG -g "daemon off;"
