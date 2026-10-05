#!/bin/sh
set -e
mkdir -p /var/log/nginx /var/run/fail2ban /var/lib/fail2ban
touch /var/log/nginx/access.log /var/log/nginx/error.log
fail2ban-server -b -x || echo "AVISO: fail2ban no pudo iniciar, nginx sigue sirviendo igual"
exec nginx -g 'daemon off;'
