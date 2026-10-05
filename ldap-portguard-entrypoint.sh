#!/bin/sh
set -e
apk add --no-cache iptables >/dev/null

# Limita a 20 conexiones NUEVAS por minuto por IP de origen hacia el puerto LDAPS (636)
iptables -A INPUT -p tcp --dport 636 -m conntrack --ctstate NEW -m recent --set --name ldaps_limit
iptables -A INPUT -p tcp --dport 636 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 20 --name ldaps_limit -j DROP

echo "Reglas de iptables aplicadas sobre el namespace de red de openldap:"
iptables -L INPUT -n -v
tail -f /dev/null
