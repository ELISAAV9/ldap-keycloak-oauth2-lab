FROM nginx:1.27-alpine
RUN apk add --no-cache fail2ban iptables

# Quitamos los jails que vienen activados por defecto (sshd, etc.)
RUN rm -f /etc/fail2ban/jail.d/*.conf

RUN rm -f /var/log/nginx/access.log /var/log/nginx/error.log
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY jail.local /etc/fail2ban/jail.local
COPY filter-http-flood.conf /etc/fail2ban/filter.d/http-flood.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
