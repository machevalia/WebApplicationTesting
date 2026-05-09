# A two-process container that reproduces a classic CL.TE smuggling setup:
#   front  : haproxy 2.0 (uses Content-Length, ignores Transfer-Encoding)
#   back   : node http server that prefers Transfer-Encoding when both present
FROM haproxy:2.0-alpine

USER root
RUN apk add --no-cache nodejs npm bash

WORKDIR /app
COPY back.js .
COPY haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg
COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 80
CMD ["/start.sh"]
