#!/usr/bin/env bash
set -e
node /app/back.js &
exec haproxy -f /usr/local/etc/haproxy/haproxy.cfg
