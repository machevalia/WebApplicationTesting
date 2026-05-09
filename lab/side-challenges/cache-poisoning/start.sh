#!/usr/bin/env bash
set -e
gunicorn -w 1 -b 127.0.0.1:5000 app:app &
exec nginx -g 'daemon off;'
