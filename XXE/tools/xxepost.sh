#!/usr/bin/env bash
# Usage: ./xxepost.sh https://target.tld/endpoint payload.xml 'Header: Value'
set -euo pipefail

TARGET="${1:-}"
PAYLOAD="${2:-}"
HEADER="${3:-}"

if [[ -z "$TARGET" || -z "$PAYLOAD" ]]; then
  echo "Usage: $0 https://target.tld/endpoint payload.xml ['Header: Value']" >&2
  exit 1
fi

curl -sk -X POST "$TARGET" \
  -H "Content-Type: application/xml" \
  ${HEADER:+-H "$HEADER"} \
  --data-binary @"$PAYLOAD" -D -

