#!/usr/bin/env bash
# Usage: ./cors_probe.sh https://target.tld/path /path/to/origins.txt
set -euo pipefail

TARGET="${1:-}"
LIST="${2:-}"
if [[ -z "$TARGET" || -z "$LIST" ]]; then
  echo "Usage: $0 https://target.tld/path origins.txt" >&2
  exit 1
fi

while IFS= read -r ORIGIN; do
  [[ -z "$ORIGIN" ]] && continue
  echo "\n== Origin: $ORIGIN =="
  curl -sk -o /dev/null -D - -H "Origin: $ORIGIN" "$TARGET" | \
    awk '/^Access-Control-Allow-Origin|^Access-Control-Allow-Credentials|^Access-Control-Allow-Methods|^Access-Control-Allow-Headers/ {print}'
done < "$LIST"

