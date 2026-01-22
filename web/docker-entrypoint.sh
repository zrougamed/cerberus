#!/bin/sh
set -e

# Default Cerberus backend URL if not provided
CERBERUS_BACKEND=${CERBERUS_BACKEND:-http://cerberus:8080/api/v1/}

# Ensure trailing slash for proxy_pass
case "$CERBERUS_BACKEND" in
  */) ;;
  *) CERBERUS_BACKEND="$CERBERUS_BACKEND/" ;;
esac

# Replace placeholder in nginx config
sed -i "s|CERBERUS_BACKEND|$CERBERUS_BACKEND|g" /etc/nginx/conf.d/default.conf

echo "Cerberus UI starting with backend: $CERBERUS_BACKEND"

# Start nginx
exec nginx -g 'daemon off;'
