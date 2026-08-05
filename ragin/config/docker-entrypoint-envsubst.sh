#!/bin/sh
# Inject RAGIN_API_KEY into the nginx config at container start.
# Runs as part of the official nginx entrypoint (/docker-entrypoint.d/*.sh).
# Only ${RAGIN_API_KEY} is substituted; all nginx $vars are left untouched.
set -eu

if [ -z "${RAGIN_API_KEY:-}" ]; then
    echo "ERROR: RAGIN_API_KEY is not set — nginx /v1/ auth would be locked open" >&2
    exit 1
fi

envsubst '${RAGIN_API_KEY}' \
    < /etc/nginx/nginx.conf.template \
    > /etc/nginx/nginx.conf

echo "RAGIN: injected RAGIN_API_KEY into /etc/nginx/nginx.conf"
