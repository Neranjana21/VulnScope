#!/bin/sh
# infra/postgres/00-init-roles.sh
# The only file inside /docker-entrypoint-initdb.d/ for this purpose; init-roles.sql is mounted
# to /opt/vulnscope/init-roles.sql, outside the auto-scanned directory. The entrypoint sources
# this file, so it must stay free of exec.
set -eu
: "${VULNSCOPE_APP_PASSWORD:?VULNSCOPE_APP_PASSWORD is required}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -f /opt/vulnscope/init-roles.sql
