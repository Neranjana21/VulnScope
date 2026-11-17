#!/bin/sh
# infra/postgres/00-init-roles.sh
# The only file inside /docker-entrypoint-initdb.d/ for this purpose --
# init-roles.sql itself is mounted to /opt/vulnscope/init-roles.sql,
# OUTSIDE this auto-scanned directory, so the Postgres entrypoint never
# auto-executes it a second time (docs/gates/slice0-plan.md Section 3.9,
# round-2 fix for INFRA-2).
set -eu
psql -v vulnscope_app_password="${VULNSCOPE_APP_PASSWORD}" \
     --username "${POSTGRES_USER}" --dbname "${POSTGRES_DB}" \
     -f /opt/vulnscope/init-roles.sql
