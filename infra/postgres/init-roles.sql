-- infra/postgres/init-roles.sql: roles and the dev marker ONLY.
-- No statement here may reference a table. Table privileges are applied by
-- alembic/versions/0001_initial.py (docs/gates/slice0-plan.md 3.10.1).
-- Invoked exactly once by infra/postgres/00-init-roles.sh at first container boot, as the
-- cluster's bootstrap superuser. Mounted outside /docker-entrypoint-initdb.d/ so the
-- entrypoint never runs it a second time.
-- Keep the password out of the server log: a failing CREATE ROLE would otherwise log the
-- statement text (log_min_error_statement defaults to error). These three SETs need superuser,
-- which the bootstrap session is.
SET log_min_error_statement = panic;
SET log_statement = 'none';
SET log_min_duration_statement = -1;
\getenv vulnscope_app_password VULNSCOPE_APP_PASSWORD
\getenv init_db POSTGRES_DB
CREATE ROLE vulnscope_app LOGIN PASSWORD :'vulnscope_app_password'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
ALTER DATABASE :"init_db" SET vulnscope.env = 'dev-disposable';
