-- infra/postgres/init-roles.sql
-- Mounted to /opt/vulnscope/init-roles.sql, OUTSIDE /docker-entrypoint-initdb.d/
-- (docs/gates/slice0-plan.md Section 3.9, fixes round-2 INFRA-2) -- never
-- auto-executed by the Postgres entrypoint's own .sql scan. Invoked
-- explicitly, exactly once, by infra/postgres/00-init-roles.sh (the only
-- file actually inside /docker-entrypoint-initdb.d/), which supplies
-- :vulnscope_app_password from VULNSCOPE_APP_PASSWORD and runs via
-- psql -f /opt/vulnscope/init-roles.sql, authenticated as the cluster's
-- initial superuser (POSTGRES_USER=vulnscope_migrator in dev).
--
-- Two-role split (design C, Section 3.10): vulnscope_migrator owns every
-- table (the only role with DDL/ALTER/DROP rights; used only by Alembic,
-- never by the running app -- see alembic/env.py). vulnscope_app is not
-- superuser, owns nothing, and is used by the running FastAPI process and
-- PostgresChainBackend.

CREATE ROLE vulnscope_app LOGIN PASSWORD :'vulnscope_app_password' NOSUPERUSER NOCREATEDB NOCREATEROLE;
-- vulnscope_migrator already exists as the bootstrap superuser in
-- dev/compose; in a managed or production Postgres it would instead be
-- provisioned as a plain, non-superuser schema owner -- out of scope for
-- this dev-only script.

-- Ledger/checkpoint tables: vulnscope_app may read and append, never
-- mutate or remove.
GRANT SELECT, INSERT ON ledger_entries TO vulnscope_app;
REVOKE UPDATE, DELETE, TRUNCATE ON ledger_entries FROM vulnscope_app;  -- explicit, even though a
                                                                        -- non-owner role already
                                                                        -- has no such privileges by
                                                                        -- default -- documents
                                                                        -- intent and survives any
                                                                        -- future accidental
                                                                        -- GRANT ALL.
GRANT SELECT, INSERT ON checkpoints TO vulnscope_app;
REVOKE UPDATE, DELETE, TRUNCATE ON checkpoints FROM vulnscope_app;

-- chain_heads: the lock target for D1's per-chain serialization (Section
-- 3.2's existing design, not a new mechanism). SELECT ... FOR UPDATE
-- requires UPDATE privilege in Postgres even though it only locks rows --
-- so vulnscope_app needs UPDATE here, and only here (never on
-- ledger_entries or checkpoints), to take that lock.
GRANT SELECT, INSERT, UPDATE ON chain_heads TO vulnscope_app;
REVOKE DELETE, TRUNCATE ON chain_heads FROM vulnscope_app;   -- rows are updated, never removed

-- Other tables (engagements, scans, findings, evidence, idempotency_keys,
-- orgs, users, api_keys) get normal CRUD grants for vulnscope_app under
-- the same two-role split; not detailed further here since the owner's
-- requirements were specifically about the ledger/checkpoint/chain_heads
-- set.
GRANT SELECT, INSERT, UPDATE, DELETE ON engagements, scans, findings, evidence, idempotency_keys,
    orgs, users, api_keys TO vulnscope_app;

-- Dev-disposable marker (owner-required safety guard, tests/integration/_guard.py):
-- lets integration tests verify, via a read-only query, that a configured
-- database URL actually points at this throwaway dev instance before any
-- destructive test proceeds. Takes effect for new sessions connecting to
-- this database, not the current one (ALTER DATABASE ... SET semantics).
ALTER DATABASE vulnscope SET vulnscope.env = 'dev-disposable';
