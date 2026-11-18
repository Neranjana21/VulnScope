"""Table grants applied by a migration (docs/gates/slice0-plan.md 3.10.1).

Pure statement generation is split from execution. Every failure is a
``MigrationPreconditionError``. The application role name is a module constant: there is no
command-line, configuration or process-level way to name another role.
"""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Final

from sqlalchemy import text
from sqlalchemy.engine import Connection

from vulnscope.db import role_checks

APP_ROLE: Final = "vulnscope_app"
SCHEMA: Final = "public"
CRUD: Final = ("SELECT", "INSERT", "UPDATE", "DELETE")
ALLOWED_PRIVILEGES: Final = frozenset(CRUD)  # TRUNCATE/REFERENCES/TRIGGER/MAINTAIN: never grantable
# Safety-property privileges are fixed here, not left to each migration's map: grant_statements()
# refuses any other set for these names in every migration.
FIXED_PRIVILEGES: Final[Mapping[str, frozenset[str]]] = {
    "ledger_entries": frozenset({"SELECT", "INSERT"}),
    "checkpoints": frozenset({"SELECT", "INSERT"}),
    "chain_heads": frozenset({"SELECT", "INSERT", "UPDATE"}),
    "alembic_version": frozenset(),
}
CHECKED_PRIVILEGES: Final = (*CRUD, "TRUNCATE", "REFERENCES", "TRIGGER")  # + MAINTAIN on PG17
_COLUMN_PRIVILEGES: Final = ("SELECT", "INSERT", "UPDATE", "REFERENCES")
_IDENT: Final = re.compile(r"[a-z_][a-z0-9_]{0,62}")

Relation = tuple[str, str, str]  # (schema, name, relkind)


class MigrationPreconditionError(RuntimeError):
    """A migration precondition or post-condition failed; nothing is left applied."""


def _q(ident: str) -> str:
    if not isinstance(ident, str) or not _IDENT.fullmatch(ident):
        raise MigrationPreconditionError(f"unsafe SQL identifier: {ident!r}")
    return f'"{ident}"'


def grant_statements(role: str, table_grants: Mapping[str, Sequence[str]]) -> list[str]:
    """Pure. Per table, sorted: REVOKE ALL FROM PUBLIC, REVOKE ALL FROM role, then one GRANT if
    the privilege tuple is non-empty (an empty tuple is an explicit 'role gets nothing')."""
    if "alembic_version" not in table_grants:
        raise MigrationPreconditionError(
            "map must carry an explicit 'alembic_version': () decision"
        )
    role_q = _q(role)
    out: list[str] = []
    for table in sorted(table_grants):
        privs = tuple(table_grants[table])
        if not set(privs) <= ALLOWED_PRIVILEGES or len(set(privs)) != len(privs):
            raise MigrationPreconditionError(
                f"{table}: privileges {privs!r} are not a duplicate-free subset of "
                f"{sorted(ALLOWED_PRIVILEGES)}"
            )
        fixed = FIXED_PRIVILEGES.get(table)
        if fixed is not None and set(privs) != fixed:
            raise MigrationPreconditionError(
                f"{table}: privileges must be exactly {sorted(fixed)}, got {sorted(privs)}"
            )
        rel = f"{_q(SCHEMA)}.{_q(table)}"
        out.append(f"REVOKE ALL ON TABLE {rel} FROM PUBLIC")
        out.append(f"REVOKE ALL ON TABLE {rel} FROM {role_q}")
        if privs:
            out.append(f"GRANT {', '.join(privs)} ON TABLE {rel} TO {role_q}")
    return out


def require_app_role(conn: Connection, role: str) -> None:
    """First database access of upgrade(); runs before any DDL."""
    if conn.execute(text("SELECT current_user")).scalar_one() == role:
        raise MigrationPreconditionError(
            f"migrations must not run as the app role {role!r}. No DDL was applied."
        )
    violations = role_checks.role_violations(conn, role)
    if violations is None:
        raise MigrationPreconditionError(
            f"migration requires database role {role!r} to exist, but it is not in pg_roles. "
            "No DDL was applied. infra/postgres/init-roles.sql creates it on first container "
            "boot; on an existing disposable dev volume run 'docker compose -p vulnscope "
            "-f docker-compose.dev.yml down -v' and start again, or create the role by hand "
            "with LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION."
        )
    if violations:
        raise MigrationPreconditionError(
            f"database role {role!r} is not the least-privilege app role: "
            + "; ".join(violations)
            + ". Table GRANTs would not constrain it. Refusing to migrate. No DDL was applied."
        )


def list_relations(conn: Connection) -> frozenset[Relation]:
    """Tables, partitioned tables, views, matviews, sequences and foreign tables outside the
    system schemas. alembic_version is included."""
    rows = conn.execute(
        text(
            "SELECT CAST(n.nspname AS text), CAST(c.relname AS text), CAST(c.relkind AS text) "
            "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
            "WHERE c.relkind IN ('r','p','v','m','S','f') "
            "AND n.nspname NOT IN ('pg_catalog','information_schema') "
            "AND n.nspname NOT LIKE 'pg\\_toast%' AND n.nspname NOT LIKE 'pg\\_temp\\_%'"
        )
    )
    return frozenset((str(s), str(n), str(k)) for s, n, k in rows)


def require_grant_decision_for_new_relations(
    before: frozenset[Relation],
    after: frozenset[Relation],
    table_grants: Mapping[str, Sequence[str]],
) -> None:
    """Runtime deny-by-default. Only ordinary or partitioned tables in public that appear in the
    map may be created; anything else needs a conscious decision (extend the helper). A map entry
    naming a table that does not exist also fails."""
    bad = sorted(
        f"{s}.{n} (relkind {k})"
        for s, n, k in after - before
        if not (s == SCHEMA and k in ("r", "p") and n in table_grants)
    )
    stale = sorted(set(table_grants) - {n for s, n, _ in after if s == SCHEMA})
    if bad or stale:
        raise MigrationPreconditionError(
            f"no grant decision for new relation(s) {bad}; map names missing table(s) {stale}. "
            "A new relation needs a conscious decision: extend the helper."
        )


def apply_statements(conn: Connection, statements: Sequence[str]) -> None:
    for stmt in statements:
        conn.execute(text(stmt))


def verify_effective_privileges(
    conn: Connection, role: str, table_grants: Mapping[str, Sequence[str]]
) -> None:
    """Last statement of upgrade(), same transaction: any mismatch raises and rolls everything
    back. Checks the EFFECTIVE state, so it also catches what REVOKE cannot remove (a privilege
    granted by a third role, inherited rights, column ACLs)."""
    role_oid = conn.execute(
        text(
            "SELECT CAST(oid AS bigint) FROM pg_catalog.pg_roles "
            "WHERE rolname = CAST(:r AS name)"
        ),
        {"r": role},
    ).scalar_one_or_none()
    if role_oid is None:
        raise MigrationPreconditionError(f"database role {role!r} is not in pg_roles")
    version = int(conn.execute(text("SELECT current_setting('server_version_num')")).scalar_one())
    checked = (*CHECKED_PRIVILEGES, "MAINTAIN") if version >= 170000 else CHECKED_PRIVILEGES
    problems: list[str] = []
    for table in sorted(table_grants):
        wanted = set(table_grants[table])
        params = {"rel": f"{_q(SCHEMA)}.{_q(table)}", "r": role}
        owner = conn.execute(
            text(
                "SELECT CAST(c.relowner AS bigint), c.relowner = "
                "(SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user) "
                "FROM pg_catalog.pg_class c WHERE c.oid = to_regclass(CAST(:rel AS text))"
            ),
            params,
        ).one_or_none()
        if owner is None:
            problems.append(f"{table}: table does not exist")
            continue
        owner_oid, owned_by_migrator = owner
        if not owned_by_migrator:
            problems.append(f"{table}: not owned by the migrating role")
        for priv in checked:
            has = conn.execute(
                text(
                    "SELECT has_table_privilege(CAST(:r AS name), CAST(:rel AS text), "
                    "CAST(:p AS text))"
                ),
                {**params, "p": priv},
            ).scalar_one()
            if bool(has) != (priv in wanted):
                problems.append(f"{table}: {role} {'has' if has else 'lacks'} {priv}")
        for priv in _COLUMN_PRIVILEGES:
            has = conn.execute(
                text(
                    "SELECT has_any_column_privilege(CAST(:r AS name), CAST(:rel AS text), "
                    "CAST(:p AS text))"
                ),
                {**params, "p": priv},
            ).scalar_one()
            if bool(has) != (priv in wanted):
                problems.append(f"{table}: column-level {priv} for {role} is {bool(has)}")
        column_acls = conn.execute(
            text(
                "SELECT count(*) FROM pg_catalog.pg_attribute "
                "WHERE attrelid = to_regclass(CAST(:rel AS text)) AND attacl IS NOT NULL"
            ),
            params,
        ).scalar_one()
        if column_acls:
            problems.append(f"{table}: {column_acls} column ACL(s) present")
        entries = conn.execute(
            text(
                "SELECT CAST(a.grantee AS bigint), CAST(a.grantor AS bigint), a.is_grantable "
                "FROM pg_catalog.pg_class c, pg_catalog.aclexplode(c.relacl) a "
                "WHERE c.oid = to_regclass(CAST(:rel AS text))"
            ),
            {"rel": params["rel"]},
        )
        for grantee, grantor, grantable in entries:
            if grantee == 0:
                problems.append(f"{table}: a PUBLIC grant exists")
            elif grantee not in (owner_oid, role_oid):
                problems.append(f"{table}: unexpected grantee oid {grantee}")
            if grantor != owner_oid:
                problems.append(f"{table}: a grant was made by a role other than the owner")
            if grantable:
                problems.append(f"{table}: a grant carries GRANT OPTION")
    if problems:
        raise MigrationPreconditionError(
            "effective privileges differ from the grant map: " + "; ".join(sorted(set(problems)))
        )


def require_disposable_or_empty_ledger(conn: Connection) -> None:
    """Used by a downgrade that drops the ledger: refuse unless the database carries the
    dev-disposable marker, or ledger_entries is absent or empty."""
    marked = conn.execute(
        text("SELECT coalesce(current_setting('vulnscope.env', true), '') = 'dev-disposable'")
    ).scalar_one()
    if marked:
        return
    # Two statements: a table named in FROM is resolved at parse time, so one combined
    # expression would fail with 'relation does not exist' when the table is absent.
    if conn.execute(text("SELECT to_regclass('public.ledger_entries') IS NULL")).scalar_one():
        return
    if conn.execute(text("SELECT EXISTS (SELECT 1 FROM public.ledger_entries)")).scalar_one():
        raise MigrationPreconditionError(
            "refusing to downgrade: database is not marked dev-disposable "
            "and the ledger is non-empty"
        )
