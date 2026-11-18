"""Least-privilege checks for the application database role (docs/gates/slice0-plan.md 3.10.1).

``role_violations`` is shared by the migration precondition. Every query reads only world-readable
catalogs, so it needs no privilege. Closed rules, deliberately simple.
"""
from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import Connection

_ROLE_OID = "(SELECT oid FROM pg_catalog.pg_roles WHERE rolname = CAST(:r AS name))"


def role_violations(conn: Connection, role: str) -> list[str] | None:
    """None if the role does not exist; otherwise every reason it is NOT the least-privilege
    application role (an empty list means acceptable).

    * SUPERUSER, BYPASSRLS, CREATEROLE, CREATEDB, REPLICATION are forbidden; LOGIN is required;
    * any pg_auth_members row with member = role is forbidden (covers the table owner, the
      predefined pg_* roles and any ordinary group role);
    * the role owns no relation, function, schema or database;
    * the role has no CREATE on schema public or on the current database.
    """
    row = conn.execute(
        text(
            "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication, "
            "rolcanlogin FROM pg_catalog.pg_roles WHERE rolname = CAST(:r AS name)"
        ),
        {"r": role},
    ).one_or_none()
    if row is None:
        return None
    out: list[str] = []
    flags = (
        (row.rolsuper, "SUPERUSER"),
        (row.rolbypassrls, "BYPASSRLS"),
        (row.rolcreaterole, "CREATEROLE"),
        (row.rolcreatedb, "CREATEDB"),
        (row.rolreplication, "REPLICATION"),
    )
    out.extend(f"has attribute {label}" for flag, label in flags if flag)
    if not row.rolcanlogin:
        out.append("is NOLOGIN")
    groups = conn.execute(
        text(
            "SELECT CAST(pg_catalog.pg_get_userbyid(m.roleid) AS text) "
            f"FROM pg_catalog.pg_auth_members m WHERE m.member = {_ROLE_OID}"
        ),
        {"r": role},
    ).scalars()
    out.extend(f"is a member of role {g!r}" for g in groups)
    owned = conn.execute(
        text(
            f"SELECT (SELECT count(*) FROM pg_catalog.pg_class WHERE relowner = {_ROLE_OID}) + "
            f"(SELECT count(*) FROM pg_catalog.pg_proc WHERE proowner = {_ROLE_OID}) + "
            f"(SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspowner = {_ROLE_OID}) + "
            f"(SELECT count(*) FROM pg_catalog.pg_database WHERE datdba = {_ROLE_OID})"
        ),
        {"r": role},
    ).scalar_one()
    if owned:
        out.append(f"owns {owned} database object(s)")
    checks = (
        (
            "schema public",
            "SELECT has_schema_privilege(CAST(:r AS name), CAST('public' AS text), "
            "CAST('CREATE' AS text))",
        ),
        (
            "this database",
            "SELECT has_database_privilege(CAST(:r AS name), "
            "CAST(current_database() AS text), CAST('CREATE' AS text))",
        ),
    )
    for scope, sql in checks:
        if conn.execute(text(sql), {"r": role}).scalar_one():
            out.append(f"has CREATE on {scope}")
    return out
