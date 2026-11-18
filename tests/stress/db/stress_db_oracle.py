# ruff: noqa: E501
"""Independent ACL oracle for the grants-in-migration design (plan 3.10.1, stress #1).

R1 file. Deliberately imports NOTHING from vulnscope.db (no migration_grants, no
role_checks): policy comes from the invariants below and from ``Base.metadata``.
``violations()`` takes an asyncpg connection (any role that can read the catalogs)
and a role NAME, so it never needs to log in as the audited role.

Every violation string starts with a tag so tests can assert on the *reason*:
NO-DECISION, MISSING-TABLE, UNEXPECTED, MISSING, COLUMN, COLUMN-ACL, GRANTEE, GRANTOR,
GRANT-OPTION, OWNER-IS-ROLE, INHERITS-OWNER, ATTRIBUTE, MEMBER-OF, OWNS, SCHEMA-CREATE,
DB-CREATE, SEQUENCE.
"""
from __future__ import annotations

from typing import Any

from vulnscope.models import Base  # type: ignore[import-untyped]

CRUD = frozenset({"SELECT", "INSERT", "UPDATE", "DELETE"})
TABLE_PRIVS = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
COLUMN_PRIVS = ("SELECT", "INSERT", "UPDATE", "REFERENCES")

# The ledger policy, written out by hand here (a deliberate independent copy).
LEDGER_POLICY: dict[str, frozenset[str]] = {
    "ledger_entries": frozenset({"SELECT", "INSERT"}),
    "checkpoints": frozenset({"SELECT", "INSERT"}),
    "chain_heads": frozenset({"SELECT", "INSERT", "UPDATE"}),
    "alembic_version": frozenset(),
}

METADATA_TABLES: tuple[str, ...] = tuple(sorted(Base.metadata.tables))
ALL_TABLES: tuple[str, ...] = tuple(sorted({*METADATA_TABLES, "alembic_version"}))


def expected_privileges(table: str) -> frozenset[str]:
    if table in LEDGER_POLICY:
        return LEDGER_POLICY[table]
    if table in METADATA_TABLES:
        return CRUD
    raise KeyError(f"no grant decision for {table}")


def expected_map() -> dict[str, tuple[str, ...]]:
    """Table -> ordered privilege tuple, in the shape the plan's TABLE_GRANTS uses."""
    order = ("SELECT", "INSERT", "UPDATE", "DELETE")
    return {t: tuple(p for p in order if p in expected_privileges(t)) for t in ALL_TABLES}


def reference_grant_sql(role: str) -> list[str]:
    """Plain SQL that gives ``role`` exactly the policy (used on scratch roles for mutants)."""
    out = []
    for t, privs in expected_map().items():
        if privs:
            out.append(f'GRANT {", ".join(privs)} ON TABLE public."{t}" TO "{role}"')
    return out


_RELATIONS = (
    "SELECT n.nspname AS s, c.relname AS n, c.relkind::text AS k, c.oid::bigint AS oid, "
    "c.relowner::bigint AS owner_oid, pg_get_userbyid(c.relowner) AS owner "
    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE c.relkind IN ('r','p','v','m','S','f') "
    "AND n.nspname NOT IN ('pg_catalog','information_schema') "
    "AND n.nspname NOT LIKE 'pg\\_toast%' AND n.nspname NOT LIKE 'pg\\_temp\\_%' "
    "ORDER BY 1, 2"
)


async def violations(
    conn: Any,
    role: str,
    *,
    extra_grantees: frozenset[str] = frozenset(),
    check_role_level: bool = True,
) -> list[str]:
    out: list[str] = []
    ver = await conn.fetchval("SELECT current_setting('server_version_num')::int")
    privs = TABLE_PRIVS + (("MAINTAIN",) if ver >= 170000 else ())
    role_oid = await conn.fetchval("SELECT oid::bigint FROM pg_roles WHERE rolname = $1::name", role)
    if role_oid is None:
        return [f"MISSING-TABLE: role {role} does not exist"]

    rels = await conn.fetch(_RELATIONS)
    present: dict[str, Any] = {}
    for r in rels:
        if r["s"] == "public" and r["k"] in ("r", "p") and r["n"] in ALL_TABLES:
            present[r["n"]] = r
        else:
            out.append(f"NO-DECISION: no grant decision for {r['s']}.{r['n']} (relkind {r['k']})")
        if r["k"] == "S":
            for p in ("USAGE", "SELECT", "UPDATE"):
                if await conn.fetchval(
                    "SELECT has_sequence_privilege($1::name, $2::oid, $3::text)", role, r["oid"], p
                ):
                    out.append(f"SEQUENCE: {r['n']}: {role} has {p}")
    for t in ALL_TABLES:
        if t not in present:
            out.append(f"MISSING-TABLE: table {t} does not exist")

    for t, r in present.items():
        want = expected_privileges(t)
        oid = r["oid"]
        owner_oid = r["owner_oid"]
        for p in privs:
            has = await conn.fetchval(
                "SELECT has_table_privilege($1::name, $2::oid, $3::text)", role, oid, p
            )
            if has and p not in want:
                out.append(f"UNEXPECTED: {t}: {role} has {p}")
            if not has and p in want:
                out.append(f"MISSING: {t}: {role} lacks {p}")
        for p in COLUMN_PRIVS:
            has_any = await conn.fetchval(
                "SELECT has_any_column_privilege($1::name, $2::oid, $3::text)", role, oid, p
            )
            if has_any and p not in want:
                out.append(f"COLUMN: {t}: {role} has a column-level or table-level {p} that is not allowed")
            if not has_any and p in want:
                out.append(f"COLUMN: {t}: {role} has no {p} on any column although {p} is required")
        n_attacl = await conn.fetchval(
            "SELECT count(*) FROM pg_attribute WHERE attrelid = $1::oid AND attacl IS NOT NULL "
            "AND NOT attisdropped",
            oid,
        )
        if n_attacl:
            out.append(f"COLUMN-ACL: {t}: {n_attacl} column(s) carry their own ACL")
        allowed = {owner_oid, role_oid}
        extra_oids = {
            await conn.fetchval("SELECT oid::bigint FROM pg_roles WHERE rolname = $1::name", g)
            for g in extra_grantees
        }
        allowed |= {o for o in extra_oids if o is not None}
        for a in await conn.fetch(
            "SELECT a.grantee::bigint AS grantee, a.grantor::bigint AS grantor, "
            "a.is_grantable AS g, a.privilege_type AS p FROM pg_class c, "
            "LATERAL aclexplode(c.relacl) a WHERE c.oid = $1::oid",
            oid,
        ):
            if a["grantee"] == 0:
                out.append(f"GRANTEE: {t}: PUBLIC holds {a['p']}")
            elif a["grantee"] not in allowed:
                out.append(f"GRANTEE: {t}: unexpected grantee oid {a['grantee']} holds {a['p']}")
            if a["grantor"] != owner_oid:
                out.append(f"GRANTOR: {t}: {a['p']} granted by non-owner (oid {a['grantor']})")
            if a["g"]:
                out.append(f"GRANT-OPTION: {t}: {a['p']} carries GRANT OPTION")
        if owner_oid == role_oid:
            out.append(f"OWNER-IS-ROLE: {t} is owned by {role}")
        if await conn.fetchval("SELECT pg_has_role($1::name, $2::oid, 'USAGE')", role, owner_oid):
            out.append(f"INHERITS-OWNER: {role} can use the rights of the owner of {t}")

    if check_role_level:
        out += await role_level_violations(conn, role, role_oid)
    return out


async def role_level_violations(conn: Any, role: str, role_oid: int) -> list[str]:
    out: list[str] = []
    r = await conn.fetchrow(
        "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication, rolcanlogin "
        "FROM pg_roles WHERE oid = $1::oid",
        role_oid,
    )
    for col, label in (
        ("rolsuper", "SUPERUSER"),
        ("rolbypassrls", "BYPASSRLS"),
        ("rolcreaterole", "CREATEROLE"),
        ("rolcreatedb", "CREATEDB"),
        ("rolreplication", "REPLICATION"),
    ):
        if r[col]:
            out.append(f"ATTRIBUTE: {role} has {label}")
    if not r["rolcanlogin"]:
        out.append(f"ATTRIBUTE: {role} is NOLOGIN")
    for g in await conn.fetch(
        "SELECT pg_get_userbyid(roleid) AS g FROM pg_auth_members WHERE member = $1::oid", role_oid
    ):
        out.append(f"MEMBER-OF: {role} is a member of {g['g']}")
    owned = await conn.fetchval(
        "SELECT (SELECT count(*) FROM pg_class WHERE relowner = $1::oid) + "
        "(SELECT count(*) FROM pg_proc WHERE proowner = $1::oid) + "
        "(SELECT count(*) FROM pg_namespace WHERE nspowner = $1::oid) + "
        "(SELECT count(*) FROM pg_database WHERE datdba = $1::oid)",
        role_oid,
    )
    if owned:
        out.append(f"OWNS: {role} owns {owned} database object(s)")
    for s in await conn.fetch(
        "SELECT nspname FROM pg_namespace WHERE nspname NOT IN ('pg_catalog','information_schema') "
        "AND nspname NOT LIKE 'pg\\_toast%' AND nspname NOT LIKE 'pg\\_temp\\_%'"
    ):
        if await conn.fetchval("SELECT has_schema_privilege($1::name, $2::text, 'CREATE')", role, s["nspname"]):
            out.append(f"SCHEMA-CREATE: {role} has CREATE on schema {s['nspname']}")
    if await conn.fetchval(
        "SELECT has_database_privilege($1::name, current_database(), 'CREATE')", role
    ):
        out.append(f"DB-CREATE: {role} has CREATE on the database")
    return out


async def snapshot(conn: Any) -> list[tuple[str, ...]]:
    """Full ACL snapshot: relkind r,p,v,m,S,f in all non-system schemas, owner, relacl text
    (includes grantors and grant options), every column ACL."""
    rows = await conn.fetch(
        "SELECT n.nspname, c.relname, c.relkind::text, pg_get_userbyid(c.relowner), "
        "coalesce(c.relacl::text, '-'), coalesce((SELECT string_agg(a.attname || '=' || a.attacl::text, "
        "',' ORDER BY a.attname) FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attacl IS NOT NULL), '-') "
        "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE c.relkind IN ('r','p','v','m','S','f') AND n.nspname NOT IN ('pg_catalog','information_schema') "
        "AND n.nspname NOT LIKE 'pg\\_toast%' AND n.nspname NOT LIKE 'pg\\_temp\\_%' ORDER BY 1, 2"
    )
    return [tuple(str(x) for x in r.values()) for r in rows]


# ------------------------------------------------------------------ behavioural probes
# Errors that prove the privilege check PASSED (the statement then failed on data or a trigger).
ALLOWED_AFTER_PRIVILEGE_CHECK = (
    "NotNullViolationError",
    "CheckViolationError",
    "ForeignKeyViolationError",
    "UniqueViolationError",
    "RaiseError",
)

VERBS = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "SELECT_FOR_UPDATE")


def probe_statement(table: str, verb: str, columns: list[str]) -> str:
    t = f'public."{table}"'
    if verb == "SELECT":
        return f"SELECT * FROM {t} WHERE false"
    if verb == "INSERT":
        return f"INSERT INTO {t} DEFAULT VALUES"
    if verb == "UPDATE":
        sets = ", ".join(f'"{c}" = "{c}"' for c in columns)
        return f"UPDATE {t} SET {sets} WHERE false"
    if verb == "DELETE":
        return f"DELETE FROM {t} WHERE false"
    if verb == "TRUNCATE":
        return f"TRUNCATE {t}"
    if verb == "SELECT_FOR_UPDATE":
        return f"SELECT * FROM {t} WHERE false FOR UPDATE"
    raise KeyError(verb)


def expected_verb_allowed(table: str, verb: str) -> bool:
    want = expected_privileges(table)
    return {
        "SELECT": "SELECT" in want,
        "INSERT": "INSERT" in want,
        "UPDATE": "UPDATE" in want,
        "DELETE": "DELETE" in want,
        "TRUNCATE": False,
        "SELECT_FOR_UPDATE": "UPDATE" in want and "SELECT" in want,
    }[verb]


async def run_probe(conn: Any, stmt: str) -> tuple[str, str]:
    """Run ``stmt`` in a transaction that is ALWAYS rolled back.
    Returns ("denied"|"allowed"|"unexpected", error class name or "")."""
    import asyncpg

    tr = conn.transaction()
    await tr.start()
    try:
        await conn.execute(stmt)
        return ("allowed", "")
    except asyncpg.InsufficientPrivilegeError:
        return ("denied", "InsufficientPrivilegeError")
    except Exception as exc:  # noqa: BLE001 - classified below
        name = type(exc).__name__
        if name in ALLOWED_AFTER_PRIVILEGE_CHECK:
            return ("allowed", name)
        return ("unexpected", f"{name}: {exc}")
    finally:
        await tr.rollback()
