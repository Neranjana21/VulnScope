"""Cheap static tripwires S1-S5 (docs/gates/slice0-plan.md 3.10.1). Helper module, not a test.

They are tripwires, not controls: the controls are the runtime guard
``require_grant_decision_for_new_relations``, ``verify_effective_privileges`` and the independent
oracle in ``tests/stress/db/``. Each function returns a list of violation strings (empty = clean).
"""
from __future__ import annotations

import ast
import re
import shlex
from collections.abc import Iterator

# Deliberate third copy of migration_grants.FIXED_PRIVILEGES (a tripwire, not the control).
_FIXED = {
    "ledger_entries": {"SELECT", "INSERT"},
    "checkpoints": {"SELECT", "INSERT"},
    "chain_heads": {"SELECT", "INSERT", "UPDATE"},
    "alembic_version": set(),
}
_SQL_FORBIDDEN = [
    r"create\s+(unlogged\s+|temp\w*\s+)?table",
    r"\bselect\b.*\binto\b",
    r"\bgrant\b",
    r"\brevoke\b",
    r"default\s+privileges",
    r"\bdo\s+\$",
    r"disable\s+trigger",
]
_SOURCE_FORBIDDEN = [r"default\s+privileges", r"grant\s+all", r"\bto\s+public\b", r"get_x_argument"]
_INFRA_FORBIDDEN = [
    r"\b(grant|revoke)\b",
    r"default\s+privileges",
    r"\bdo\s+\$",
    r"\bexecute\b",
    r"\bin\s+role\b",
    r"\bto\s+public\b",
]
_GRANT_CALLS = (
    "grant_statements",
    "require_app_role",
    "list_relations",
    "require_grant_decision_for_new_relations",
    "apply_statements",
    "verify_effective_privileges",
)
_ORDER = _GRANT_CALLS  # required top-level order inside upgrade()


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).lower()


# ---- migrations (S1, S2, S4)
def _call_name(node: ast.AST) -> tuple[str | None, str | None]:
    """(receiver name, attribute or function name) of a Call node."""
    if not isinstance(node, ast.Call):
        return None, None
    fn = node.func
    if isinstance(fn, ast.Attribute):
        recv = fn.value.id if isinstance(fn.value, ast.Name) else None
        return recv, fn.attr
    if isinstance(fn, ast.Name):
        return None, fn.id
    return None, None


def _aliases(tree: ast.Module) -> tuple[set[str], set[str]]:
    """Names bound to alembic's ``op`` and to the ``migration_grants`` module."""
    ops: set[str] = set()
    mgs: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for a in node.names:
                if node.module == "alembic" and a.name == "op":
                    ops.add(a.asname or a.name)
                if node.module == "vulnscope.db" and a.name == "migration_grants":
                    mgs.add(a.asname or a.name)
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "vulnscope.db.migration_grants" and a.asname:
                    mgs.add(a.asname)
    return ops or {"op"}, mgs or {"mg"}


def _table_grants(tree: ast.Module, out: list[str]) -> dict[str, tuple[str, ...]] | None:
    for node in tree.body:
        target: ast.expr | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            target, value = node.target, node.value
        if isinstance(target, ast.Name) and target.id == "TABLE_GRANTS" and value is not None:
            try:
                parsed = ast.literal_eval(value)
            except (ValueError, TypeError, SyntaxError):
                out.append("TABLE_GRANTS is not a plain literal (ast.literal_eval failed)")
                return None
            ok = isinstance(parsed, dict) and all(
                isinstance(k, str) and isinstance(v, tuple) and all(isinstance(p, str) for p in v)
                for k, v in parsed.items()
            )
            if not ok:
                out.append("TABLE_GRANTS must map str to tuple[str, ...]")
                return None
            return dict(parsed)
    out.append("no module-level TABLE_GRANTS literal")
    return None


def _scopes(tree: ast.Module) -> Iterator[tuple[str, list[ast.AST]]]:
    rest: list[ast.AST] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            yield node.name, list(ast.walk(node))
        else:
            rest.extend(ast.walk(node))
    yield "<module>", rest


def _check_sql_arg(arg: ast.expr, where: str, out: list[str]) -> None:
    if _call_name(arg)[1] == "text":  # op.execute(sa.text(...)): inner text() is checked itself
        return
    if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
        out.append(f"{where}: SQL argument is not a plain string constant")
        return
    sql = _norm(arg.value)
    for pattern in _SQL_FORBIDDEN:
        if re.search(pattern, sql):
            out.append(f"{where}: SQL matches forbidden /{pattern}/")


def _check_calls(tree: ast.Module, ops: set[str], tgrants: dict[str, tuple[str, ...]] | None,
                 out: list[str]) -> None:
    for scope, nodes in _scopes(tree):
        for node in nodes:
            recv, name = _call_name(node)
            if name is None or not isinstance(node, ast.Call):
                continue
            if recv in ops and name == "create_table":
                first = node.args[0] if node.args else None
                if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                    out.append("op.create_table first argument is not a string literal")
                elif tgrants is not None and first.value not in tgrants:
                    out.append(f"op.create_table({first.value!r}) is not a key of TABLE_GRANTS")
            elif recv in ops and name == "execute":
                if not node.args:
                    out.append("op.execute without an argument")
                else:
                    _check_sql_arg(node.args[0], "op.execute", out)
                    _check_trigger_sql(node.args[0], scope, out)
            elif name == "text" and node.args:
                _check_sql_arg(node.args[0], "text()", out)
            elif recv in ops and name == "batch_alter_table":
                out.append("op.batch_alter_table is not allowed (it can recreate tables)")
            elif name in ("execute", "exec_driver_sql") and recv not in ops:
                out.append(f"raw {name}() outside op.execute")
            elif name == "create" and isinstance(node.func, ast.Attribute) and _call_name(
                node.func.value
            )[1] == "Table":
                out.append("sa.Table(...).create is not allowed")
            elif recv in ops and name == "drop_table":
                first = node.args[0] if node.args else None
                if (
                    isinstance(first, ast.Constant)
                    and first.value in ("ledger_entries", "checkpoints")
                    and scope != "downgrade"
                ):
                    out.append(f"drop_table({first.value!r}) outside downgrade()")


def _check_trigger_sql(arg: ast.expr, scope: str, out: list[str]) -> None:
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        sql = _norm(arg.value)
        if re.search(r"drop\s+trigger", sql) and scope != "downgrade":
            out.append("DROP TRIGGER outside downgrade()")


def _top_calls(body: list[ast.stmt], mgs: set[str]) -> list[str | None]:
    """For each top-level statement: the migration_grants function it calls, or None."""
    names: list[str | None] = []
    for stmt in body:
        value = stmt.value if isinstance(stmt, ast.Expr | ast.Assign) else None
        recv, name = _call_name(value) if value is not None else (None, None)
        known = (*_GRANT_CALLS, "require_disposable_or_empty_ledger")
        names.append(name if recv in mgs and name in known else None)
    return names


def _statements(fn: ast.FunctionDef) -> list[ast.stmt]:
    """Function body without its docstring."""
    return [
        s
        for s in fn.body
        if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
    ]


def _check_functions(tree: ast.Module, mgs: set[str], out: list[str]) -> None:
    funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    up, down = funcs.get("upgrade"), funcs.get("downgrade")
    if up is None or down is None:
        out.append("upgrade() and downgrade() must both exist")
        return
    body = _statements(up)
    first = body[0] if body else None
    offline_ok = (
        isinstance(first, ast.If)
        and any(_call_name(n)[1] == "is_offline_mode" for n in ast.walk(first.test))
        and any(isinstance(n, ast.Raise) for n in first.body)
    )
    if not offline_ok:
        out.append("upgrade() must start with an offline-mode refusal")
    top = _top_calls(body, mgs)
    positions: list[int] = []
    for name in _ORDER:
        total = sum(
            1 for n in ast.walk(up) if _call_name(n)[1] == name and _call_name(n)[0] in mgs
        )
        # list_relations is also called inside the require_grant_decision... arguments
        total_ok = total >= 1 if name == "list_relations" else total == 1
        if top.count(name) != 1 or not total_ok:
            out.append(f"upgrade() must call {name}() exactly once as a top-level statement")
        else:
            positions.append(top.index(name))
    if len(positions) == len(_ORDER) and positions != sorted(positions):
        out.append("upgrade() grant calls are out of order")
    if positions and len(positions) == len(_ORDER) and positions[-1] != len(body) - 1:
        out.append("verify_effective_privileges must be the last statement of upgrade()")
    if any(isinstance(s, ast.Return) for s in body):
        out.append("upgrade() must not return early")
    dbody = _statements(down)
    if not dbody or _top_calls(dbody[:1], mgs) != ["require_disposable_or_empty_ledger"]:
        out.append("downgrade() must start with require_disposable_or_empty_ledger")
    for n in ast.walk(down):
        if _call_name(n)[0] in mgs and _call_name(n)[1] in _GRANT_CALLS:
            out.append(f"downgrade() must not call {_call_name(n)[1]}()")


def check_migration_source(source: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [f"migration does not parse: {exc.msg}"]
    out: list[str] = []
    ops, mgs = _aliases(tree)
    tgrants = _table_grants(tree, out)
    if tgrants is not None:
        if tgrants.get("alembic_version") != ():
            out.append('TABLE_GRANTS must contain "alembic_version": ()')
        for name, expected in _FIXED.items():
            if name in tgrants and set(tgrants[name]) != expected:
                out.append(f"TABLE_GRANTS[{name!r}] must be exactly {sorted(expected)}")
    _check_calls(tree, ops, tgrants, out)
    _check_functions(tree, mgs, out)
    norm = _norm(source)
    out.extend(f"source matches forbidden /{p}/" for p in _SOURCE_FORBIDDEN if re.search(p, norm))
    return out


# ---- init-roles.sql (S3)
_ROLE_ATTRS = "login nosuperuser nocreatedb nocreaterole nobypassrls noreplication"
_LOG_SETS = (
    r"set\s+log_min_error_statement\s*=\s*panic\s*;",
    r"set\s+log_statement\s*=\s*'none'\s*;",
    r"set\s+log_min_duration_statement\s*=\s*-1\s*;",
)
_GETENVS = (
    r"\getenv vulnscope_app_password VULNSCOPE_APP_PASSWORD",
    r"\getenv init_db POSTGRES_DB",
)


def check_init_sql(text: str) -> list[str]:
    stripped = "\n".join(line.split("--", 1)[0] for line in text.splitlines())
    out: list[str] = []
    norm = _norm(stripped)
    out.extend(f"forbidden /{p}/" for p in _INFRA_FORBIDDEN if re.search(p, norm))
    metas = [ln.strip() for ln in stripped.splitlines() if ln.strip().startswith("\\")]
    metas_norm = [re.sub(r"\s+", " ", m) for m in metas]
    if metas_norm != list(_GETENVS):
        out.append(f"psql meta-commands must be exactly the two \\getenv lines, found {metas_norm}")
    role = re.search(r"create\s+role\s+(\w+)\s+(.*?);", norm)
    if role is None or role.group(1) != "vulnscope_app":
        out.append("init-roles.sql must contain CREATE ROLE vulnscope_app")
        return out
    attrs = re.sub(r"password\s+:'[a-z_]+'\s*", "", role.group(2)).strip()
    if attrs != _ROLE_ATTRS:
        out.append(f"CREATE ROLE attributes must be exactly {_ROLE_ATTRS!r}, found {attrs!r}")
    first_getenv = norm.find("\\getenv")
    for pattern in _LOG_SETS:
        found = re.search(pattern, norm)
        if found is None:
            out.append(f"missing logging SET /{pattern}/")
        elif found.start() > role.start() or (first_getenv != -1 and found.start() > first_getenv):
            out.append(f"logging SET /{pattern}/ must precede \\getenv and CREATE ROLE")
    return out


# ---- 00-init-roles.sh (S5)
def check_wrapper_sh(text: str) -> list[str]:
    out: list[str] = []
    commands: list[list[str]] = []
    for line in text.replace("\\\n", " ").splitlines():
        try:
            tokens = shlex.split(line, comments=True, posix=True)
        except ValueError as exc:
            out.append(f"unparseable shell line: {exc}")
            continue
        if tokens:
            commands.append(tokens)
    flat = [t for cmd in commands for t in cmd]
    if "exec" in flat:
        out.append("exec is forbidden (the entrypoint sources this file)")
    sets = [c for c in commands if c[0] == "set"]
    if not any(any(t.startswith("-") and "e" in t and "u" in t for t in c[1:]) for c in sets):
        out.append("missing 'set -eu'")
    if any(t.startswith("-") and not t.startswith("--") and "x" in t for c in sets for t in c[1:]):
        out.append("set -x is forbidden")
    for var in ("VULNSCOPE_APP_PASSWORD", "POSTGRES_PASSWORD"):
        if not any(c[0] == ":" and any(f"${{{var}:?" in t for t in c[1:]) for c in commands):
            out.append(f"missing ':?' guard for {var}")
    psql = [c for c in commands if c[0] == "psql"]
    if not psql:
        out.append("no psql command found")
    for cmd in psql:
        pairs = zip(cmd, cmd[1:], strict=False)
        if not any(a == "-v" and b == "ON_ERROR_STOP=1" for a, b in pairs):
            out.append("psql must be run with -v ON_ERROR_STOP=1")
        if any("vulnscope_app_password" in t.lower() or "VULNSCOPE_APP_PASSWORD" in t for t in cmd):
            out.append("the app password must not appear on the psql command line")
    return out
