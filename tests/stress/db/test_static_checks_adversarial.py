# ruff: noqa: E501
"""Stress #11: adversarial fixtures for the static tripwires S1-S5 (plan 3.10.1). R1.

Feeds hostile or sloppy sources to the implementer's ``tests/unit/infra/static_checks.py``
(interface pinned in docs/gates/slice0-grants-stress-pins.md): ``check_migration_source``,
``check_init_sql``, ``check_wrapper_sh``, each ``(text) -> list[str]`` of violations.
Every adversarial fixture must be flagged; every control must be clean (a checker that flags
everything proves nothing). A fixture the tripwire cannot see is a finding to be recorded as a
known limit with the runtime control (G1 / verify_effective_privileges / oracle) that catches it;
that decision is the owner's, so such a fixture simply fails here.
No database. Lazy import: red individually before the implementer writes the module.
"""
from __future__ import annotations

import importlib
import sys

import pytest
import vulnscope_db_plugin as kit

GOOD_MIGRATION = '''
from alembic import context, op
import sqlalchemy as sa
from vulnscope.db import migration_grants as mg

TABLE_GRANTS = {
    "alembic_version": (),
    "orgs": ("SELECT", "INSERT", "UPDATE", "DELETE"),
    "ledger_entries": ("SELECT", "INSERT"),
    "checkpoints": ("SELECT", "INSERT"),
    "chain_heads": ("SELECT", "INSERT", "UPDATE"),
}

def upgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError("0001_initial cannot run with --sql")
    statements = mg.grant_statements(mg.APP_ROLE, TABLE_GRANTS)
    bind = op.get_bind()
    mg.require_app_role(bind, mg.APP_ROLE)
    before = mg.list_relations(bind)
    op.create_table("orgs", sa.Column("id", sa.String(36), primary_key=True))
    op.create_table("ledger_entries", sa.Column("id", sa.String(36), primary_key=True))
    op.create_table("checkpoints", sa.Column("id", sa.String(36), primary_key=True))
    op.create_table("chain_heads", sa.Column("chain_id", sa.String(255), primary_key=True))
    mg.require_grant_decision_for_new_relations(before, mg.list_relations(bind), TABLE_GRANTS)
    mg.apply_statements(bind, statements)
    mg.verify_effective_privileges(bind, mg.APP_ROLE, TABLE_GRANTS)

def downgrade() -> None:
    mg.require_disposable_or_empty_ledger(op.get_bind())
    op.drop_table("chain_heads")
    op.drop_table("checkpoints")
    op.drop_table("ledger_entries")
    op.drop_table("orgs")
'''

GOOD_INIT_SQL = """-- roles and the dev marker ONLY
SET log_min_error_statement = panic;
SET log_statement = 'none';
SET log_min_duration_statement = -1;
\\getenv vulnscope_app_password VULNSCOPE_APP_PASSWORD
\\getenv init_db POSTGRES_DB
CREATE ROLE vulnscope_app LOGIN PASSWORD :'vulnscope_app_password'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
ALTER DATABASE :"init_db" SET vulnscope.env = 'dev-disposable';
"""

GOOD_WRAPPER = """#!/bin/sh
set -eu
: "${VULNSCOPE_APP_PASSWORD:?VULNSCOPE_APP_PASSWORD is required}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \\
     -f /opt/vulnscope/init-roles.sql
"""


def _mut(src: str, old: str, new: str) -> str:
    assert old in src, f"fixture bug: {old!r} not in base source"
    return src.replace(old, new, 1)


def _sets_after_create_role() -> str:
    ln = GOOD_INIT_SQL.splitlines()
    return "\n".join([ln[0], *ln[4:8], *ln[1:4], ln[8]]) + "\n"


MIG = "check_migration_source"
SQL = "check_init_sql"
SH = "check_wrapper_sh"

CASES: list[tuple[str, str, str, bool]] = [
    # (id, checker, source, must_be_flagged)
    ("control_good_migration", MIG, GOOD_MIGRATION, False),
    ("control_good_init_sql", SQL, GOOD_INIT_SQL, False),
    ("control_good_wrapper", SH, GOOD_WRAPPER, False),
    ("variable_table_name", MIG, _mut(GOOD_MIGRATION, 'op.create_table("orgs",', 'name = "rogue"\n    op.create_table(name,'), True),
    ("table_not_in_map", MIG, _mut(GOOD_MIGRATION, 'op.create_table("orgs",', 'op.create_table("rogue",'), True),
    ("aliased_op_rogue_table", MIG, _mut(_mut(GOOD_MIGRATION, "from alembic import context, op", "from alembic import context, op as o"), 'op.create_table("orgs",', 'o.create_table("rogue",'), True),
    ("do_block_dollar_quoted_grant", MIG, _mut(GOOD_MIGRATION, "    mg.apply_statements(bind, statements)", "    op.execute(\"DO $$ BEGIN EXECUTE 'GRA' || 'NT ALL ON orgs TO PUBLIC'; END $$\")\n    mg.apply_statements(bind, statements)"), True),
    ("grant_calls_only_in_downgrade", MIG, _mut(_mut(GOOD_MIGRATION, "    mg.apply_statements(bind, statements)\n", ""), "    op.drop_table(\"chain_heads\")", "    mg.apply_statements(op.get_bind(), [])\n    op.drop_table(\"chain_heads\")"), True),
    ("verify_not_last_statement", MIG, _mut(GOOD_MIGRATION, "    mg.verify_effective_privileges(bind, mg.APP_ROLE, TABLE_GRANTS)", "    mg.verify_effective_privileges(bind, mg.APP_ROLE, TABLE_GRANTS)\n    op.execute(\"SELECT 1\")"), True),
    ("verify_under_if_false", MIG, _mut(GOOD_MIGRATION, "    mg.verify_effective_privileges(bind, mg.APP_ROLE, TABLE_GRANTS)", "    if False:\n        mg.verify_effective_privileges(bind, mg.APP_ROLE, TABLE_GRANTS)"), True),
    ("create_table_extra_whitespace", MIG, _mut(GOOD_MIGRATION, "    mg.apply_statements(bind, statements)", "    op.execute(\"CREATE   TABLE\\n rogue (id int)\")\n    mg.apply_statements(bind, statements)"), True),
    ("create_table_as", MIG, _mut(GOOD_MIGRATION, "    mg.apply_statements(bind, statements)", "    op.execute(\"CREATE TABLE rogue AS SELECT 1\")\n    mg.apply_statements(bind, statements)"), True),
    ("select_into", MIG, _mut(GOOD_MIGRATION, "    mg.apply_statements(bind, statements)", "    op.execute(\"SELECT 1 AS a INTO rogue\")\n    mg.apply_statements(bind, statements)"), True),
    ("create_unlogged_table", MIG, _mut(GOOD_MIGRATION, "    mg.apply_statements(bind, statements)", "    op.execute(\"create unlogged table rogue (a int)\")\n    mg.apply_statements(bind, statements)"), True),
    ("fstring_execute", MIG, _mut(GOOD_MIGRATION, "    mg.apply_statements(bind, statements)", "    t = 'orgs'\n    op.execute(f\"GRANT ALL ON {t} TO PUBLIC\")\n    mg.apply_statements(bind, statements)"), True),
    ("string_concatenation_execute", MIG, _mut(GOOD_MIGRATION, "    mg.apply_statements(bind, statements)", "    op.execute(\"GRA\" + \"NT ALL ON orgs TO PUBLIC\")\n    mg.apply_statements(bind, statements)"), True),
    ("default_privileges", MIG, _mut(GOOD_MIGRATION, "    mg.apply_statements(bind, statements)", "    op.execute(\"alter  default\\n privileges in schema public grant all on tables to public\")\n    mg.apply_statements(bind, statements)"), True),
    ("batch_alter_table", MIG, _mut(GOOD_MIGRATION, "    mg.apply_statements(bind, statements)", "    with op.batch_alter_table(\"orgs\") as b:\n        b.add_column(sa.Column(\"x\", sa.Integer()))\n    mg.apply_statements(bind, statements)"), True),
    ("sa_table_create", MIG, _mut(GOOD_MIGRATION, "    mg.apply_statements(bind, statements)", "    sa.Table(\"rogue\", sa.MetaData(), sa.Column(\"a\", sa.Integer())).create(bind)\n    mg.apply_statements(bind, statements)"), True),
    ("table_grants_not_a_literal", MIG, _mut(_mut(GOOD_MIGRATION, 'TABLE_GRANTS = {', 'TABLE_GRANTS = {k: v for k, v in {'), '}\n\ndef upgrade', '}.items()}\n\ndef upgrade'), True),
    ("map_without_alembic_version", MIG, _mut(GOOD_MIGRATION, '    "alembic_version": (),\n', ""), True),
    ("ledger_widened_in_map", MIG, _mut(GOOD_MIGRATION, '"ledger_entries": ("SELECT", "INSERT"),', '"ledger_entries": ("SELECT", "INSERT", "UPDATE"),'), True),
    ("get_x_argument_seam", MIG, _mut(GOOD_MIGRATION, "    statements = mg.grant_statements(mg.APP_ROLE, TABLE_GRANTS)", "    role = context.get_x_argument(as_dictionary=True).get('app_role', mg.APP_ROLE)\n    statements = mg.grant_statements(role, TABLE_GRANTS)"), True),
    ("downgrade_missing_guard", MIG, _mut(GOOD_MIGRATION, "    mg.require_disposable_or_empty_ledger(op.get_bind())\n", ""), True),
    ("sql_grant_present", SQL, GOOD_INIT_SQL + "GRANT SELECT ON ledger_entries TO vulnscope_app;\n", True),
    ("sql_in_role_membership", SQL, _mut(GOOD_INIT_SQL, "NOSUPERUSER NOCREATEDB", "IN ROLE pg_write_all_data NOSUPERUSER NOCREATEDB"), True),
    ("sql_do_block", SQL, GOOD_INIT_SQL + "DO $$ BEGIN EXECUTE 'GRA' || 'NT ALL ON x TO PUBLIC'; END $$;\n", True),
    ("sql_missing_nobypassrls", SQL, _mut(GOOD_INIT_SQL, " NOBYPASSRLS", ""), True),
    ("sql_createdb_attribute", SQL, _mut(GOOD_INIT_SQL, "NOCREATEDB", "CREATEDB"), True),
    ("sql_logging_sets_after_create_role", SQL, _sets_after_create_role(), True),
    ("sql_extra_meta_command", SQL, GOOD_INIT_SQL + "\\! id\n", True),
    ("control_sql_grant_word_in_comment", SQL, GOOD_INIT_SQL + "-- no GRANT here\n", False),
    ("sh_on_error_stop_only_in_comment", SH, _mut(GOOD_WRAPPER, "psql -X -v ON_ERROR_STOP=1", "# -v ON_ERROR_STOP=1\npsql -X"), True),
    ("sh_missing_password_guard", SH, _mut(GOOD_WRAPPER, ': "${VULNSCOPE_APP_PASSWORD:?VULNSCOPE_APP_PASSWORD is required}"\n', ""), True),
    ("sh_exec_psql", SH, _mut(GOOD_WRAPPER, "psql -X", "exec psql -X"), True),
    ("sh_set_x", SH, _mut(GOOD_WRAPPER, "set -eu", "set -eux"), True),
    ("sh_password_via_v_flag", SH, _mut(GOOD_WRAPPER, "-v ON_ERROR_STOP=1", "-v ON_ERROR_STOP=1 -v vulnscope_app_password=$VULNSCOPE_APP_PASSWORD"), True),
]


def _checks() -> object:
    unit_infra = str(kit.REPO_ROOT / "tests" / "unit" / "infra")
    if unit_infra not in sys.path:
        sys.path.insert(0, unit_infra)
    return importlib.import_module("static_checks")


@pytest.mark.parametrize(
    ("checker", "source", "must_flag"),
    [c[1:] for c in CASES],
    ids=[c[0] for c in CASES],
)
def test_tripwire_flags_adversarial_fixture_and_passes_control(
    checker: str, source: str, must_flag: bool
) -> None:
    mod = _checks()
    violations = getattr(mod, checker)(source)
    assert isinstance(violations, list), f"{checker} must return list[str], got {type(violations)}"
    if must_flag:
        assert violations, f"TRIPWIRE BYPASS: {checker} reported nothing for an adversarial fixture"
    else:
        assert not violations, f"FALSE POSITIVE on a control fixture: {violations}"
