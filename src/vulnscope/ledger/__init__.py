"""Hash-chained evidence ledger: one chain per engagement, plus an intake
chain per org (D1). Pure hashing/typing logic (``types.py``, ``chain.py``,
and later ``canonical.py``/``verify.py``) must never import ``sqlalchemy``,
``fastapi``, or anything from ``models``/``api`` -- enforced by
``tests/unit/test_module_boundaries.py``.
"""
