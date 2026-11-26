"""STEP 1 DEVELOPMENT PATH: no gateway, no worker, not the security boundary.

ADR-0013. This package is not part of the built distribution, nothing under ``src/``
may import it, it may only talk to our own stub on 127.0.0.1, and it is DELETED when
Step 2 lands.
"""

LABEL = "STEP 1 DEVELOPMENT PATH: no gateway, no worker, not the security boundary"
