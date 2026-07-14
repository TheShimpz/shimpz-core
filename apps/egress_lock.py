"""Fail-closed configuration gate for deployed-App egress isolation.

The lock is intentionally not a feature toggle.  An omitted setting means the secure default;
the only accepted explicit value is the exact string ``"1"``.  Keeping this parser separate from
the Docker-backed driver makes its startup contract hermetically testable.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

ENV_NAME = "SHIMPZ_APP_EGRESS_LOCK"


def require_enabled(environ: Mapping[str, str] | None = None) -> bool:
    """Return true only for the secure configuration, otherwise abort startup."""
    source = os.environ if environ is None else environ
    value = source.get(ENV_NAME, "1")
    if value != "1":
        raise RuntimeError(
            f"{ENV_NAME} must be exactly '1'; refusing to start with deployed-App egress isolation disabled"
        )
    return True
