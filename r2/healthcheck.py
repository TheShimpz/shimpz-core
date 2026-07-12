#!/usr/local/bin/python3
"""Docker HEALTHCHECK probe: the server is up and its auth gate is live.

No `curl` in this image on purpose — an unauthenticated GET must be refused with 403 (see app.py's
bearer-token check), the same proof the other sidecars' healthchecks make for their own endpoints.
"""

import sys
import urllib.error
import urllib.request

try:
    urllib.request.urlopen("http://127.0.0.1:7075/v1/r2/list", timeout=3)
except urllib.error.HTTPError as exc:
    sys.exit(0 if exc.code == 403 else 1)
except Exception:  # noqa: BLE001 — any other failure (connection refused, timeout) is unhealthy
    sys.exit(1)
else:
    sys.exit(1)  # a 2xx with no auth would mean the bearer-token gate isn't enforced at all
