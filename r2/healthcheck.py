#!/usr/local/bin/python3
"""Docker HEALTHCHECK probe: the server is up and its auth gate is live.

No `curl` in this image on purpose — an unauthenticated GET must be refused with 403 (see app.py's
bearer-token check), the same proof the other sidecars' healthchecks make for their own endpoints.
"""

import http.client
import sys

connection = http.client.HTTPConnection("127.0.0.1", 7075, timeout=3)
try:
    connection.request("GET", "/v1/r2/list")
    response = connection.getresponse()
    response.read()
except OSError, http.client.HTTPException:
    sys.exit(1)
else:
    sys.exit(0 if response.status == 403 else 1)
finally:
    connection.close()
