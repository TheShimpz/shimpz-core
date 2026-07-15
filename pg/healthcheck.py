#!/usr/local/bin/python3
"""Docker HEALTHCHECK probe: liveness is public and the mutation auth gate is live."""

import json
import sys
import urllib.error
import urllib.request

import driver_manifest

manifest = driver_manifest.load()

try:
    with urllib.request.urlopen(f"http://127.0.0.1:{manifest.port}{manifest.health_path}", timeout=3) as response:
        healthy = response.status == 200 and json.load(response) == {"status": "ok"}
except OSError, ValueError, json.JSONDecodeError:
    sys.exit(1)

if not healthy:
    sys.exit(1)

try:
    request = urllib.request.Request(
        f"http://127.0.0.1:{manifest.port}/v1/capsules/provision",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(request, timeout=3)  # noqa: S310 - fixed loopback URL
except urllib.error.HTTPError as exc:
    sys.exit(0 if exc.code == 403 else 1)
except OSError, ValueError:
    sys.exit(1)
else:
    sys.exit(1)  # a 2xx with no auth would mean the bearer-token gate isn't enforced at all
