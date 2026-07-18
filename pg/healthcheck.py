#!/usr/local/bin/python3
"""Docker HEALTHCHECK probe: liveness is public and the mutation auth gate is live."""

import http.client
import json
import sys

import driver_manifest

manifest = driver_manifest.load()

connection = http.client.HTTPConnection("127.0.0.1", manifest.port, timeout=3)
try:
    connection.request("GET", manifest.health_path)
    response = connection.getresponse()
    healthy = response.status == 200 and json.load(response) == {"status": "ok"}
except OSError, ValueError, json.JSONDecodeError, http.client.HTTPException:
    sys.exit(1)
finally:
    connection.close()

if not healthy:
    sys.exit(1)

connection = http.client.HTTPConnection("127.0.0.1", manifest.port, timeout=3)
try:
    connection.request(
        "POST",
        "/v1/teams/provision",
        body=b"{}",
        headers={"Content-Type": "application/json"},
    )
    response = connection.getresponse()
    response.read()
    protected = response.status == 403
except OSError, ValueError, http.client.HTTPException:
    sys.exit(1)
finally:
    connection.close()

sys.exit(0 if protected else 1)
