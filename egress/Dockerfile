# syntax=docker/dockerfile:1
#
# egress-proxy — the brain's ONLY internet route (SECURITY_ENGINEERING_PLAN.md item 8). A CONNECT-only
# forward proxy that forwards ONLY allowlisted hosts (.anthropic.com, api.telegram.org) and refuses
# everything else. Holds NO credential and NO docker.sock; a compromise here can, at worst, reach the
# two hosts already on the allowlist. stdlib-only (socket/select) — zero third-party deps, no uv/venv.
# Pinned by digest (not the movable `3.14-slim` tag) — SECURITY_ENGINEERING_PLAN.md item 6. Same digest
# as the other driver sidecars; bump all together.
FROM python:3.14-slim@sha256:b877e50bd90de10af8d82c57a022fc2e0dc731c5320d762a27986facfc3355c1

# IPv6 egress is broken on this host (see the main Dockerfile) → prefer IPv4 so an outbound CONNECT to a
# dual-stack allowlisted host (e.g. api.telegram.org) doesn't stall on an unreachable AAAA. Same fix as
# every other image in this repo. `>>` creates the file; glibc's getaddrinfo reads it when present.
RUN echo 'precedence ::ffff:0:0/96 100' >> /etc/gai.conf

RUN useradd -u 10004 -M -s /usr/sbin/nologin egressproxy

WORKDIR /app
COPY app.py audit.py healthcheck.py ./

# Pre-create + own the audit-log volume mountpoint — Docker copies image-dir ownership into a fresh
# empty named volume on first mount (otherwise root:root/0755, unwritable by the non-root user).
RUN mkdir -p /var/log/egress-proxy && chown -R egressproxy:egressproxy /var/log/egress-proxy

USER egressproxy
EXPOSE 8888
# The Docker HEALTHCHECK is defined in docker-compose.yml (matching the sibling drivers), so it
# stays with the rest of the service config; healthcheck.py proves the allowlist gate is live.
ENTRYPOINT ["python3", "/app/app.py"]
