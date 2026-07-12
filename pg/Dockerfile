# syntax=docker/dockerfile:1
# check=skip=SecretsUsedInArgOrEnv ; false positive: the *_TOKEN_GID/*_TOKEN_* ARGs here hold numeric group IDs and file paths, never secret values
#
# pg-driver — the ONLY container that holds SHIMPZ_PG_DSN (the Postgres superuser DSN).
# `shimpz-brain` never sees it; it calls this restricted, allowlisted, audited HTTP API instead. Deliberately
# holds NO other credential — a compromise here can only ever touch project databases/roles this
# cluster already manages, never Cloudflare, Redpanda, or Docker.
# Only third-party piece is the `postgresql-client` CLI (psql/createdb/dropdb) — the SAME commands
# shimpz-db already ran directly against the superuser, just moved server-side; no Python DB driver.
# Pinned by digest (not just the `3.14-slim` tag, which can move) — SECURITY_ENGINEERING_PLAN.md
# item 6. `docker pull python:3.14-slim` resolved to this exact digest; bump both together.
FROM python:3.14-slim@sha256:b877e50bd90de10af8d82c57a022fc2e0dc731c5320d762a27986facfc3355c1

# Fixed GID for the token-sharing group — MUST match the same groupadd in the main Dockerfile
# (shimpz-brain's `abc` user joins it there). Distinct from every other sidecar's own GID so no
# driver's token is ever readable via another's group.
ARG SHIMPZ_PGDRIVER_TOKEN_GID=10004

RUN apt-get update && apt-get install -y --no-install-recommends postgresql-client && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN groupadd -g "${SHIMPZ_PGDRIVER_TOKEN_GID}" shimpzpgdriver-token \
    && useradd -u 10001 -G shimpzpgdriver-token -M -s /usr/sbin/nologin pgdriver

WORKDIR /app
COPY app.py validate.py pg_client.py audit.py token_store.py healthcheck.py ./

# Pre-create + own every path a NAMED VOLUME will be mounted onto — Docker copies an image
# directory's ownership/content into a fresh empty volume on first mount, which is otherwise
# root:root/0755 and unwritable by the non-root `pgdriver` user.
RUN mkdir -p /run/shimpz-pgdriver /var/log/pg-driver \
    && chown pgdriver:shimpzpgdriver-token /run/shimpz-pgdriver && chmod 750 /run/shimpz-pgdriver \
    && chown -R pgdriver:shimpzpgdriver-token /var/log/pg-driver

USER pgdriver
EXPOSE 7072
ENTRYPOINT ["python3", "/app/app.py"]
