# syntax=docker/dockerfile:1
# check=skip=SecretsUsedInArgOrEnv ; false positive: the *_TOKEN_GID/*_TOKEN_* ARGs here hold numeric group IDs and file paths, never secret values
#
# r2-driver — the ONLY container that holds the Cloudflare R2 credentials (RCLONE_CONFIG_R2_*)
# (SECURITY_ENGINEERING_PLAN.md item 7). `shimpz-brain` never sees the R2 secret; it calls this restricted,
# allowlisted, audited HTTP API instead. Deliberately holds NO other credential and NO docker.sock —
# a compromise here can only ever touch the one R2 bucket Shimpz already uses, never the rest of the
# keyring. stdlib-only Python (urllib/http.server); rclone is the one binary it shells (fixed argv).
# Pinned by digest (same base the other stdlib sidecars pin) — SECURITY_ENGINEERING_PLAN.md item 6.
FROM python:3.14-slim@sha256:b877e50bd90de10af8d82c57a022fc2e0dc731c5320d762a27986facfc3355c1

# rclone = the S3 client for Cloudflare R2. SAME pinned version + sha256 as the main Dockerfile once
# installed in the brain — bump both together. Official binary (Debian's is frozen years behind).
ARG RCLONE_VERSION=1.74.3
ARG RCLONE_SHA256=dbee7ccd7a5d617e4ed4cd4555c16669b511abfe8d31164f61be35ac9e999bd2
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl unzip; \
    curl -fsSL "https://downloads.rclone.org/v${RCLONE_VERSION}/rclone-v${RCLONE_VERSION}-linux-amd64.zip" -o /tmp/rclone.zip; \
    echo "${RCLONE_SHA256}  /tmp/rclone.zip" | sha256sum -c -; \
    unzip -j /tmp/rclone.zip '*/rclone' -d /usr/local/bin/; \
    chmod +x /usr/local/bin/rclone; \
    rm -f /tmp/rclone.zip; \
    apt-get purge -y curl unzip; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*

# Fixed GID for the token-sharing group — MUST match the same groupadd in the main Dockerfile (shimpz-brain's
# `abc` user joins it there). DISTINCT from every other sidecar's token GID (10002-10006) so no
# sidecar's token is ever readable via another's group.
ARG SHIMPZ_R2DRIVER_TOKEN_GID=10007
RUN groupadd -g "${SHIMPZ_R2DRIVER_TOKEN_GID}" shimpzr2driver-token \
    && useradd -u 10007 -G shimpzr2driver-token -M -s /usr/sbin/nologin r2driver

WORKDIR /app
COPY app.py validate.py r2_client.py audit.py token_store.py healthcheck.py ./

# Pre-create + own every path a NAMED VOLUME mounts onto — Docker seeds a fresh volume from the image
# dir's ownership, otherwise root:root/0755 and unwritable by the non-root `r2driver` user.
RUN mkdir -p /run/shimpz-r2driver /var/log/r2-driver \
    && chown r2driver:shimpzr2driver-token /run/shimpz-r2driver && chmod 750 /run/shimpz-r2driver \
    && chown -R r2driver:shimpzr2driver-token /var/log/r2-driver

USER r2driver
EXPOSE 7075
ENTRYPOINT ["python3", "/app/app.py"]
