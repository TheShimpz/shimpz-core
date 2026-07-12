# syntax=docker/dockerfile:1
# check=skip=SecretsUsedInArgOrEnv ; false positive: the *_TOKEN_GID/*_TOKEN_* ARGs here hold numeric group IDs and file paths, never secret values
#
# shimpz-driver — the ONLY container in this stack that holds /var/run/docker.sock.
# `shimpz-brain` never mounts it (SECURITY_ENGINEERING_PLAN.md 1.1). This process's own UID is
# unprivileged (10001), but note holding the socket is host-root-equivalent regardless of
# UID — the non-root user is defense-in-depth against trivial container-filesystem tampering,
# not a claim that socket access itself is contained.
# Pinned by digest (not just the `3.14-slim` tag, which can move) — SECURITY_ENGINEERING_PLAN.md
# item 6, extra weight given this is the ONE container holding docker.sock. `docker pull
# python:3.14-slim` resolved to this exact digest; bump both together.
FROM python:3.14-slim@sha256:b877e50bd90de10af8d82c57a022fc2e0dc731c5320d762a27986facfc3355c1

ARG UV_VERSION=0.11.25
# Same version AND hash as the main Dockerfile's UV_INSTALL_SHA256 (astral.sh serves an immutable
# versioned artifact — confirmed by downloading this exact URL and computing its sha256 directly,
# not copied on faith). Bump both together if UV_VERSION ever changes here.
ARG UV_INSTALL_SHA256=ca2de1bca2913ba30ce88658b6d90a663c627ecac378803aa58084a9adb35a46
# Must match the GID that owns /var/run/docker.sock on the host running this compose stack
# (checked with `stat -c '%g' /var/run/docker.sock`); override via compose build-arg if it differs.
ARG DOCKER_GID=989
# Fixed GID for the token-sharing group — MUST match the same groupadd in the main Dockerfile
# (shimpz-brain's `abc` user joins it there) so both sides can agree on a numeric GID without a runtime
# lookup. Picked well outside the base image's/DOCKER_GID's normal range to avoid collision.
ARG SHIMPZ_DRIVER_TOKEN_GID=10002

# Downloaded to a file and hash-checked BEFORE execution — never `curl | sh` (SECURITY_ENGINEERING_PLAN.md
# item 6: an unverified pipe-to-shell is a full supply-chain compromise if astral.sh (or anything on
# the path to it) is ever compromised or MITM'd, pinned version or not).
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    curl -LsSf "https://astral.sh/uv/${UV_VERSION}/install.sh" -o /tmp/uv-install.sh && \
    echo "${UV_INSTALL_SHA256}  /tmp/uv-install.sh" | sha256sum -c - && \
    env UV_INSTALL_DIR=/usr/local/bin INSTALLER_NO_MODIFY_PATH=1 sh /tmp/uv-install.sh && \
    rm -f /tmp/uv-install.sh && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# `driver` needs TWO supplementary groups: `dockersock` (to read/write the Docker socket) and
# `shimpzdriver-token` (so the token file it writes can be group-readable by `shimpz-brain`'s `abc` user,
# which is NOT UID 10001 and was previously locked out entirely — SECURITY_ENGINEERING_PLAN.md
# item 1). Neither is driver's PRIMARY group so a plain `chown driver:X` still says what X means.
RUN groupadd -g "${DOCKER_GID}" dockersock \
    && groupadd -g "${SHIMPZ_DRIVER_TOKEN_GID}" shimpzdriver-token \
    && useradd -u 10001 -g dockersock -G shimpzdriver-token -M -s /usr/sbin/nologin driver

WORKDIR /app
COPY pyproject.toml .
# Pinned EXACT (not the open `docker>=7.1.0` range pyproject.toml's own dependency spec still
# documents for humans) — SECURITY_ENGINEERING_PLAN.md item 6: an unbounded range lets any future
# release, including a compromised or breaking one, install silently on the next rebuild. Bump
# deliberately, in both places, together.
RUN uv venv /opt/venv && uv pip install --python /opt/venv/bin/python --no-cache-dir docker==7.1.0

COPY app.py validate.py manifests.py audit.py token_store.py caddy_routes.py ./

# Pre-create + own every path a NAMED VOLUME will be mounted onto — Docker copies an image
# directory's ownership/content into a fresh empty volume on first mount, which is otherwise
# root:root/0755 and unwritable by the non-root `driver` user. /run/shimpz-driver specifically gets
# GROUP `shimpzdriver-token` (not `dockersock`) so the fresh volume's directory perms already match
# what the token file inside it will need — readable by shimpz-brain's `abc` user via that shared group.
RUN mkdir -p /run/shimpz-driver /var/log/shimpz-driver /caddy-sites \
    && chown driver:shimpzdriver-token /run/shimpz-driver && chmod 750 /run/shimpz-driver \
    && chown -R driver:dockersock /var/log/shimpz-driver /caddy-sites

USER driver
EXPOSE 7070
ENTRYPOINT ["/opt/venv/bin/python", "/app/app.py"]
