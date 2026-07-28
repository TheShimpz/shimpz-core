# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89
# check=skip=SecretsUsedInArgOrEnv ; false positive: the *_TOKEN_GID/DOCKER_GID ARGs are numeric group IDs, never secrets
#
# team-driver — the SECOND container (besides shimpz-driver) holding /var/run/docker.sock, dedicated
# to Team lifecycle. `shimpz-brain` never mounts the socket; the
# authenticated admin panel calls this driver's restricted, allowlisted, audited API instead. This
# process's own UID is unprivileged (10001) — defense-in-depth against trivial filesystem tampering,
# not a claim that socket access itself is contained (holding the socket is host-root-equivalent).
# Pinned by digest (same as drivers/apps/Dockerfile — bump both together).
FROM python:3.14-slim@sha256:b877e50bd90de10af8d82c57a022fc2e0dc731c5320d762a27986facfc3355c1
ARG SOURCE_DATE_EPOCH=0

ARG DEBIAN_SNAPSHOT=20260623T000000Z
RUN set -eux; \
    . /etc/os-release; \
    archive_keyring="$(find /usr/share/keyrings -maxdepth 1 -type f -name 'debian-archive-keyring.*' -print -quit)"; \
    test -n "$archive_keyring"; \
    rm -f /etc/apt/sources.list; \
    find /etc/apt/sources.list.d -maxdepth 1 -type f -delete; \
    printf '%s\n' \
        "deb [signed-by=${archive_keyring}] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} ${VERSION_CODENAME} main" \
        "deb [signed-by=${archive_keyring}] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} ${VERSION_CODENAME}-updates main" \
        "deb [signed-by=${archive_keyring}] https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT} ${VERSION_CODENAME}-security main" \
        > /etc/apt/sources.list.d/debian-snapshot.list; \
    printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99shimpz-snapshot; \
    test "$(grep -Fc "https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}" /etc/apt/sources.list.d/debian-snapshot.list)" -eq 2; \
    test "$(grep -Fc "https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}" /etc/apt/sources.list.d/debian-snapshot.list)" -eq 1

ARG UV_VERSION=0.11.25
# Same version AND hash as drivers/apps/Dockerfile (astral.sh serves an immutable versioned artifact).
ARG UV_INSTALL_SHA256=ca2de1bca2913ba30ce88658b6d90a663c627ecac378803aa58084a9adb35a46
ARG COSIGN_VERSION=3.0.6
ARG COSIGN_AMD64_SHA256=c956e5dfcac53d52bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74
ARG COSIGN_ARM64_SHA256=bedac92e8c3729864e13d4a17048007cfafa79d5deca993a43a90ffe018ef2b8
ARG TARGETARCH
# Must match the GID that owns /var/run/docker.sock on the host (stat -c '%g' /var/run/docker.sock).
ARG DOCKER_GID=989
# Fixed GID for THIS driver's token group — the caller (admin, uid 1000) joins it to read the token.
# Distinct from every other sidecar's (10002–10009) so no token is readable via another's group.
ARG SHIMPZ_TEAMDRIVER_TOKEN_GID=10010
# The pg-driver token group — this driver joins it (read-only) to request a scoped DB from pg-driver.
# MUST match drivers/apps + brain's SHIMPZ_PGDRIVER_TOKEN_GID so the shared 0440 token is readable.
ARG SHIMPZ_PGDRIVER_TOKEN_GID=10004
ARG SHIMPZ_BRAINCRED_UNSEAL_TOKEN_GID=10012
ARG SHIMPZ_ACCOUNTS_BRAIN_RESOLVE_TOKEN_GID=10013
# Controller-owned token shared read-only with the isolated Brain runtime.
ARG SHIMPZ_BRAIN_RUNTIME_TOKEN_GID=10016
ARG SHIMPZ_APP_EGRESS_POLICY_GID=10017

# Downloaded + hash-checked BEFORE execution — never `curl | sh`.
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    curl -LsSf "https://astral.sh/uv/${UV_VERSION}/install.sh" -o /tmp/uv-install.sh && \
    echo "${UV_INSTALL_SHA256}  /tmp/uv-install.sh" | sha256sum -c - && \
    env UV_INSTALL_DIR=/usr/local/bin INSTALLER_NO_MODIFY_PATH=1 sh /tmp/uv-install.sh && \
    rm -f /tmp/uv-install.sh && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /var/lib/apt/periodic/* /var/cache/apt/* /var/cache/fontconfig/* \
        /var/cache/ldconfig/aux-cache /var/cache/man/* /var/log/apt/* \
        /var/log/alternatives.log /var/log/dpkg.log /root/.cache/uv

RUN case "${TARGETARCH}" in \
        amd64) cosign_sha256="${COSIGN_AMD64_SHA256}" ;; \
        arm64) cosign_sha256="${COSIGN_ARM64_SHA256}" ;; \
        *) echo "unsupported Cosign architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && curl -LsSf "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-${TARGETARCH}" \
        -o /tmp/cosign \
    && echo "${cosign_sha256}  /tmp/cosign" | sha256sum -c - \
    && install -m 0755 /tmp/cosign /usr/local/bin/cosign \
    && rm -f /tmp/cosign

# Every shared capability has a distinct supplementary group.
RUN groupadd -g "${DOCKER_GID}" dockersock \
    && groupadd -g "${SHIMPZ_TEAMDRIVER_TOKEN_GID}" shimpzteamdriver-token \
    && groupadd -g "${SHIMPZ_PGDRIVER_TOKEN_GID}" shimpzpgdriver-token \
    && groupadd -g "${SHIMPZ_BRAINCRED_UNSEAL_TOKEN_GID}" shimpzbraincred-unseal-token \
    && groupadd -g "${SHIMPZ_ACCOUNTS_BRAIN_RESOLVE_TOKEN_GID}" shimpzbrain-resolve \
    && groupadd -g "${SHIMPZ_BRAIN_RUNTIME_TOKEN_GID}" shimpzbrain-runtime-token \
    && groupadd -g "${SHIMPZ_APP_EGRESS_POLICY_GID}" shimpzapp-egress-policy \
    && useradd -u 10001 -g dockersock \
        -G shimpzteamdriver-token,shimpzpgdriver-token,shimpzbraincred-unseal-token,shimpzbrain-resolve,shimpzbrain-runtime-token,shimpzapp-egress-policy \
        -M -s /usr/sbin/nologin teamdriver

WORKDIR /app
# BuildKit is required: read-only bind mounts keep dependency metadata out of every image layer while the
# frozen lock binds Docker SDK's complete transitive graph and artifact hashes.
RUN --mount=type=bind,source=pyproject.toml,target=/app/pyproject.toml,ro \
    --mount=type=bind,source=uv.lock,target=/app/uv.lock,ro \
    UV_PROJECT_ENVIRONMENT=/opt/venv uv sync --frozen --no-install-project --no-dev --python 3.14 && \
    rm -rf /root/.cache/uv

COPY app.py validate.py manifests.py marketplace.py assistant_registry.py assistant_catalog.json assistant_genesis.py assistant_manifest.py cleanup_state.py audit.py token_store.py \
     assistant_chat.py \
     assistant_account_challenges.py assistant_account_flow.py oauth_account_store.py oauth_account_service.py \
     oauth_broker_client.py oauth_http_client.py oauth_pkce_challenges.py oauth_providers.py \
     team_storage.py brain_runtime_client.py brain_runtime_token_store.py chat_orchestrator.py chat_turn_engine.py inference_config.py \
     model_catalog.json egress_policy.py power_execution.py power_journal.py strict_json.py pgdriver_client.py accounts_client.py brain_credentials_client.py healthcheck.py ./
COPY assistant_human/__init__.py assistant_human/challenge_store.py assistant_human/hosted_assistants.py \
     assistant_human/hosted_chat_api.py assistant_human/hosted_chat_segment.py assistant_human/private_state.py \
     ./assistant_human/
COPY container_policy/__init__.py container_policy/hosted_apps.py container_policy/hosted_lifecycle.py \
     container_policy/hosted_resources.py container_policy/network.py ./container_policy/
# Keep the vendored contract authority byte-complete for its independent digest re-verification.
COPY contracts ./contracts
COPY hosted_install/__init__.py hosted_install/artifact_trust.py hosted_install/developers_client.py \
     hosted_install/developers_controller_contract.py hosted_install/developers_delegation.py \
     hosted_install/dynamic_assistants.py hosted_install/marketplace_image.py hosted_install/registry_auth.py \
     ./hosted_install/
COPY http_boundary/__init__.py http_boundary/hosted.py http_boundary/hosted_controller.py \
     http_boundary/runtime_state.py http_boundary/stdlib.py http_boundary/strict.py ./http_boundary/

# Pre-create + own every named-volume mountpoint so the fresh (root:root) volume is writable by the
# non-root user. /run/shimpz-teamdriver gets GROUP `shimpzteamdriver-token` so the fresh volume's
# perms already match what the token file inside needs — readable by the admin panel via that group.
RUN mkdir -p /run/shimpz-teamdriver /var/log/team-driver /var/lib/team-driver/pg-principals \
        /var/lib/team-driver/storage \
        /var/lib/team-driver/cleanup \
        /var/lib/team-driver/inference \
        /var/lib/team-driver/power-journal \
        /var/lib/team-driver/assistant-accounts/state \
        /var/lib/team-driver/assistant-accounts/key \
        /var/lib/team-driver/dynamic-assistants \
        /var/lib/team-driver/cosign \
        /app-egress-policy /run/shimpz-braincred-unseal /run/shimpz-accounts-brain-resolve \
        /run/shimpz-brain-runtime \
    && chown teamdriver:shimpzteamdriver-token /run/shimpz-teamdriver && chmod 750 /run/shimpz-teamdriver \
    && chown teamdriver:shimpzbraincred-unseal-token /run/shimpz-braincred-unseal \
    && chown teamdriver:shimpzbrain-resolve /run/shimpz-accounts-brain-resolve \
    && chmod 0750 /run/shimpz-braincred-unseal /run/shimpz-accounts-brain-resolve \
    && chown teamdriver:shimpzbrain-runtime-token /run/shimpz-brain-runtime \
    && chmod 0750 /run/shimpz-brain-runtime \
    && chown -R teamdriver:dockersock /var/log/team-driver /var/lib/team-driver \
    && chmod 0700 /var/lib/team-driver/pg-principals \
        /var/lib/team-driver/storage \
        /var/lib/team-driver/cleanup \
        /var/lib/team-driver/inference \
        /var/lib/team-driver/power-journal \
        /var/lib/team-driver/assistant-accounts/state \
        /var/lib/team-driver/assistant-accounts/key \
        /var/lib/team-driver/dynamic-assistants \
        /var/lib/team-driver/cosign \
    && chown teamdriver:shimpzapp-egress-policy /app-egress-policy \
    && chmod 0770 /app-egress-policy

USER teamdriver
EXPOSE 7077
# The umbrella Compose deployment owns liveness and invokes /app/healthcheck.py.
ENTRYPOINT ["/opt/venv/bin/python", "/app/app.py"]
