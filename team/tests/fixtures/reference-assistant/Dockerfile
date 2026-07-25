# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89
FROM python:3.14-slim@sha256:b877e50bd90de10af8d82c57a022fc2e0dc731c5320d762a27986facfc3355c1

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY tests/fixtures/reference-assistant/shimpz.toml /opt/shimpz/shimpz.toml
COPY tests/fixtures/reference-assistant/shimpz-power /usr/local/bin/shimpz-power
COPY tests/fixtures/reference-assistant/shimpz.contract.json /opt/shimpz/shimpz.contract.json
RUN groupadd --gid 10001 assistant && \
    useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin assistant && \
    chmod 0444 /opt/shimpz/shimpz.toml /opt/shimpz/shimpz.contract.json && \
    chmod 0555 /usr/local/bin/shimpz-power

LABEL org.shimpz.assistant.id="shimpz-cloudflare" org.shimpz.assistant.api="1"
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/python3", "-c", "import signal; signal.pause()"]
