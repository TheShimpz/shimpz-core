"""The ONLY place SHIMPZ_BUS_ADMIN_* is ever read or sent.

Same confluent-kafka admin/producer/consumer logic shimpz-bus used to run directly as the cluster
SUPERUSER — moved server-side, unchanged behavior, so this is a credential relocation
(SECURITY_ENGINEERING_PLAN.md item 2), not a rewrite of already-correct logic. `shimpz-bus provision`
still creates a project's OWN least-privilege proj_<name> SASL user, scoped by ACL prefix, exactly
as before — that per-project identity is what projects actually run as; this admin identity never
leaves this container.
"""

from __future__ import annotations

import hmac
import json
import os
import time
from hashlib import sha256

from confluent_kafka import Consumer, KafkaException, Producer
from confluent_kafka.admin import (
    AclBinding,
    AclOperation,
    AclPermissionType,
    AdminClient,
    NewTopic,
    ResourcePatternType,
    ResourceType,
    ScramCredentialInfo,
    ScramMechanism,
    UserScramCredentialUpsertion,
)

BROKERS = os.environ.get("SHIMPZ_BUS_BROKERS", "redpanda:9092")
_ADMIN_USERNAME = os.environ.get("SHIMPZ_BUS_ADMIN_USERNAME", "")
_ADMIN_PASSWORD = os.environ.get("SHIMPZ_BUS_ADMIN_PASSWORD", "")
_ADMIN_MECHANISM = os.environ.get("SHIMPZ_BUS_ADMIN_MECHANISM", "SCRAM-SHA-256")
_SCRAM_MECHANISMS = {
    "SCRAM-SHA-256": ScramMechanism.SCRAM_SHA_256,
    "SCRAM-SHA-512": ScramMechanism.SCRAM_SHA_512,
}


class BusError(Exception):
    """A Kafka/Redpanda admin, produce, or consume call failed."""


def _client_conf(**extra: object) -> dict:
    conf = {"bootstrap.servers": BROKERS, **extra}
    if _ADMIN_USERNAME and _ADMIN_PASSWORD:
        conf.update(
            {
                "security.protocol": "SASL_PLAINTEXT",
                "sasl.mechanism": _ADMIN_MECHANISM,
                "sasl.username": _ADMIN_USERNAME,
                "sasl.password": _ADMIN_PASSWORD,
            }
        )
    return conf


def _admin() -> AdminClient:
    return AdminClient(_client_conf())


def health() -> dict:
    try:
        md = _admin().list_topics(timeout=8)
    except KafkaException as exc:
        raise BusError(str(exc)) from exc
    return {"brokers": len(md.brokers), "topics": len(md.topics), "bootstrap": BROKERS}


def topics() -> list[str]:
    try:
        md = _admin().list_topics(timeout=8)
    except KafkaException as exc:
        raise BusError(str(exc)) from exc
    return sorted(md.topics)


def create_topic(topic: str, partitions: int) -> dict:
    ac = _admin()
    futures = ac.create_topics([NewTopic(topic, num_partitions=partitions, replication_factor=1)])
    for future in futures.values():
        try:
            future.result(timeout=10)
        except KafkaException as exc:
            if "already exists" in str(exc).lower():
                return {"created": False, "topic": topic}
            raise BusError(str(exc)) from exc
    return {"created": True, "topic": topic}


def produce(topic: str, payload: dict, key: str | None) -> dict:
    producer = Producer(_client_conf())
    errors: list[object] = []
    producer.produce(topic, json.dumps(payload).encode(), key=key, callback=lambda e, _m: errors.append(e))
    producer.flush(15)
    if errors and errors[0] is not None:
        raise BusError(str(errors[0]))
    if not errors:
        raise BusError(f"produce to {topic} not confirmed within 15s (broker unreachable or auth failed)")
    return {"published": True, "topic": topic}


def tail(topic: str, n: int) -> dict:
    consumer = Consumer(
        _client_conf(
            **{
                "group.id": f"bus-driver-tail-{int(time.time())}",
                "auto.offset.reset": "earliest",
                "enable.auto.commit": False,
            }
        )
    )
    consumer.subscribe([topic])
    messages = []
    try:
        idle = 0
        while len(messages) < n and idle < 6:
            msg = consumer.poll(1.0)
            if msg is None:
                idle += 1
                continue
            if msg.error():
                continue
            idle = 0
            messages.append(
                {
                    "key": msg.key().decode() if msg.key() else None,
                    "value": msg.value().decode("utf-8", "replace")[:300],
                }
            )
    finally:
        consumer.close()
    return {"messages": messages, "count": len(messages)}


def _project_bus_password(project: str) -> str:
    if not _ADMIN_PASSWORD:
        raise BusError("cluster SASL isn't configured (SHIMPZ_BUS_ADMIN_PASSWORD unset)")
    return hmac.new(_ADMIN_PASSWORD.encode(), project.encode(), sha256).hexdigest()[:32]


def provision(project: str) -> dict:
    user = f"proj_{project}"
    password = _project_bus_password(project)
    ac = _admin()

    upsertion = UserScramCredentialUpsertion(
        user, ScramCredentialInfo(_SCRAM_MECHANISMS[_ADMIN_MECHANISM], 8192), password.encode(), None
    )
    futures = ac.alter_user_scram_credentials([upsertion])
    for future in futures.values():
        try:
            future.result(timeout=10)
        except KafkaException as exc:
            raise BusError(str(exc)) from exc

    # Prefixed ACLs: this user can touch ONLY <proj>.* topics/groups — never another project's, the
    # infra registry topic, or anything else on the shared cluster.
    prefix = f"{project}."
    principal = f"User:{user}"
    acls = [
        AclBinding(
            ResourceType.TOPIC,
            prefix,
            ResourcePatternType.PREFIXED,
            principal,
            "*",
            AclOperation.ALL,
            AclPermissionType.ALLOW,
        ),
        AclBinding(
            ResourceType.GROUP,
            prefix,
            ResourcePatternType.PREFIXED,
            principal,
            "*",
            AclOperation.ALL,
            AclPermissionType.ALLOW,
        ),
    ]
    acl_futures = ac.create_acls(acls)
    for future in acl_futures.values():
        try:
            future.result(timeout=10)
        except KafkaException as exc:
            raise BusError(str(exc)) from exc

    return {
        "username": user,
        "password": password,
        "mechanism": _ADMIN_MECHANISM,
        "topic_prefix": prefix,
    }


def grant_consume(consumer_project: str, topic: str) -> dict:
    """Grant proj_<consumer> READ on a FOREIGN topic — the cross-project CONSUME path (R131).

    provision() scopes every project to its OWN <project>.* prefix, so a service can never read
    another project's topic — correct isolation, but it blocks the decoupled event flow the
    microservice plane is built on (a landing publishes leads; meta-ads consumes them). This is the
    async twin of `shimpz-app --calls` (the sync path): an EXPLICIT, AUDITED, minimal grant.

    Deliberately narrow: LITERAL (this one topic, never a prefix) and READ+DESCRIBE only (the
    consumer can read the events, never WRITE into the publisher's namespace or forge them). The
    consumer keeps its consumer-group AND its dead-letter topic in its OWN <consumer>.* namespace
    (already covered by provision), so this single foreign-topic READ is the ONLY grant it needs.
    Idempotent: create_acls on an already-present binding is a success no-op, so re-running (a
    from-scratch cluster rebuild, a re-provision) is safe.
    """
    principal = f"User:proj_{consumer_project}"
    ac = _admin()
    acls = [
        AclBinding(ResourceType.TOPIC, topic, ResourcePatternType.LITERAL, principal, "*", op, AclPermissionType.ALLOW)
        for op in (AclOperation.READ, AclOperation.DESCRIBE)
    ]
    for future in ac.create_acls(acls).values():
        try:
            future.result(timeout=10)
        except KafkaException as exc:
            raise BusError(str(exc)) from exc
    return {"granted": True, "principal": principal, "topic": topic, "operations": ["READ", "DESCRIBE"]}
