# Local Team controller v1

`Dockerfile.local` packages the single-owner controller installed by `install.shimpz.com`. It is a
local projection of the shared Team controller domain, not a lifecycle-only Docker wrapper. It owns
Team/Assistant containers, submits turns to the separate Brain runtime, mediates Assistant Powers,
enforces egress policy, stores Team files and inference selection, and coordinates secrets, OAuth
accounts, and approval challenges.

The Admin never receives the Docker socket or controller bearer. It mounts the token volume read-only
and calls port `7077` over the private control network. Brain runtime receives only a separate runtime
bearer and has no Docker socket, Assistant credentials, or direct internet route. Assistant traffic can
leave only through the deny-by-default egress proxy policy written by this controller.

## Owned resources and identity

Every managed network and Assistant container carries these ownership labels:

- `com.shimpz.local.managed=1`
- `com.shimpz.local.profile=single-owner-local-v1`
- `com.shimpz.local.space-id=$SHIMPZ_SPACE_ID`
- a fixed resource kind plus the Team/Assistant identity used to derive its deterministic Docker name
- Team networks also carry the validated 1–80 character display name used by Admin

Unknown, partly labeled, foreign-Space, or incorrectly named Docker resources are never adopted or
removed. Team mutation is serialized. `DELETE /v1/space` selects only the complete ownership label set,
removes Assistant containers before Team networks/state, and is safe to retry after a partial daemon
failure. It does not remove shared images, the controller container, or unlabeled resources.

## Runtime boundary

- Required identity: `SHIMPZ_SPACE_ID`, a stable lowercase/dash-separated value of at most 48 bytes.
- HTTP: port `7077`, private Compose networking only. Every route—including `/healthz`—requires
  `Authorization: Bearer <controller token>`.
- Process: UID/GID `10001:10001`, supplementary token GID `10010`, read-only root filesystem, bounded
  tmpfs, resources, request bodies, queues, and audit output.
- Docker: `/var/run/docker.sock` is mounted only here. Compose supplies the socket's numeric host GID.
- Controller bearer: created atomically as 32 random bytes encoded to 64 lowercase hex characters at
  `/run/shimpz-local/token`, `10001:10010`, mode `0440`, never environment/argv/log output.
- Brain bearer/state: the controller writes the dedicated runtime token volume; Brain runtime mounts it
  read-only. Conversation checkpoints stay in the Brain runtime state volume.
- Persistent controller state: audit, Team storage, inference selection, Power journal, Assistant secret
  state/key, account state/key, remembered approvals, and egress policies each use dedicated paths or
  volumes. Secrets and account tokens are encrypted at rest and never enter metadata-only audit JSONL.
- Model credentials: Admin supplies `X-Shimpz-Model-Provider` and `X-Shimpz-Model-Api-Key` only on chat
  and challenge-resume requests. Strict HTTP parsing rejects duplicate/missing credentials. The key is
  used for that operation and is never persisted, echoed, or forwarded to Assistant containers.

The image healthcheck reads the controller bearer and performs authenticated `GET /healthz` on loopback.

## HTTP API

All request targets reject query strings, encoded path ambiguity, oversized paths, duplicate critical
headers, unexpected bodies, malformed JSON, and unknown body fields. Responses are bounded JSON with a
metadata-only `trace_id` added at the HTTP boundary.

### Space, Teams, Assistants, and files

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | authenticated process/registry health |
| `GET` | `/v1/assistants` | trusted installable Assistant registry |
| `GET` | `/v1/teams` | running Team inventory |
| `POST` | `/v1/teams/{team_id}/create` | idempotently create a named Team network/state |
| `DELETE` | `/v1/teams/{team_id}` | idempotently remove its Assistants and owned state |
| `GET` | `/v1/teams/{team_id}/assistants` | installed Assistant status inventory |
| `POST` | `/v1/teams/{team_id}/assistants` | install one trusted Assistant ID/digest |
| `DELETE` | `/v1/teams/{team_id}/assistants/{assistant_id}` | uninstall one owned Assistant |
| `GET` | `/v1/teams/{team_id}/assistants/{assistant_id}/help[/{locale}]` | validated localized Assistant help |
| `POST` | `/v1/teams/{team_id}/assistants/{assistant_id}/powers/{power_id}` | invoke one declared Power directly |
| `GET` | `/v1/teams/{team_id}/files` | list opaque Team file metadata and quota |
| `POST` | `/v1/teams/{team_id}/files` | upload one bounded base64 object |
| `DELETE` | `/v1/teams/{team_id}/files/{opaque_id}` | delete one Team-owned object |
| `DELETE` | `/v1/space` | installer reset of every exactly owned resource |

Team storage allows at most 100 MiB of payload, 256 files, and 25 MiB per upload. Storage is not mounted
into Admin, Brain runtime, or Assistants. Quota reservation and SQLite page limits are transactional.

### Inference and chat

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/v1/teams/{team_id}/inference` | read the Team's provider/model selection |
| `PUT` | `/v1/teams/{team_id}/inference` | replace the validated provider/model selection |
| `POST` | `/v1/teams/{team_id}/chat` | start one bounded Brain turn |
| `GET` | `/v1/teams/{team_id}/chat/accounts` | inspect the pending account gate |
| `POST` | `/v1/teams/{team_id}/chat/accounts` | resume after the exact account challenge completes |
| `GET` | `/v1/teams/{team_id}/chat/secrets` | inspect the pending secret gate |
| `POST` | `/v1/teams/{team_id}/chat/secrets` | submit values for the exact pending secret challenge |
| `GET` | `/v1/teams/{team_id}/chat/approval` | inspect the pending approval gate |
| `POST` | `/v1/teams/{team_id}/chat/approval` | approve the exact pending Power challenge |
| `POST` | `/v1/teams/{team_id}/chat/stop` | cancel active or challenge-paused work |

Chat accepts only `message`, opaque file IDs, and selected installed Assistant IDs. A Team has at most
one active/paused turn. Selection and workload identity are revalidated before provider start, each
Power, resume, and completion. Brain runtime returns either a terminal reply or a bounded secret,
account, or approval suspension; the controller alone executes Powers and resumes the checkpoint.

### Assistant secret, approval, and account administration

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/v1/teams/{team_id}/assistant-secrets` | masked configured-secret inventory |
| `PUT` | `/v1/teams/{team_id}/assistant-secrets` | replace one Assistant's encrypted secret set |
| `GET` | `/v1/teams/{team_id}/assistant-approvals` | list remembered Assistant/Power grants |
| `DELETE` | `/v1/teams/{team_id}/assistant-approvals` | revoke every remembered grant for the Team |
| `GET` | `/v1/teams/{team_id}/assistant-accounts` | list redacted connected-account state |
| `POST` | `/v1/teams/{team_id}/assistant-accounts/challenges/{challenge_id}/authorize` | start bounded OAuth authorization |
| `DELETE` | `/v1/teams/{team_id}/assistant-accounts/{assistant_id}/{account_id}` | disconnect and delete one credential |
| `POST` | `/v1/oauth/cloudflare/callback` | redeem the broker claim bound to the Admin session |

OAuth authorization material crosses the dedicated broker path, never chat frames. The controller
stores only encrypted account credentials, returns redacted metadata, binds claims/challenges to one
Team and Admin session, and deletes local and broker state on disconnect or Team teardown.

## Assistant execution

The trusted registry binds an Assistant ID to one immutable image digest. A missing digest may be pulled,
then repository digest and Assistant image labels are revalidated before creation. The fixed adapter
accepts only declared `POST /v1/powers/{power-id}` routes and its health probe; neither browser input nor
the Assistant manifest can supply an arbitrary method, URL, command, or container identity.

Assistant containers run as `10001:10001`, with read-only roots, all capabilities dropped,
`no-new-privileges`, default seccomp, no host mounts or published ports, one Team network, and fixed
CPU/memory/PID/file-descriptor limits. Each Power input is schema-validated, approval and secret/account
requirements are enforced before dispatch, output is bounded and schema-validated, and durable journal
state prevents ambiguous retries from silently executing a non-idempotent Power twice.

## Release binding

The source image contains an all-zero first-party Assistant placeholder and fails closed at startup.
Release automation replaces it with the published immutable digest:

```sh
docker build \
  --file team/Dockerfile.local \
  --build-arg SHIMPZ_CLOUDFLARE_ASSISTANT_IMAGE='ghcr.io/theshimpz/shimpz-space@sha256:<digest>' \
  team
```
