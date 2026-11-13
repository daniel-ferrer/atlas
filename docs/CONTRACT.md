# Client contract

Atlas is called by a client, in practice [Otto](#about-the-client), that shows host state to
an operator and lets them approve a small set of host actions. This file is the contract
between them. The client and Atlas each enforce it independently: neither trusts the other's
validation.

## Division of responsibility

| The client | Atlas |
|---|---|
| Shows the operator the exact command, consequence and expiry | Re-derives the command from the target and compares it byte for byte |
| Requires two steps: request, then approve | Refuses anything not explicitly enabled and allowlisted on the host |
| Keeps its own audit of requests and decisions | Keeps the authoritative execution audit, written before acting |
| Never falls back to a local command or an agent | Never executes the command string it receives |

## Actions: `POST /api/actions`

Authenticated with the Bearer token; no redirects. Body:

```json
{"id":"ha_<uuid>","kind":"restart-unit","target":{"unit":"nginx.service"},"command":"systemctl restart nginx.service"}
```

| Kind | Target | Canonical command |
| --- | --- | --- |
| `restart-unit` | `{unit: "nginx.service"}` | `systemctl restart nginx.service` |
| `restart-container` | `{name: "demo"}` | `docker restart demo` |
| `kill-process` | `{pid: 12345, user: "<service-user>", command: "/usr/bin/sleep 100", startedAt: 1792195200000}` | `kill -TERM 12345` |
| `run-maintenance` | `{task: "backup-unlock"}` or `{task: "backup-cache-dir"}` | `systemctl start otto-maint-backup-unlock.service` or `systemctl start otto-maint-backup-cache-dir.service` |
| `apt-upgrade` | `{}` | `env DEBIAN_FRONTEND=noninteractive apt-get update && env DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade` |

`startedAt` is Unix milliseconds, estimated from uptime. Each displayed command corresponds to
an argv that runs without a shell; the explicit `env` prefix is deliberate. For apt, the second
argv runs only after the first exits zero (`&&` is a display separator).

Atlas must:

1. **Validate independently.** Apply its own allowlists, target validation, protected unit
   identities (including aliases), permissions and per-kind enable switch. Re-derive argv,
   compare its canonical display to `command` byte for byte, and refuse a mismatch with 409
   before executing. Reject extra fields, missing identity, stale or nonexistent targets, and
   unsafe or disabled actions.
2. **Audit before acting.** Durably reserve the request `id` and audit the action before
   executing. Reject every reused id with 409, even across restarts. If the audit write fails,
   do not act.
3. **Execute safely.** No shell; bounded output. For process stops, re-verify user, command and
   start time (within 5 seconds) immediately before signalling, through a stable handle (a Linux
   pidfd) so pid reuse can't redirect the signal. Refuse with 409 `process changed` on mismatch.
   Independently protect root, kernel, client and Atlas processes.
4. **Report honestly.** Await completion and return 200 `{id, ok, exitCode, output}`, where
   `output` is a bounded tail and `ok: true` means every command succeeded. Return 404 when
   actions are disabled. 400/401/403/409/422 mean **nothing executed**. Once execution has
   begun, a failure is 200 `ok: false`; an ambiguous outcome is 5xx. Never return a refusal
   status after a side effect.
5. **Limit itself.** Serialize actions host-side, apply resource limits and least privilege.
   A client disconnect or timeout is not a cancellation. Client timeouts are 90 seconds for
   restarts, 15 seconds for SIGTERM, 15 minutes for maintenance and 30 minutes for apt, with no
   retries, so Atlas's HTTP server must allow an action response to take 30 minutes.

Client side, an explicit `ok: true` is the only "done". A refusal or connection refusal is
"failed, not run". A timeout, 5xx, redirect, unreadable response or mismatched id is
"unknown: check the host before retrying".

## Evidence reads

The client uses these to investigate an alert. Both are read-only.

- **`GET /api/journal?unit=<service-or-timer>&lines=200`.** Validate the unit, bound lines to
  1–300, filter on the host before taking the tail, and return `{lines:[{ts,unit,priority,message}]}`.
  A short tail is not proof that older failures never happened.
- **`GET /api/config?id=…`.** Allowed ids are `unit:<unit>` (the unit definition, read with fixed
  argv) and `backup-env` (mapped host-side to `/etc/restic/env`). No arbitrary paths or ids, no
  variable expansion. Atlas redacts credentials, tokens, URL userinfo and private keys **before**
  serializing and returns `{id,path,content,redacted:true}`. It never returns raw config on the
  promise that the client will redact it. The client redacts again anyway.

## Maintenance tasks

`run-maintenance` maps `backup-unlock` and `backup-cache-dir` to two fixed oneshot units. Atlas
validates only `{task}`, re-derives `systemctl start <unit>`, compares command bytes, and refuses
with a 4xx before execution if the unit is unknown, not installed, an alias, not a oneshot, or
lacks privileges. Starting the oneshot waits for it to exit. The same id reservation, audit,
serialization and output bounds apply as for every other action.

The operator writes and reviews the two units on the host. Example for a root-run restic setup:

```ini
# /etc/systemd/system/otto-maint-backup-unlock.service
[Unit]
Description=Remove stale restic locks after operator approval

[Service]
Type=oneshot
User=root
EnvironmentFile=/etc/restic/env
ExecCondition=/bin/sh -c '! /usr/bin/systemctl is-active --quiet home-backup.service'
ExecStart=/usr/bin/restic unlock
TimeoutStartSec=14min
UMask=0077
```

`restic unlock` removes stale locks only; never add `--remove-all`. The second task,
`backup-cache-dir`, runs a reviewed helper that sets `RESTIC_CACHE_DIR` only when it is not
already configured. Granting Atlas permission to start exactly these units is covered in the
[actions runbook](../deploy/actions/README.md).

## About the client

Otto is my self-hosted AI command center. On the same server, it uses Atlas for its Server
dashboard, health alerts, read-only answers to questions about the host, and alert
investigations that can propose one of the actions above for the operator to approve. A
proposed fix never approves itself. Otto is private; this contract is everything Atlas needs
from it.
