# Event format

Every decoy reports to the controller with one JSON shape. The Python model lives in
`common/mirage_common/events.py`, which is the source of truth. This page explains it.

## Sending an event

```
POST http://10.66.0.10:8000/api/events
X-Mirage-Token: <MIRAGE_INGEST_TOKEN>
Content-Type: application/json
```

From Python, use the shared client. It never raises, so a decoy keeps working if the controller is down:

```python
from mirage_common import Event, EventClient, EventType, Source

client = EventClient()  # reads MIRAGE_CONTROLLER_URL and MIRAGE_INGEST_TOKEN
client.send(Event(source=Source.ADMIN_PANEL, event_type=EventType.FILE_ACCESS,
                  src_ip="10.66.0.50", asset="/backup/.env.bak",
                  honeytoken_id="ht-env-ssh-pass-01"))
```

## Fields

| Field | Required | Notes |
|---|---|---|
| `event_id` | no | UUID, generated if missing |
| `timestamp` | no | UTC, generated if missing |
| `source` | yes | `admin-panel`, `ssh`, `s3` |
| `event_type` | yes | see below |
| `src_ip` | yes | attacker address as seen by the decoy |
| `src_port` | no | |
| `session_id` | no | groups events from one SSH/HTTP session |
| `asset` | no | what was touched: URL path, file path, username, `bucket/key` |
| `honeytoken_id` | no | set when a planted secret is involved |
| `attack_techniques` | no | ATT&CK IDs the decoy suggests, e.g. `["T1552.001"]` |
| `details` | no | free-form extras: user agent, command text, status code… |

## Event types

| Type | Meaning |
|---|---|
| `http_request` | any request to a decoy web service |
| `login_attempt` | credentials submitted; put `{"username", "success"}` in `details` |
| `file_access` | a decoy file was read or downloaded |
| `honeytoken_used` | a planted secret was presented back to us (SSH password, AWS key) |
| `session_start` / `session_end` | SSH session lifecycle |
| `command` | a shell command in the SSH decoy; put `{"command": ...}` in `details` |

## Tagging honeytokens

Set `honeytoken_id` only when the planted item was **actually touched or used**. For example, tag a
successful SSH login with the planted password, not a failed one. The IDs are listed in
`config/honeytokens.json`. The controller raises one alert the first time each address touches
each token. Repeats are stored as events only.

## Division of labour

Decoys report **what happened**. The controller decides **what it means**: the trail stage
(`mirage_common.trail.TrailStage`), the ATT&CK/Engage labels, the risk score and the response.
Keep decoys simple.

## Breadcrumb trail stages

| Stage | Trigger |
|---|---|
| 1 `ROBOTS_TXT` | robots.txt read |
| 2 `ENV_BACKUP` | backup .env downloaded |
| 3 `SSH_LOGIN` | SSH login with the .env password |
| 4 `AWS_CREDS_READ` | `~/.aws/credentials` read on the SSH decoy |
| 5 `S3_ACCESS` | fake AWS keys used against MinIO |
| 6 `BAIT_DOWNLOAD` | `passwords.xlsx` downloaded |
