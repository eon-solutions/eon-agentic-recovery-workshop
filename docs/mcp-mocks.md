# Going further: mock MCP servers

This part is optional. If your agent has already recovered and proven your bucket, you
have time to make the workflow your own. Three mock enterprise systems are running for the
workshop as MCP servers: threat intelligence, IT service management with a CMDB, and a data
catalog with lineage. Use your coding assistant (Claude Code, Cursor, Copilot, whatever you
brought) to wire one or more of them into the agent, and see how the investigation, the
restore request and the proof change.

The agent does not use them out of the box. Deciding where they belong is the exercise.

## What is running

Your `.env` carries the addresses and a token for your seat:

| Variable | Server |
|---|---|
| `MCP_THREAT_INTEL_URL` | Threat intelligence |
| `MCP_ITSM_URL` | IT service management and CMDB |
| `MCP_LINEAGE_URL` | Data catalog and lineage |
| `MCP_TOKEN` | Bearer token for all three, valid for your seat only |

They speak MCP over streamable HTTP and expect `Authorization: Bearer $MCP_TOKEN` on every
request. The organisation behind them, its people and its intelligence are fictional. The
bucket, the attack times, the snapshot times and the object checksums are real for your seat.
Each server answers only about your own bucket.

### Threat intelligence

| Tool | What it returns |
|---|---|
| `lookup_indicator` | Enrichment for a ransom note name, file extension, IP, access key id or actor name |
| `get_threat_actor` | Extortion model, dwell time, ATT&CK techniques, behaviours, decryptor availability |
| `get_asset_sightings` | What the feed saw against your bucket: first access, reads and exfiltration, writes, persistence |

Why it matters: Eon tells you when the data changed. The feed tells you when the intruder
arrived, which is usually much earlier, and whether data left before it was encrypted. That
turns some incidents from an outage into a breach with a notification clock. It also tells you
whether the attacker kept a way back in, which matters for where the restored data can go.

### IT service management and CMDB

| Tool | What it returns |
|---|---|
| `get_configuration_item` | Business service, owner, on-call, criticality, RPO and RTO, recovery and change policy |
| `create_incident`, `get_incident`, `update_incident` | Incident records for your seat |
| `create_change_request`, `get_change_request`, `close_change_request` | Change records, with the approval rules below |

The rules are enforced. A restore into the isolated recovery account is covered by an
incident. Putting data back into production needs an emergency change linked to a P1 or P2
incident, with an implementation plan and a backout plan. A standard change for a tier 1 or 2
bucket is refused. An emergency change is authorised by the emergency CAB about a minute after
it is raised, so your agent has to come back for it.

Why it matters: Eon knows the bucket's tags. The CMDB knows the RPO the business signed up
for, so you can measure the data you lost against it. It also tells you who has to approve,
and gives you incident and change numbers that belong in the restore request.

### Data catalog and lineage

| Tool | What it returns |
|---|---|
| `get_dataset` | Every object's profile from before the attack: sha256, MD5, size, rows, columns and their data classes |
| `get_object_profile` | The same for one key, plus what the catalog makes of keys it does not know |
| `get_lineage` | The producer that writes into the bucket, and every consumer run since the attack |
| `request_backfill`, `list_backfill_requests` | Reprocessing requests for downstream consumers |

Why it matters: the catalog's profiles were taken before the attack, so you can prove the
recovered copy is the same data the business had, byte for byte, without trusting Eon or an
entropy threshold. For these objects the MD5 equals the S3 ETag, so a `HeadObject` on the
recovered copy is enough to compare. Lineage shows what else the attack reached: consumers
that kept running on ciphertext need a backfill before the incident is over.

## Ideas

- **Investigate.** Bound the intrusion from the first access, not only the first write.
  Decide whether this is a breach, and say so in the report.
- **Remediate.** Open an incident with the right impact. Put its number and the CMDB's
  approvers in the restore request's reasoning. Raise the emergency change for returning the
  data to production, and wait for it to be authorised.
- **Validate.** Compare every recovered object against the catalog. Check which objects are
  missing or renamed. List the consumers that need a backfill, and file the requests.
- **Report.** Measure the data loss window against the CMDB's RPO. Close the loop on the
  incident with the evidence.

## Connecting

From Python, inside the agent: the kit already includes the Strands Agents SDK and its MCP
client, so nothing needs installing.

```python
import os
from strands.tools.mcp import MCPClient

threat_intel = MCPClient(
    url=os.environ["MCP_THREAT_INTEL_URL"],
    headers={"Authorization": f"Bearer {os.environ['MCP_TOKEN']}"},
    prefix="threat_intel",
)
```

Pass the client in the agent's tool list next to the Eon and AWS tools, or open it with
`with threat_intel:` and call `threat_intel.list_tools_sync()`.

From Claude Code, to explore a server before you write any code (macOS and Linux, from the
kit folder):

```sh
set -a; . ./.env; set +a
claude mcp add --transport http threat-intel "$MCP_THREAT_INTEL_URL" \
  --header "Authorization: Bearer $MCP_TOKEN"
```

The token belongs in `.env` and nowhere else. Do not commit it, and remove the server
configuration from your assistant when you leave. The servers, like your seat's other
credentials, stop working after the workshop.
