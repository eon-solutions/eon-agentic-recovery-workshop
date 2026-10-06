# Break It, Fix It, Prove It

An agent that works a ransomware incident end to end against a real backup platform:
it investigates the attack Eon detected on your bucket, picks the last clean recovery
point before the intrusion, proposes a restore that a human has to approve, carries
out the approved restore into an isolated account, and then proves the recovered copy
is clean with checks that do not depend on Eon.

Your kit is already configured. The `.env` next to this file carries your seat: your
bucket, your recovery bucket, and credentials that can reach exactly those and nothing
else.

## Run it

You need one tool, `uv`, which installs Python and the dependencies for you.

macOS / Linux:

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
./run.sh
```

Windows (PowerShell):

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
.\run.cmd
```

Or directly: `uv run agent/main.py`. Use `--plain` for a plain text stream instead of
the dashboard, and `--ask "..."` to ask the agent a free question about your bucket.

The run takes about ten minutes. It pauses once, when the restore it proposes is
waiting for a human to approve it. That is the control working: the agent can request
a recovery, it cannot execute one. The report it writes at the end lands in `runs/`.

## What is in the box

| Path | What it is |
|---|---|
| `agent/agent.py` | The agent: a Strands Agents SDK agent on Amazon Bedrock, with the runbook it follows |
| `agent/tools_eon.py` | Its Eon tools: inventory, classification, scan verdicts, findings, snapshots, holds, restore and approval |
| `agent/tools_aws.py` | Its AWS-native checks: public exposure, and entropy plus artefact analysis of the recovered objects |
| `agent/ui.py` | The terminal dashboard |
| `agent/agentcore_app.py` | The same agent as an Amazon Bedrock AgentCore Runtime entrypoint, if you want to host it |
| `eonlib/` | A small Eon REST client; the credential is fetched from AWS Secrets Manager at runtime |

## What your credentials can do

- **Eon**: a role scoped to one resource, your bucket. It can read inventory, scan
  results and snapshots for it, hold its snapshots, and request a restore of it into the
  recovery account only. It cannot see other resources, and it cannot approve anything.
- **AWS**: read the one secret that holds the Eon credential, invoke the Bedrock models the
  agent uses, read your recovery bucket, and write its own log stream. Nothing else.

Both expire after the event.

## License

Licensed under the [Mozilla Public License 2.0](./LICENSE).
