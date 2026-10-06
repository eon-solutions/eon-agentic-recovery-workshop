"""Amazon Bedrock AgentCore Runtime entrypoint for the same agent.

The laptop run and the hosted run share build_agent; only the front door differs. On
AgentCore the Eon credential comes from Secrets Manager (EON_SECRET_ARN) rather than a
.env file, and there is no terminal dashboard, so the response is the incident report.

    pip install bedrock-agentcore
    agentcore configure -e agent/agentcore_app.py && agentcore launch
    agentcore invoke '{"bucket": "<your-bucket>"}'
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bedrock_agentcore import BedrockAgentCoreApp  # noqa: E402

from agent import build_agent, incident_task  # noqa: E402

app = BedrockAgentCoreApp()


@app.entrypoint
def invoke(payload: dict, context=None) -> dict:
    bucket = payload.get("bucket")
    prompt = payload.get("prompt") or (incident_task(bucket) if bucket else None)
    if not prompt:
        return {"error": "pass {\"bucket\": \"<victim bucket>\"} or {\"prompt\": \"...\"}"}
    agent = build_agent(callback_handler=None)
    result = agent(prompt)
    return {"bucket": bucket, "report": str(result)}


if __name__ == "__main__":
    app.run()
