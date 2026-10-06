#!/usr/bin/env python3
"""Run the recovery agent on your laptop.

    uv run agent/main.py                 # work the incident on your assigned bucket
    uv run agent/main.py --plain         # no dashboard, plain streamed text
    uv run agent/main.py --ask "what does Eon know about my bucket?"

Reads the .env file in the package root for the Eon credential, the AWS credential,
your bucket and the recovery bucket. Writes the final incident report to runs/.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agent"))
sys.path.insert(0, str(ROOT))

from eonlib.env import load_env  # noqa: E402

load_env()

from rich.console import Console  # noqa: E402
from rich.markdown import Markdown  # noqa: E402
from rich.panel import Panel  # noqa: E402

from agent import DEFAULT_MODEL, build_agent, incident_task  # noqa: E402


def _check_env() -> list[str]:
    need = ["EON_ACCOUNT_DOMAIN", "EON_PROJECT_ID", "EON_RESTORE_ACCOUNT_ID", "VICTIM_BUCKET",
            "RECOVERY_BUCKET", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
    missing = [k for k in need if not os.environ.get(k)]
    # The Eon credential comes from Secrets Manager (EON_SECRET_ARN) or from the env pair.
    if not os.environ.get("EON_SECRET_ARN") and not (
            os.environ.get("EON_CLIENT_ID") and os.environ.get("EON_CLIENT_SECRET")):
        missing.append("EON_SECRET_ARN (or EON_CLIENT_ID + EON_CLIENT_SECRET)")
    return missing


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bucket", default=os.environ.get("VICTIM_BUCKET"))
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--plain", action="store_true", help="no dashboard, plain streamed text")
    ap.add_argument("--ask", help="free-form question instead of the incident runbook")
    args = ap.parse_args()

    console = Console()
    missing = _check_env()
    if missing:
        console.print(f"[red]missing settings in .env: {', '.join(missing)}[/]")
        return 2
    task = (f"Context: your assigned bucket (its provider resource id) is {args.bucket}.\n\n{args.ask}"
            if args.ask else incident_task(args.bucket))
    attendee = os.environ.get("ATTENDEE", "analyst")
    runs = ROOT / "runs"
    runs.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    report_path = runs / f"{stamp}-{args.bucket}.md"

    if args.plain:
        agent = build_agent(model_id=args.model)
        result = agent(task)
        text = str(result)
    else:
        from ui import Dashboard
        dash = Dashboard(attendee=attendee, bucket=args.bucket, model=args.model, console=console)
        agent = build_agent(model_id=args.model, callback_handler=dash.callback, hooks=[dash])
        with dash:
            try:
                result = agent(task)
            except KeyboardInterrupt:
                console.print("[yellow]interrupted[/]")
                return 130
        text = dash.final_text or str(result)
        # After the full-screen dashboard closes, leave the evidence board and report behind.
        console.print(dash._evidence_panel())
        console.print(Panel(Markdown(text), title="[bold]INCIDENT REPORT[/]", border_style="bright_green"))
        console.print(f"[grey50]trace: {dash.tool_calls} tool calls; report saved to {report_path}[/]")

    report_path.write_text(f"# Incident report: {args.bucket}\n\n{stamp}  model {args.model}\n\n{text}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
