"""Terminal dashboard for the recovery run: a live view of the hunt and the remediation.

Built on Rich so it runs the same on macOS, Linux and Windows Terminal. It plugs into
Strands twice: as a hook provider (tool calls start and finish) and as the callback
handler (streamed model text). It renders four regions: a header with the phase
track, the tool trace, the evidence board the tools fill in, and the analyst's
narration. A footer shows the live state of a blocking wait (approval, restore).
"""

from __future__ import annotations

import json
import time
from collections import deque
from datetime import datetime
from typing import Any

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from strands.hooks import (AfterInvocationEvent, AfterToolCallEvent, BeforeInvocationEvent,
                           BeforeToolCallEvent, HookProvider, HookRegistry)

import tools_eon

PHASES = ["IDENTIFY", "EVIDENCE", "STAKES", "CONTAIN", "RECOVERY POINT", "APPROVAL",
          "RESTORE", "VERIFY", "PROVE"]
TOOL_PHASE = {
    "eon_get_resource": "IDENTIFY",
    "eon_get_scan_verdict": "EVIDENCE", "eon_list_findings": "EVIDENCE",
    "eon_list_infected_snapshots": "EVIDENCE", "eon_list_snapshots": "EVIDENCE",
    "eon_get_classification": "STAKES",
    "eon_hold_snapshot": "CONTAIN",
    "eon_select_clean_snapshots": "RECOVERY POINT", "eon_list_restore_accounts": "RECOVERY POINT",
    "eon_request_restore": "APPROVAL", "eon_wait_for_approval": "APPROVAL",
    "eon_execute_approved_restore": "RESTORE", "eon_wait_for_restore": "RESTORE",
    "aws_verify_not_public": "VERIFY",
    "aws_prove_recovery": "PROVE",
}
SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

C_BG = "on black"
C_DIM = "grey50"
C_ACCENT = "bright_cyan"
C_OK = "bright_green"
C_WARN = "yellow"
C_BAD = "bright_red"
C_MAG = "bright_magenta"


def _short(s: Any, n: int = 10) -> str:
    s = str(s or "")
    return s[:n] if len(s) > n else s


def _hms(seconds: float) -> str:
    seconds = int(seconds)
    return f"{seconds // 60:02d}:{seconds % 60:02d}"


class Dashboard(HookProvider):
    def __init__(self, attendee: str, bucket: str, model: str, console: Console | None = None):
        self.attendee, self.bucket, self.model = attendee, bucket, model
        self.console = console or Console()
        self.started = time.time()
        self.phase = PHASES[0]
        self.done_phases: set[str] = set()
        self.trace: deque[Text] = deque(maxlen=200)
        self.evidence: dict[str, tuple[str, str]] = {}   # label -> (value, style)
        self.analyst = ""
        self.threat: str | None = None       # banner text
        self.threat_style = C_WARN
        self.tool_calls = 0
        self.tool_started: dict[str, float] = {}
        self.finished = False
        self.final_text = ""
        self._live: Live | None = None

    # ------------------------------------------------------------ strands plumbing

    def register_hooks(self, registry: HookRegistry, **_: Any) -> None:
        registry.add_callback(BeforeInvocationEvent, self._on_start)
        registry.add_callback(AfterInvocationEvent, self._on_end)
        registry.add_callback(BeforeToolCallEvent, self._on_tool_start)
        registry.add_callback(AfterToolCallEvent, self._on_tool_end)

    def callback(self, **kwargs: Any) -> None:
        data = kwargs.get("data")
        if data:
            self.analyst += data
        if kwargs.get("complete") and self.analyst and not self.analyst.endswith("\n"):
            self.analyst += "\n"

    def _on_start(self, event: BeforeInvocationEvent) -> None:
        self._log(Text.assemble(("▶ ", C_ACCENT), ("agent online  ", "bold " + C_ACCENT),
                                (f"model {self.model}", C_DIM)))

    def _on_end(self, event: AfterInvocationEvent) -> None:
        self.finished = True
        self.final_text = self.analyst
        self._log(Text.assemble(("■ ", C_ACCENT), ("run complete  ", "bold " + C_ACCENT),
                                (f"{self.tool_calls} tool calls, {_hms(time.time() - self.started)}", C_DIM)))

    def _on_tool_start(self, event: BeforeToolCallEvent) -> None:
        use = getattr(event, "tool_use", None) or {}
        name = use.get("name", "?")
        tid = use.get("toolUseId", "")
        self.tool_started[tid] = time.time()
        self.tool_calls += 1
        phase = TOOL_PHASE.get(name)
        if phase and phase != self.phase:
            self.done_phases.add(self.phase)
            self.phase = phase
        args = use.get("input") or {}
        arg_s = ", ".join(f"{k}={_short(v, 28)}" for k, v in args.items()
                          if k not in ("reason",))[:70]
        self._log(Text.assemble(("  ↳ ", C_DIM), (name, "bold white"), (f"  {arg_s}", C_DIM)))
        if self.analyst and not self.analyst.endswith("\n"):
            self.analyst += "\n"

    def _on_tool_end(self, event: AfterToolCallEvent) -> None:
        use = getattr(event, "tool_use", None) or {}
        name = use.get("name", "?")
        tid = use.get("toolUseId", "")
        ms = int((time.time() - self.tool_started.pop(tid, time.time())) * 1000)
        result = getattr(event, "result", None) or {}
        text = ""
        for block in (result.get("content") or []) if isinstance(result, dict) else []:
            if isinstance(block, dict) and "text" in block:
                text = block["text"]
                break
        payload: dict = {}
        try:
            payload = json.loads(text) if text else {}
        except json.JSONDecodeError:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        err = payload.get("error") is True or (isinstance(result, dict) and result.get("status") == "error")
        summary, style = self._digest(name, payload, err)
        glyph = ("✖", C_BAD) if err else ("✔", C_OK)
        self._log(Text.assemble(("    ", ""), glyph, (f" {ms / 1000:.1f}s  ", C_DIM), (summary, style)))

    # ------------------------------------------------------------ evidence digest

    def _digest(self, name: str, p: dict, err: bool) -> tuple[str, str]:
        if err:
            return (_short(p.get("detail") or p.get("error") or "error", 60), C_BAD)
        ev = self.evidence
        if name == "eon_get_resource":
            r = p.get("resource") or {}
            tags = r.get("tags") or {}
            ev["Resource"] = (f"{r.get('name')}  ({r.get('type')})", "bold white")
            ev["Environment"] = (str(r.get("environment") or tags.get("env") or "?"), "white")
            ev["Owner / app"] = (f"{tags.get('owner', '?')} / {tags.get('app', '?')}", "white")
            ev["Tagged data"] = (f"{tags.get('data-class', '?')}  {tags.get('compliance', '')}", "white")
            ev["Detection"] = (str(r.get("threatDetection")), C_OK if r.get("threatDetection") == "ASSIGNED" else C_WARN)
            return (f"{r.get('name')} in {r.get('account')}", "white")
        if name == "eon_get_scan_verdict":
            last = p.get("lastScan") or {}
            concl = last.get("conclusion") or "?"
            bad = concl in tools_eon.INFECTED_CONCLUSIONS
            ev["Verdict"] = (concl, C_BAD if bad else C_OK)
            just = (last.get("justification") or "")
            if just:
                ev["Justification"] = (_short(just.replace("\n", " "), 90), C_DIM)
            if bad:
                self.threat, self.threat_style = f"THREAT CONFIRMED  {concl}", C_BAD
            return (concl, C_BAD if bad else C_OK)
        if name == "eon_list_findings":
            fs = p.get("findings") or []
            kinds: dict[str, int] = {}
            for f in fs:
                kinds[f.get("evidenceType") or "?"] = kinds.get(f.get("evidenceType") or "?", 0) + 1
            ev["Findings"] = (f"{p.get('totalCount', len(fs))}: " + ", ".join(f"{k} ×{v}" for k, v in kinds.items()), C_BAD)
            return (f"{p.get('totalCount', len(fs))} findings", C_BAD if fs else C_OK)
        if name == "eon_list_infected_snapshots":
            ss = p.get("snapshots") or []
            times = sorted(s.get("pointInTime") or s.get("createdTime") or "" for s in ss)
            ev["Infected snapshots"] = (f"{len(ss)}  earliest {times[0][:19] if times else '-'}", C_BAD if ss else C_OK)
            return (f"{len(ss)} infected snapshots", C_BAD if ss else C_OK)
        if name == "eon_list_snapshots":
            return (f"{p.get('count')} snapshots on the timeline", "white")
        if name == "eon_get_classification":
            cats = p.get("dataCategories") or []
            n = p.get("detectedEntityCount", 0)
            label = ", ".join(cats) if cats else ("erased by encryption" if p.get("latestScanInfected") else "none detected")
            ev["Classified data"] = (f"{label}  ({n} entities)", C_MAG if cats else C_WARN)
            return (f"{label}, {n} entities", C_MAG if cats else C_WARN)
        if name == "eon_hold_snapshot":
            held = ev.get("Held snapshots", ("0", C_OK))
            ev["Held snapshots"] = (str(int(held[0]) + 1), C_OK)
            return (f"hold on {_short(p.get('snapshotId'), 8)}", C_OK)
        if name == "eon_select_clean_snapshots":
            items = p.get("items") or []
            it = items[0] if items else {}
            snap = it.get("snapshotId") or it.get("snapshot", {}).get("id") or "-"
            when = (it.get("pointInTime") or it.get("snapshot", {}).get("pointInTime") or "")[:19]
            status = it.get("status") or ""
            ok = bool(snap and snap != "-" and "NO_CLEAN" not in status)
            ev["Recovery point"] = (f"{_short(snap, 8)}  {when}" if ok else "NO CLEAN SNAPSHOT", C_OK if ok else C_BAD)
            return (f"clean snapshot {_short(snap, 8)} at {when}" if ok else "no clean snapshot", C_OK if ok else C_BAD)
        if name == "eon_list_restore_accounts":
            t = next((a for a in p.get("accounts") or [] if a.get("designatedRecoveryTarget")), {})
            ev["Destination"] = (f"{t.get('name', '?')}  {t.get('providerAccountId', '')}  isolated", C_OK if t else C_BAD)
            return (f"isolated target {t.get('providerAccountId', '?')}", C_OK if t else C_BAD)
        if name == "eon_request_restore":
            rid = p.get("approvalRequestId")
            ev["Approval request"] = (f"{_short(rid, 8)}  {'duplicate, reused' if p.get('duplicate') else 'submitted'}", C_WARN)
            self.threat, self.threat_style = "RESTORE INTERCEPTED  awaiting human approval", C_WARN
            return (f"intercepted → request {_short(rid, 8)}", C_WARN)
        if name == "eon_wait_for_approval":
            st = p.get("status")
            ok = st == "APPROVED"
            ev["Approval"] = (f"{st} after {_hms(p.get('waitedSeconds', 0))}", C_OK if ok else C_BAD)
            self.threat, self.threat_style = (("APPROVED  recovery authorised", C_OK) if ok else (f"{st}  recovery not authorised", C_BAD))
            return (f"{st} after {_hms(p.get('waitedSeconds', 0))}", C_OK if ok else C_BAD)
        if name == "eon_execute_approved_restore":
            ev["Restore job"] = (_short(p.get("restoreJobId"), 8) + "  running", C_ACCENT)
            return (f"restore job {_short(p.get('restoreJobId'), 8)} started", C_ACCENT)
        if name == "eon_wait_for_restore":
            st = p.get("status")
            ok = st == "JOB_COMPLETED"
            ev["Restore job"] = (f"{st} in {_hms(p.get('waitedSeconds', 0))}", C_OK if ok else C_BAD)
            return (f"{st} → {p.get('recoveryBucket')}" if ok else f"{st}: {p.get('error')}", C_OK if ok else C_BAD)
        if name == "aws_verify_not_public":
            exp = p.get("exposed")
            ev["Exposure check"] = ("NOT PUBLIC" if exp is False else "EXPOSED", C_OK if exp is False else C_BAD)
            return ("not publicly exposed" if exp is False else "EXPOSED", C_OK if exp is False else C_BAD)
        if name == "aws_prove_recovery":
            clean = p.get("clean")
            e = p.get("entropy") or {}
            ev["Proof"] = (f"{'CLEAN' if clean else 'FAILED'}  {p.get('objectCount')} objects, entropy mean {e.get('mean')} max {e.get('max')} (threshold {e.get('threshold')})", C_OK if clean else C_BAD)
            self.threat, self.threat_style = (("RECOVERED AND PROVEN", C_OK) if clean else ("PROOF FAILED", C_BAD))
            return (f"{'clean' if clean else 'NOT clean'}: entropy mean {e.get('mean')} max {e.get('max')}", C_OK if clean else C_BAD)
        return (_short(json.dumps(p), 60), C_DIM)

    # ------------------------------------------------------------ rendering

    def _log(self, t: Text) -> None:
        stamp = Text(datetime.now().strftime("%H:%M:%S "), style=C_DIM)
        self.trace.append(stamp + t)

    def _header(self) -> Panel:
        track = Text()
        for i, ph in enumerate(PHASES):
            if ph == self.phase and not self.finished:
                track.append(f" {ph} ", style=f"bold black on {C_ACCENT}")
            elif ph in self.done_phases or self.finished:
                track.append(f" {ph} ", style=C_OK)
            else:
                track.append(f" {ph} ", style=C_DIM)
            if i < len(PHASES) - 1:
                track.append("▸", style=C_DIM)
        title = Text.assemble(("EON", f"bold {C_ACCENT}"), (" // ", C_DIM),
                              ("AGENTIC RECOVERY", "bold white"), ("   ", ""),
                              (f"analyst {self.attendee}", C_DIM), ("   ", ""),
                              (f"target {self.bucket}", C_MAG), ("   ", ""),
                              (f"T+{_hms(time.time() - self.started)}", C_DIM))
        return Panel(Group(title, Align.center(track)), box=box.HEAVY, border_style=C_ACCENT, padding=(0, 1))

    def _trace_panel(self, height: int) -> Panel:
        rows = list(self.trace)[-(max(height - 2, 1)):]
        return Panel(Group(*rows) if rows else Text("waiting…", style=C_DIM), title="[bold]TRACE[/]",
                     subtitle=f"[{C_DIM}]{self.tool_calls} tool calls[/]", box=box.ROUNDED,
                     border_style=C_DIM, padding=(0, 1))

    def _evidence_panel(self) -> Panel:
        t = Table.grid(padding=(0, 1), expand=True)
        t.add_column(style=C_DIM, no_wrap=True, width=19)
        t.add_column(ratio=1)
        for label, (value, style) in self.evidence.items():
            t.add_row(label, Text(value, style=style))
        if not self.evidence:
            t.add_row("", Text("no evidence yet", style=C_DIM))
        body: Any = t
        if self.threat:
            banner = Panel(Align.center(Text(self.threat, style=f"bold {self.threat_style}")),
                           box=box.HEAVY, border_style=self.threat_style, padding=(0, 1))
            body = Group(banner, t)
        return Panel(body, title="[bold]EVIDENCE[/]", box=box.ROUNDED, border_style=C_MAG, padding=(0, 1))

    def _analyst_panel(self, height: int) -> Panel:
        lines = self.analyst.rstrip("\n").splitlines()
        n = max(height - 2, 1)
        text = Text("\n".join(lines[-n:]), style="white")
        return Panel(text, title="[bold]ANALYST[/]", box=box.ROUNDED, border_style=C_ACCENT, padding=(0, 1))

    def _footer(self) -> Panel:
        pr = tools_eon.progress
        spin = SPINNER[int(time.time() * 8) % len(SPINNER)]
        if pr.get("phase") == "approval":
            msg = Text.assemble((f"{spin} ", C_WARN), ("AWAITING HUMAN APPROVAL  ", f"bold {C_WARN}"),
                                (f"request {_short(pr.get('requestId'), 8)}  status {pr.get('status')}  ", "white"),
                                (f"waiting {_hms(time.time() - pr.get('started', time.time()))}", C_DIM))
        elif pr.get("phase") == "restore":
            msg = Text.assemble((f"{spin} ", C_ACCENT), ("RESTORE IN PROGRESS  ", f"bold {C_ACCENT}"),
                                (f"job {_short(pr.get('jobId'), 8)}  status {pr.get('status')}  ", "white"),
                                (f"running {_hms(time.time() - pr.get('started', time.time()))}", C_DIM))
        elif self.finished:
            msg = Text("RUN COMPLETE  incident report below", style=f"bold {C_OK}")
        else:
            msg = Text.assemble((f"{spin} ", C_ACCENT), ("agent reasoning…", C_DIM))
        return Panel(msg, box=box.HEAVY, border_style=C_DIM, padding=(0, 1))

    def render(self) -> Layout:
        h = self.console.size.height
        layout = Layout()
        layout.split_column(Layout(name="header", size=4), Layout(name="body", ratio=1),
                            Layout(name="footer", size=3))
        layout["body"].split_row(Layout(name="trace", ratio=5), Layout(name="right", ratio=4))
        body_h = max(h - 7, 10)
        layout["right"].split_column(Layout(name="evidence", ratio=3), Layout(name="analyst", ratio=2))
        layout["header"].update(self._header())
        layout["trace"].update(self._trace_panel(body_h))
        layout["evidence"].update(self._evidence_panel())
        layout["analyst"].update(self._analyst_panel(int(body_h * 0.4)))
        layout["footer"].update(self._footer())
        return layout

    def __enter__(self) -> "Dashboard":
        self._live = Live(get_renderable=self.render, console=self.console, refresh_per_second=8,
                          screen=True, transient=True)
        self._live.__enter__()
        return self

    def __exit__(self, *exc) -> None:
        if self._live:
            self._live.__exit__(*exc)
            self._live = None
