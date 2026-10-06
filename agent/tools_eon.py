"""Eon tools for the workshop recovery agent.

Each tool is one or two REST calls through eonlib and returns JSON text. There is
deliberately no business logic here: the reasoning belongs to the model, and the hard
guardrail (no restore without a human approval) belongs to Eon's action approval rule,
which is enforced server-side and cannot be talked around.

Docstrings are the tool descriptions the model reads, so they carry the operational
detail it needs.
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from strands import tool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from eonlib import EonClient, EonError, MpaIntercepted  # noqa: E402

_client: EonClient | None = None

INFECTED_CONCLUSIONS = ("HIGH_CHANCE_FOR_RANSOMWARE", "MALWARE_DETECTED", "DATA_ANOMALY_DETECTED")

# Live status the UI reads while a long-running tool (approval wait, restore wait) polls.
progress: dict[str, Any] = {}


def client() -> EonClient:
    global _client
    if _client is None:
        _client = EonClient()
    return _client


def _err(exc: Exception) -> str:
    if isinstance(exc, EonError):
        return json.dumps({"error": True, "status": exc.status, "detail": exc.body})
    return json.dumps({"error": True, "detail": str(exc)})


def _slim_resource(r: dict) -> dict:
    cls = r.get("classifications") or {}
    apps = [a.get("name") for a in ((cls.get("appsDetails") or {}).get("apps") or [])]
    dc = (cls.get("dataClassesDetails") or {}).get("dataClasses") or []
    return {
        "resourceId": r.get("id"),
        "name": r.get("resourceName"),
        "providerResourceId": r.get("providerResourceId"),
        "type": r.get("resourceType"),
        "account": r.get("providerAccountId"),
        "accountName": r.get("accountDisplayName"),
        "region": r.get("region"),
        "backupStatus": r.get("backupStatus"),
        "threatDetection": r.get("threatDetection"),
        "apps": apps,
        "dataClasses": dc,
        "environment": (cls.get("environmentDetails") or {}).get("environment"),
        "sensitivity": (cls.get("sensitivityLabelsDetails") or {}).get("sensitivityLevel"),
        "latestSnapshot": r.get("latestSnapshotTime"),
        "tags": r.get("tags"),
    }


# ---------------------------------------------------------------- identify

@tool
def eon_get_resource(provider_resource_id: str) -> str:
    """Look up one resource by its cloud provider ID (a bucket name, an instance ID).

    This is the first call of an investigation: it turns the bucket name you were given
    into the Eon resource UUID every other tool needs, and returns the resource's tags
    (owner, application, environment, data-class, compliance), its backup and detection
    status, and the data classes Eon found.

    Args:
        provider_resource_id: e.g. a bucket name or "i-0abc123def4567890"
    """
    try:
        r = client().resource_by_provider_id(provider_resource_id)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)
    if not r:
        return json.dumps({"found": False, "providerResourceId": provider_resource_id})
    return json.dumps({"found": True, "resource": _slim_resource(r)})


_ENTITY_CATEGORY = {
    "US_SOCIAL_SECURITY_NUMBER": "PII", "US_SSN": "PII", "EMAIL_ADDRESS": "PII",
    "PHONE_NUMBER": "PII", "PERSON": "PII", "US_PASSPORT": "PII", "DATE_TIME": "PII",
    "US_DRIVER_LICENSE": "PII", "IP_ADDRESS": "PII", "LOCATION": "PII",
    "CREDIT_DEBIT_CARD_NUMBER": "FI", "CREDIT_DEBIT_CARD_CVV": "FI",
    "IBAN_CODE": "FI", "BANK_ACCOUNT_NUMBER": "FI", "US_BANK_ROUTING_MICR": "FI",
    "US_BANK_NUMBER": "FI", "SWIFT_CODE": "FI", "CRYPTO": "FI",
    "MEDICAL_LICENSE": "PHI", "US_DEA": "PHI",
    "PASSWORD": "CREDENTIALS", "API_KEY": "CREDENTIALS", "AWS_ACCESS_KEY": "CREDENTIALS",
}


@tool
def eon_get_classification(resource_id: str) -> str:
    """What data Eon classified on the resource: regulated categories (PII, FI, PHI,
    CREDENTIALS), the entity types behind them, and sample file paths and columns.

    This is what makes the incident concrete. A production claims-payout bucket holding
    SSNs and bank account numbers is a different severity from a log archive. Carry it
    into the severity call, the recovery reason reviewers read, and the destination
    decision.

    Eon classifies the LATEST scanned snapshot. If that snapshot is the encrypted one
    the classifier saw ciphertext, so `latestScanInfected` is true and zero entities is
    NOT evidence the data is harmless: the clean snapshot you recover is the copy that
    held the data. In that case reason from the tags (data-class, compliance) and the
    application, and say plainly that encryption erased the live classification.

    Args:
        resource_id: the Eon resource UUID (from eon_get_resource)
    """
    try:
        r = client().call("GET", f"/v1/projects/{{p}}/resources/{resource_id}")
        resource = r.get("resource") or r
        entities_found = client().data_classification_entities(resource_id)
        scans = client().security_scans(resource_id) or {}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)
    cls = resource.get("classifications") or {}
    sens = cls.get("sensitivityLabelsDetails") or {}
    conclusion = (scans.get("lastScan") or {}).get("conclusion")
    latest_infected = conclusion in INFECTED_CONCLUSIONS
    categories: dict[str, int] = {}
    entities: dict[str, int] = {}
    samples = []
    for e in entities_found:
        ent = e.get("entityType", "?")
        entities[ent] = entities.get(ent, 0) + 1
        cat = _ENTITY_CATEGORY.get(ent, "OTHER")
        categories[cat] = categories.get(cat, 0) + 1
        if len(samples) < 10:
            loc = e.get("dataLocation") or {}
            samples.append({"filePath": loc.get("location"), "column": loc.get("column"),
                            "entity": ent, "category": cat})
    caveat = None
    if latest_infected and not entities_found and not sens.get("isOverridden"):
        caveat = ("latest scan is infected, so the live classification reflects the "
                  "encrypted snapshot; absence of entities is not evidence the data is "
                  "non-sensitive")
    return json.dumps({
        "dataClasses": (cls.get("dataClassesDetails") or {}).get("dataClasses") or [],
        "environment": (cls.get("environmentDetails") or {}).get("environment"),
        "sensitivityLevel": sens.get("sensitivityLevel"),
        "sensitivityOverridden": bool(sens.get("isOverridden")),
        "latestScanInfected": latest_infected,
        "dataCategories": sorted(categories),
        "categoryCounts": categories,
        "entityCounts": entities,
        "detectedEntityCount": len(entities_found),
        "sampleDetections": samples,
        "classificationCaveat": caveat,
    })


# ---------------------------------------------------------------- evidence

@tool
def eon_get_scan_verdict(resource_id: str) -> str:
    """The resource's latest security scan verdict and its last known clean snapshot.

    Returns `lastScan` (conclusion, justification, snapshot, time) and `lastClean`. Read
    the justification, not only the conclusion: it carries the measurements (entropy
    before and after, file patterns) that make your assessment concrete.

    Args:
        resource_id: the Eon resource UUID
    """
    try:
        return json.dumps(client().security_scans(resource_id))
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@tool
def eon_list_findings(resource_id: str, evidence_types: list[str] | None = None) -> str:
    """Individual security findings for the resource, with the file paths hit.

    Findings name the detector (entropy, file signatures, deletions), the evidence type
    and the exact object keys, which is how you describe what the attacker did: which
    files were overwritten with ciphertext, which were renamed, whether a ransom note
    was dropped, what was deleted.

    Args:
        resource_id: the Eon resource UUID
        evidence_types: optional filter, e.g. ["modified_files_became_encrypted",
            "suspicious_extension_detected"]
    """
    filters: dict[str, Any] = {"resourceId": {"in": [resource_id]}}
    if evidence_types:
        filters["evidenceType"] = {"in": evidence_types}
    try:
        resp = client().security_findings(filters)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)
    findings = [{
        "detectorType": f.get("detectorType"),
        "evidenceType": f.get("evidenceType"),
        "conclusion": f.get("conclusion"),
        "path": f.get("path"),
        "score": f.get("score"),
        "justification": f.get("justification"),
        "snapshotId": f.get("snapshotId"),
    } for f in resp.get("findings", [])]
    return json.dumps({"totalCount": resp.get("totalCount"), "findings": findings})


@tool
def eon_list_infected_snapshots(resource_id: str) -> str:
    """Every snapshot of the resource that carries security findings, newest first.

    The EARLIEST infected snapshot bounds when the attack first reached a backup. Use
    its time, minus a safety margin, as the upper bound for choosing a recovery point.

    Args:
        resource_id: the Eon resource UUID
    """
    try:
        return json.dumps({"snapshots": client().infected_snapshots(resource_id)})
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@tool
def eon_list_snapshots(resource_id: str, limit: int = 30) -> str:
    """The resource's snapshot timeline, newest first: id, time, status, and whether a
    hold is set. Use it to see how many recovery points exist around the attack and to
    sanity-check the clean snapshot you chose against the infected ones.

    Args:
        resource_id: the Eon resource UUID
        limit: how many of the newest snapshots to return
    """
    try:
        snaps = client().snapshots(resource_id)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)
    snaps = sorted(snaps, key=lambda s: s.get("pointInTime") or s.get("createdTime") or "",
                   reverse=True)[:limit]
    return json.dumps({"count": len(snaps), "snapshots": [{
        "snapshotId": s.get("id"),
        "pointInTime": s.get("pointInTime") or s.get("createdTime"),
        "status": s.get("status"),
        "hold": bool(s.get("isHold") or s.get("hold")),
    } for s in snaps]})


# ---------------------------------------------------------------- contain

@tool
def eon_hold_snapshot(snapshot_id: str) -> str:
    """Place a hold on a snapshot so retention cannot delete it.

    Hold every infected snapshot before recovering anything: they are the forensic
    evidence and would otherwise expire on the retention schedule.

    Args:
        snapshot_id: the Eon snapshot UUID
    """
    try:
        client().hold_snapshot(snapshot_id)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)
    return json.dumps({"held": True, "snapshotId": snapshot_id})


# ---------------------------------------------------------------- recovery point

@tool
def eon_select_clean_snapshots(resource_ids: list[str], not_after: str | None = None,
                               lookback_days: int = 30) -> str:
    """The latest CLEAN snapshot per resource inside a window: the "last known good" primitive.

    Only snapshots with a clean scan verdict are eligible. A resource with none in range
    comes back as BULK_SELECT_SNAPSHOT_STATUS_NO_CLEAN_SNAPSHOT rather than being
    dropped silently; treat that as an escalation, never as something to work around.

    Pass the upper bound as not_after so the chosen snapshot predates the attack.
    Taking the latest clean snapshot unbounded can pick one taken after the intrusion
    began but before encryption started.

    Args:
        resource_ids: Eon resource UUIDs
        not_after: ISO-8601 upper bound, e.g. "2026-10-06T02:10:00Z"
        lookback_days: how far back to search from the upper bound
    """
    to = not_after or datetime.now(timezone.utc).isoformat()
    try:
        to_dt = datetime.fromisoformat(to.replace("Z", "+00:00"))
    except ValueError:
        return json.dumps({"error": True, "detail": f"not_after not ISO-8601: {to}"})
    frm = (to_dt - timedelta(days=lookback_days)).isoformat()
    try:
        items = client().select_clean_snapshots(resource_ids, frm=frm, to=to_dt.isoformat())
    except Exception as exc:  # noqa: BLE001
        return _err(exc)
    return json.dumps({"window": {"from": frm, "to": to_dt.isoformat()}, "items": items})


# ---------------------------------------------------------------- destination

@tool
def eon_list_restore_accounts() -> str:
    """Restore accounts available as recovery targets.

    Exactly one is the designated isolated recovery target for this exercise (marked
    designatedRecoveryTarget and isolated). Regulated data must recover there; it must
    be CONNECTED. S3 restores copy objects into an existing bucket in that account and
    launch no server, so they need no region connectivity.
    """
    target_id = os.environ.get("EON_RESTORE_ACCOUNT_ID")
    try:
        accounts = client().restore_accounts()
    except Exception as exc:  # noqa: BLE001
        return _err(exc)
    rows = []
    for a in accounts:
        row = {"restoreAccountId": a.get("id"), "providerAccountId": a.get("providerAccountId"),
               "name": a.get("name"), "cloudProvider": a.get("cloudProvider"),
               "status": a.get("status"), "isolated": False}
        if a.get("id") == target_id:
            row["designatedRecoveryTarget"] = True
            row["isolated"] = True
            row["recoveryBucket"] = os.environ.get("RECOVERY_BUCKET")
        rows.append(row)
    rows.sort(key=lambda r: not r.get("designatedRecoveryTarget"))
    return json.dumps({"accounts": rows})


# ---------------------------------------------------------------- restore

_DEAD = {"DENIED", "EXPIRED", "FAILED", "CANCELED", "CANCELED_PENDING_APPROVAL",
         "CANCELED_PENDING_EXECUTION", "CANCELED_APPROVED"}
# A request counts as standing only while a decision or its execution is still pending.
# An EXECUTED request is a finished remediation; a later run of the same incident may
# legitimately ask again.
_OPEN = {"PENDING_APPROVAL", "APPROVED"}


def _inflight(path: str) -> dict | None:
    """A standing request for the same restore path, if one is still open."""
    try:
        reqs = client().list_my_approval_requests()
    except Exception:  # noqa: BLE001
        return None
    for q in reqs:
        if q.get("requestPath", "").endswith(path.split("{p}")[-1]) and q.get("status") in _OPEN:
            return {"approvalRequestId": q.get("id"), "status": q.get("status")}
    return None


@tool
def eon_request_restore(resource_id: str, snapshot_id: str, restore_account_id: str,
                        reason: str) -> str:
    """Request a restore of one S3 snapshot into the isolated recovery bucket.

    This does NOT restore anything by itself. Every restore is protected by Eon's action
    approval rule, so the call is intercepted and returns an approval request a human
    must approve. The `reason` is what the reviewer reads: state the evidence, the
    snapshot you chose and why that one and not a later one, the data at stake, and the
    destination.

    If a request for this same restore is already open, the standing one is returned
    instead of a duplicate.

    Args:
        resource_id: the Eon resource UUID being recovered
        snapshot_id: the CLEAN snapshot to restore from
        restore_account_id: the Eon restore account UUID of the isolated target
        reason: justification shown to the human reviewer
    """
    bucket = os.environ.get("RECOVERY_BUCKET")
    if not bucket:
        return json.dumps({"error": True, "detail": "RECOVERY_BUCKET is not configured"})
    path = f"/v1/projects/{{p}}/resources/{resource_id}/snapshots/{snapshot_id}/restore-bucket"
    body = {"restoreAccountId": restore_account_id,
            "destination": {"s3Bucket": {"bucketName": bucket}}}
    standing = _inflight(path)
    if standing:
        return json.dumps({"intercepted": True, "duplicate": True, **standing,
                           "message": "a request for this restore is already open; reuse it"})
    try:
        result = client().protected_call("POST", path, body)
    except MpaIntercepted as exc:
        try:
            client().submit_approval_request(exc.request_id, reason)
            submitted = True
        except Exception as sub_exc:  # noqa: BLE001
            submitted = False
            reason = f"submit failed: {sub_exc}"
        return json.dumps({"intercepted": True, "approvalRequestId": exc.request_id,
                           "submitted": submitted, "destinationBucket": bucket,
                           "message": "Restore intercepted by the approval rule and submitted "
                                      "for human review. Call eon_wait_for_approval next."})
    except Exception as exc:  # noqa: BLE001
        return _err(exc)
    return json.dumps({"intercepted": False, "result": result})


@tool
def eon_wait_for_approval(approval_request_id: str, timeout_minutes: int = 30) -> str:
    """Block until a human approves or denies the request (polls every few seconds).

    Returns the final status: APPROVED means you may execute the restore; DENIED,
    EXPIRED or CANCELED means you stop and report. A TIMEOUT means nobody decided in
    time; stop and say the request is still pending.

    Args:
        approval_request_id: the request returned by eon_request_restore
        timeout_minutes: how long to wait before giving up
    """
    deadline = time.time() + timeout_minutes * 60
    started = time.time()
    status = None
    progress.update({"phase": "approval", "requestId": approval_request_id, "started": started,
                     "status": "PENDING"})
    while time.time() < deadline:
        try:
            req = client().approval_request(approval_request_id)
            status = req.get("status")
        except Exception as exc:  # noqa: BLE001
            status = f"ERROR {exc}"
        progress["status"] = status
        if status == "APPROVED" or status in _DEAD:
            reviews = [{"reviewer": (r.get("reviewer") or {}).get("email") or r.get("reviewerId"),
                        "decision": r.get("decision") or r.get("status"),
                        "comment": r.get("comment")} for r in (req.get("reviews") or [])]
            progress["phase"] = None
            return json.dumps({"status": status, "waitedSeconds": int(time.time() - started),
                               "reviews": reviews})
        time.sleep(5)
    progress["phase"] = None
    return json.dumps({"status": "TIMEOUT", "lastSeen": status,
                       "waitedSeconds": int(time.time() - started)})


@tool
def eon_execute_approved_restore(approval_request_id: str) -> str:
    """Execute a restore a human has APPROVED.

    Eon stored the original method, path and body on the request, so this replays it
    exactly; you never reconstruct the restore parameters. Returns the restore job id.

    Args:
        approval_request_id: the approved request UUID
    """
    try:
        result = client().execute_approved(approval_request_id)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)
    job_id = result.get("jobId") or result.get("id") or (result.get("job") or {}).get("id")
    return json.dumps({"executed": True, "restoreJobId": job_id, "result": result})


@tool
def eon_wait_for_restore(restore_job_id: str, timeout_minutes: int = 30) -> str:
    """Block until the restore job finishes, then return its outcome and destination.

    Args:
        restore_job_id: the job id from eon_execute_approved_restore
        timeout_minutes: how long to wait before giving up
    """
    deadline = time.time() + timeout_minutes * 60
    started = time.time()
    progress.update({"phase": "restore", "jobId": restore_job_id, "started": started,
                     "status": "JOB_PENDING"})
    status = None
    while time.time() < deadline:
        try:
            job = client().restore_job(restore_job_id)
            status = (job.get("jobExecutionDetails") or {}).get("status") or job.get("status")
        except Exception as exc:  # noqa: BLE001
            status = f"ERROR {exc}"
            job = {}
        progress["status"] = status
        if status in ("JOB_COMPLETED", "JOB_FAILED", "JOB_CANCELED", "JOB_CANCELLED"):
            progress["phase"] = None
            dest = job.get("destinationDetails") or {}
            return json.dumps({"status": status, "waitedSeconds": int(time.time() - started),
                               "destination": dest,
                               "recoveryBucket": os.environ.get("RECOVERY_BUCKET"),
                               "error": (job.get("jobExecutionDetails") or {}).get("errorMessage")})
        time.sleep(10)
    progress["phase"] = None
    return json.dumps({"status": "TIMEOUT", "lastSeen": status})


EON_TOOLS = [
    eon_get_resource,
    eon_get_classification,
    eon_get_scan_verdict,
    eon_list_findings,
    eon_list_infected_snapshots,
    eon_list_snapshots,
    eon_hold_snapshot,
    eon_select_clean_snapshots,
    eon_list_restore_accounts,
    eon_request_restore,
    eon_wait_for_approval,
    eon_execute_approved_restore,
    eon_wait_for_restore,
]
