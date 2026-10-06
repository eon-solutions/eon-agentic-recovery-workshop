"""Eon REST client.

Credentials resolve, in order: AWS Secrets Manager (EON_SECRET_ARN) for a hosted
runtime; then the EON_* environment variables; then the eon block of config/config.yaml
for local development. Nothing here depends on any external CLI or its local files.

This module is also the tool layer the recovery agent uses. Keep every method a thin
wrapper over one REST call; reasoning belongs in the agent, not here.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

TOKEN_TTL_SECONDS = 11 * 3600  # access tokens last 12h; refresh a little early


class EonError(RuntimeError):
    """An Eon API call failed. Carries the status code and decoded body."""

    def __init__(self, status: int, body: Any, method: str, path: str):
        self.status = status
        self.body = body
        self.method = method
        self.path = path
        super().__init__(f"{method} {path} -> {status}: {json.dumps(body)[:600]}")


class MpaIntercepted(Exception):
    """A protected action was intercepted by an action approval rule.

    Raised instead of returning, because callers must not treat interception as
    success. Carries the approval request and the exact request that produced it,
    since replay after approval has to match byte for byte.
    """

    def __init__(self, request_id: str, payload: dict, replay: dict):
        self.request_id = request_id
        self.payload = payload
        self.replay = replay
        super().__init__(f"action approval required: request {request_id}")


def _secret_from_secrets_manager(arn: str) -> tuple[str | None, str]:
    """Fetch the Eon API credential from AWS Secrets Manager.

    This is how the credential reaches AgentCore Runtime (and Lambda) in production: the
    runtime carries only EON_SECRET_ARN, never the client secret in a plaintext env var,
    and its execution role is granted secretsmanager:GetSecretValue on exactly this ARN.

    The secret value is JSON {"clientId": ..., "clientSecret": ...} (both, so neither is
    in the runtime env); a plain string is accepted as the secret alone. Import boto3
    lazily so local runs never need it."""
    import boto3  # lazy: only containers that set EON_SECRET_ARN need it

    region = arn.split(":")[3] if arn.startswith("arn:") and len(arn.split(":")) > 3 else None
    sm = boto3.client("secretsmanager", region_name=region) if region else boto3.client("secretsmanager")
    value = sm.get_secret_value(SecretId=arn)["SecretString"]
    try:
        data = json.loads(value)
    except json.JSONDecodeError:
        return None, value
    return data.get("clientId"), data.get("clientSecret")


class EonClient:
    def __init__(self, profile: str | None = None, project_id: str | None = None):
        # `profile` is accepted for call-site compatibility but no longer selects a
        # credential source — credentials come from Secrets Manager, env, or config.
        self.profile = profile
        # Non-secret connection details, and the local-dev credential, come from the
        # eon block of config/config.yaml (falling back to config.example.yaml).
        from .env import load_env
        load_env()
        eon_cfg: dict = {}

        # A hosted runtime carries only EON_SECRET_ARN; the credential (both halves)
        # lives in Secrets Manager, so nothing sensitive sits in its environment. When
        # the ARN is set it is authoritative — a failed fetch raises rather than
        # silently falling back.
        sm_client_id: str | None = None
        sm_secret: str | None = None
        secret_arn = os.environ.get("EON_SECRET_ARN")
        if secret_arn:
            sm_client_id, sm_secret = _secret_from_secrets_manager(secret_arn)

        self.domain = os.environ.get("EON_ACCOUNT_DOMAIN") or eon_cfg.get("domain")
        self.project_id = (project_id or os.environ.get("EON_PROJECT_ID")
                           or eon_cfg.get("project_id"))
        self.client_id = (sm_client_id or os.environ.get("EON_CLIENT_ID")
                          or eon_cfg.get("client_id"))
        # Precedence mirrors the above: Secrets Manager > env > config file.
        self._secret = (sm_secret or os.environ.get("EON_CLIENT_SECRET")
                        or eon_cfg.get("client_secret"))
        missing = [n for n, v in (("domain", self.domain), ("project_id", self.project_id),
                                  ("client_id", self.client_id), ("client_secret", self._secret))
                   if not v]
        if missing:
            raise EonError(
                0,
                {"error": f"incomplete Eon credentials: missing {', '.join(missing)}. "
                          "Set EON_SECRET_ARN (Secrets Manager), or the EON_ACCOUNT_DOMAIN "
                          "/ EON_PROJECT_ID / EON_CLIENT_ID / EON_CLIENT_SECRET env vars "
                          "(the workshop .env file carries them)."},
                "GET",
                "config",
            )
        self.base = f"https://{self.domain}.console.eon.io/api"
        self._token: str | None = None
        self._token_at = 0.0

    # ---------- transport ----------

    def _access_token(self) -> str:
        if self._token and time.time() - self._token_at < TOKEN_TTL_SECONDS:
            return self._token
        body = json.dumps({"clientId": self.client_id, "clientSecret": self._secret}).encode()
        req = urllib.request.Request(
            f"{self.base}/v1/token",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            self._token = json.load(resp)["accessToken"]
        self._token_at = time.time()
        return self._token

    def call(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        headers: dict | None = None,
        raw_status: bool = False,
    ) -> Any:
        """Issue one API call. `{p}` in path is replaced with the project id."""
        path = path.replace("{p}", self.project_id)
        url = f"{self.base}{path}"
        data = json.dumps(body).encode() if body is not None else None
        hdrs = {
            "Authorization": f"Bearer {self._access_token()}",
            "Content-Type": "application/json",
        }
        hdrs.update(headers or {})
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                text = resp.read().decode() or "{}"
                parsed = json.loads(text)
                return (resp.status, parsed) if raw_status else parsed
        except urllib.error.HTTPError as exc:
            text = exc.read().decode() or "{}"
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = {"error": text}
            raise EonError(exc.code, parsed, method, path) from None

    # ---------- inventory ----------

    def list_resources(self, filters: dict | None = None, page_size: int = 200) -> list[dict]:
        """List resources. Uses the REST path directly rather than a generated SDK,
        which rejects resource types newer than its enum (AWS_KEYSPACES_TABLE)."""
        out, token = [], None
        while True:
            path = f"/v1/projects/{{p}}/resources?pageSize={page_size}"
            if token:
                path += f"&pageToken={token}"
            resp = self.call("POST", path, {"filters": filters} if filters else {})
            out.extend(resp.get("resources", []))
            token = resp.get("nextToken")
            if not token:
                return out

    def invoke_discovery(self, eon_account_id: str) -> dict:
        """Trigger resource discovery for a cloud account so newly created resources (e.g. a
        fresh bucket) show up in inventory promptly instead of waiting for the next cycle."""
        return self.call("POST", f"/projects/{{p}}/accounts/{eon_account_id}/invoke-discovery", {})

    def resource_by_provider_id(self, provider_id: str) -> dict | None:
        hits = self.list_resources({"providerResourceId": {"in": [provider_id]}})
        return hits[0] if hits else None

    def snapshots(self, resource_id: str) -> list[dict]:
        resp = self.call("POST", f"/v1/projects/{{p}}/resources/{resource_id}/snapshots", {})
        return resp.get("snapshots", [])

    # ---------- backup ----------

    def take_snapshot(self, resource_id: str, vault_id: str, retention_days: int = 5) -> dict:
        """On-demand backup.

        Note the route: /resources/{id}/take-snapshot. The /inventory/{id}/take-snapshot
        path 404s, and retentionDays is required.
        """
        return self.call(
            "POST",
            f"/v1/projects/{{p}}/resources/{resource_id}/take-snapshot",
            {"vaultId": vault_id, "retentionDays": retention_days},
        )

    def backup_job(self, job_id: str) -> dict | None:
        resp = self.call("POST", "/v1/projects/{p}/backup-jobs", {"filters": {"id": {"in": [job_id]}}})
        jobs = resp.get("jobs") or []
        return jobs[0] if jobs else None

    @staticmethod
    def job_status(job: dict | None) -> str:
        """Status lives under jobExecutionDetails, not at the top level."""
        if not job:
            return "UNKNOWN"
        return (job.get("jobExecutionDetails") or {}).get("status", "UNKNOWN")

    # ---------- security plan / detection ----------

    def get_security_plan(self) -> dict:
        return self.call("GET", "/projects/{p}/inventory/security-plan")

    def security_plan_enabled(self) -> bool:
        return bool(self.call("GET", "/projects/{p}/inventory/security-plan-enabled").get("enabled"))

    def save_security_plan(self, condition: dict, include: list[str], exclude: list[str] | None = None) -> dict:
        """Save the project security plan.

        A non-empty `condition` is mandatory. The matcher tests
        `!Condition.IsEmpty() && (MatchIds(Include) || Match(Condition))`, so an empty
        condition makes `include` a silent no-op: the PUT succeeds, echoes back, and
        nothing is ever assigned.
        """
        if not condition or not condition.get("operator"):
            raise ValueError(
                "condition must be non-empty or nothing will be assigned; "
                "scope with e.g. {'property':'resourceId','operator':'In','value':[...]}"
            )
        return self.call(
            "PUT",
            "/projects/{p}/inventory/security-plan",
            {"condition": condition, "include": include, "exclude": exclude or []},
        )

    def assign_provider_ids(self, provider_ids: list[str]) -> dict:
        """Scope detection to exactly these resources, by canonical provider id
        (bucket name, i-...), never the Eon UUID."""
        return self.save_security_plan(
            condition={"property": "resourceId", "operator": "In", "value": list(provider_ids)},
            include=list(provider_ids),
        )

    def assign_detection(self, provider_ids: list[str]) -> dict:
        """Assign ransomware detection to exactly these resources, by canonical provider
        id (bucket name, i-...).

        The security-plan matcher is MatchIds(Include) || Match(Condition). Only the
        `resourceId In` *condition* route assigns reliably for an S3 bucket: a plan whose
        condition is a tag leaves the bucket NOT_ASSIGNED even with the bucket in the
        plan's Include and PROTECTED, while a resourceId-In condition assigns it in ~30s.
        The in-memory matcher resolves S3 canonical tags differently from EC2's, so
        tag-based detection selection is not usable for buckets; provider-id selection is.

        Assignment is event-driven and only recomputes backed-up resources, so call this
        AFTER the target resource reaches PROTECTED — saving fires SECURITY_PLAN_CHANGED,
        which recomputes assignment while the resource is eligible. Pass every resource
        detection should cover in one call (a save replaces the whole plan); for a
        combined S3+EC2 demo, include the EC2 host provider ids here too."""
        return self.assign_provider_ids(list(provider_ids))

    def security_scans(self, resource_id: str) -> dict:
        return self.call("GET", f"/projects/{{p}}/inventory/{resource_id}/security-scans")

    def request_scan(self, resource_id: str) -> dict:
        """Trigger a scan without waiting for the next backup."""
        return self.call("POST", "/projects/{p}/scan-jobs", {"resourceId": resource_id})

    def security_findings(self, filters: dict | None = None) -> dict:
        return self.call(
            "POST",
            "/projects/{p}/security-findings?pageSize=200",
            {"filters": filters} if filters else {},
        )

    def infected_snapshots(self, resource_id: str) -> list[dict]:
        resp = self.call("GET", f"/projects/{{p}}/resources/{resource_id}/infected-snapshots")
        return resp.get("snapshots", [])

    # ---------- threat hunting ----------

    def threat_hunt(self, resource_id: str, snapshot_id: str | None = None,
                    custom_rule: str | None = None) -> dict:
        """YARA scan of a snapshot. A custom_rule replaces the Forge rule set entirely."""
        body: dict[str, Any] = {"resourceId": resource_id}
        if snapshot_id:
            body["snapshotId"] = snapshot_id
        if custom_rule:
            body["customRule"] = custom_rule
        return self.call("POST", "/v1/projects/{p}/threat-hunting/scan-requests", body)

    def threat_hunt_results(self, request_id: str | None = None,
                            resource_id: str | None = None) -> dict:
        body = {k: v for k, v in (("requestId", request_id), ("resourceId", resource_id)) if v}
        return self.call("POST", "/v1/projects/{p}/threat-hunting/results/list", body)

    # ---------- clean-snapshot selection ----------

    def select_clean_snapshots(self, resource_ids: list[str], frm: str, to: str,
                               is_clean: bool = True,
                               pick: str = "SNAPSHOT_RANGE_PICK_LATEST") -> list[dict]:
        """Best snapshot per resource in a window. With is_clean, only snapshots with a
        clean scan verdict are eligible; resources with none come back as
        BULK_SELECT_SNAPSHOT_STATUS_NO_CLEAN_SNAPSHOT rather than being dropped."""
        resp = self.call(
            "POST",
            "/v1/projects/{p}/bulk-restore/select-snapshots",
            {"resourceIds": resource_ids, "from": frm, "to": to,
             "isClean": is_clean, "pick": pick},
        )
        return resp.get("items", [])

    # ---------- snapshot hold ----------

    def hold_snapshot(self, snapshot_id: str) -> dict:
        return self.call("PATCH", f"/v1/projects/{{p}}/snapshots/{snapshot_id}/hold", {})

    def remove_hold(self, snapshot_id: str) -> dict:
        return self.call("PATCH", f"/v1/projects/{{p}}/snapshots/{snapshot_id}/remove-hold", {})

    # ---------- action approvals ----------

    def approval_rules(self) -> list[dict]:
        return self.call("GET", "/v1/projects/{p}/action-approvals/rules").get("actionApprovalRules", [])

    def create_approval_rule(self, body: dict) -> dict:
        return self.call("POST", "/v1/projects/{p}/action-approvals/rules", body)

    # Terminal states an approval request can reach; anything else is still "open".
    _APPROVAL_TERMINAL = {
        "DENIED", "EXECUTED", "EXPIRED",
        "CANCELED_PENDING_APPROVAL", "CANCELED", "CANCELED_PENDING_EXECUTION",
        "CANCELED_APPROVED", "FAILED",
    }

    def list_my_approval_requests(self, only_open: bool = False) -> list[dict]:
        """Approval requests this credential raised (the agent is the requester).

        `only_open=True` drops the terminal ones (denied/executed/expired/canceled), so
        the result is the set of requests still awaiting a human — used to dedupe restore
        submissions so a re-dispatched agent reuses the standing request instead of
        stacking a duplicate."""
        r = self.call("POST", "/v1/projects/{p}/action-approvals/my-requests/list", {})
        reqs = r.get("requests", [])
        if only_open:
            reqs = [q for q in reqs if q.get("status") not in self._APPROVAL_TERMINAL]
        return reqs

    def cancel_approval_request(self, request_id: str, comment: str = "") -> dict:
        return self.call(
            "POST",
            f"/v1/projects/{{p}}/action-approvals/my-requests/{request_id}/cancel",
            {"comment": comment} if comment else {},
        )

    def submit_approval_request(self, request_id: str, comment: str) -> dict:
        return self.call(
            "POST",
            f"/v1/projects/{{p}}/action-approvals/my-requests/{request_id}/submit",
            # The enum is CONFIRM / DISCARD, not SUBMIT.
            {"action": "CONFIRM", "comment": comment},
        )

    def approval_request(self, request_id: str) -> dict:
        """Fetch an action request. Unwraps the mpaRequestDetail envelope and returns
        {**request, "reviews": [...]} so callers see status/policyDetails at the top."""
        resp = self.call("GET", f"/v1/projects/{{p}}/action-approvals/my-requests/{request_id}")
        detail = resp.get("mpaRequestDetail") or {}
        req = detail.get("request")
        if not req:
            return resp
        return {**req, "reviews": detail.get("reviews") or []}

    def execute_approved(self, request_id: str) -> dict:
        """Execute an approved action request by replaying what Eon captured.

        Eon stores requestMethod, requestPath and requestBody on the request itself, so
        the replay is byte-identical without the caller persisting anything. The replay
        must come from the original requester and match the captured request, or the
        server returns 409.
        """
        req = self.approval_request(request_id)
        status = req.get("status")
        if status != "APPROVED":
            raise EonError(
                0,
                {"error": f"request {request_id} is {status}, not APPROVED",
                 "status": status},
                "GET",
                f"/action-approvals/my-requests/{request_id}",
            )
        method = req.get("requestMethod")
        path = req.get("requestPath")
        raw = req.get("requestBody")
        if not method or not path:
            raise EonError(0, {"error": "request did not capture method/path"}, "GET", path or "?")
        body = json.loads(raw) if isinstance(raw, str) and raw else (raw or None)
        return self.call(
            method, path, body,
            headers={"X-Action-Approval-Request-Id": request_id},
        )

    def protected_call(self, method: str, path: str, body: dict,
                       approval_request_id: str | None = None) -> Any:
        """Call an approval-protected endpoint.

        Without an approval id, a 201 means intercepted -> raises MpaIntercepted with
        the replay payload. With one, the request must match the original exactly or
        the server returns 409.
        """
        headers = {"X-Action-Approval-Request-Id": approval_request_id} if approval_request_id else {}
        status, parsed = self.call(method, path, body, headers=headers, raw_status=True)
        if status == 201 and "actionApprovalRequest" in parsed:
            req = parsed["actionApprovalRequest"]
            raise MpaIntercepted(
                req["id"], parsed, {"method": method, "path": path, "body": body}
            )
        return parsed

    # ---------- notifications ----------

    def notification_policies(self) -> list[dict]:
        resp = self.call("GET", "/v1/projects/{p}/notification-policies")
        return resp if isinstance(resp, list) else resp.get("notificationPolicies", [])

    def create_notification_policy(self, body: dict) -> dict:
        return self.call("POST", "/v1/projects/{p}/notification-policies", body)

    # ---------- vaults / accounts ----------

    def vaults(self) -> list[dict]:
        return self.call("POST", "/v1/projects/{p}/vaults/list", {}).get("vaults", [])

    def restore_accounts(self) -> list[dict]:
        resp = self.call("POST", "/v1/projects/{p}/restore-accounts/list", {})
        return resp.get("restoreAccounts", resp.get("accounts", []))

    def restore_account(self, restore_account_id: str) -> dict:
        """One restore account, unwrapped from its envelope."""
        resp = self.call("GET", f"/v1/projects/{{p}}/restore-accounts/{restore_account_id}")
        return resp.get("restoreAccount", resp)

    def restore_job(self, job_id: str) -> dict:
        """One restore job, unwrapped from GetRestoreJobResponse. Carries resourceDetails
        (the source resource), destinationDetails (restore account, region, and the
        restoreResult with the restored resource's new id), and jobExecutionDetails.status
        — enough to locate what was restored and verify it after a RESTORE_JOB_SUCCEEDED."""
        resp = self.call("GET", f"/v1/projects/{{p}}/restore-jobs/{job_id}")
        return resp.get("job", resp)

    # Restore-job statuses that mean a remediation is still under way. Everything else
    # (COMPLETED / FAILED / PARTIAL / CANCELED / REJECTED / SKIPPED) is terminal.
    INFLIGHT_JOB_STATUSES = ("JOB_PENDING", "JOB_RUNNING")

    def list_restore_jobs(self, resource_id: str | None = None,
                          provider_resource_id: str | None = None,
                          statuses: list[str] | None = None,
                          page_size: int = 50) -> list[dict]:
        """Restore jobs for the project, optionally filtered by resource and status. Used to
        detect an in-flight restore for a victim so the agent does not stack a duplicate
        remediation on a re-fired detection: pass provider_resource_id plus
        statuses=list(INFLIGHT_JOB_STATUSES) to ask 'is a restore of this resource already
        running?'.

        Filter by provider_resource_id (the cloud-provider id, e.g. the bucket name or
        instance id), NOT resource_id: a restore job records the source's providerResourceId,
        and its Eon resourceId comes back null, so the Eon-id filter never matches. The
        resource_id (Eon-id) filter is kept for completeness but does not match today."""
        filters: dict = {}
        if provider_resource_id:
            filters["providerResourceId"] = {"in": [provider_resource_id]}
        if resource_id:
            filters["id"] = {"in": [resource_id]}
        if statuses:
            filters["status"] = {"in": statuses}
        body = {"filters": filters} if filters else {}
        resp = self.call("POST", f"/v1/projects/{{p}}/restore-jobs?pageSize={page_size}", body)
        return resp.get("jobs", [])

    def restore_connectivity(self, restore_account_id: str) -> dict:
        """The per-region VPC/subnet/security-group config the restore server launches
        into. Empty when the account uses default-VPC discovery. The restore server
        launches in the *source resource's* region, so an EC2 restore needs a config
        entry for that region."""
        resp = self.call(
            "GET",
            f"/v1/projects/{{p}}/restore-accounts/{restore_account_id}/connectivity-config",
        )
        cfg = resp.get("restoreAccountConfig") or resp
        return ((cfg.get("config") or {}).get("aws") or {})

    # ---------- data + application classification ----------

    def data_classification_categories(self) -> list[dict]:
        """Project's classification categories (PII, PHI, FI, CREDENTIALS + custom)."""
        resp = self.call("GET", "/projects/{p}/data-classification-categories")
        return resp.get("categories", [])

    def data_classification_entities(self, resource_id: str) -> list[dict]:
        """The regulated-data entities the classifier actually found on a resource.

        Each item: entityType (e.g. US_SOCIAL_SECURITY_NUMBER / CREDIT_DEBIT_CARD_NUMBER)
        and dataLocation {column, location} — the CSV/table column and the file (or
        table) it lives in. This is the endpoint the console's data-classification view
        reads; it is populated once data classification has run on a snapshot.

        Note: the separate `sensitivity-annotations` endpoint is a different, often-empty
        surface — use this one to know what PII/FI/PHI/CREDENTIALS were detected."""
        resp = self.call(
            "GET",
            f"/projects/{{p}}/inventory/{resource_id}/data-classification-entities",
        )
        return resp.get("dataClassificationEntities", [])

    def sensitivity_annotations(self, resource_id: str, page_size: int = 200) -> list[dict]:
        """Per-file sensitivity findings for a resource: filePath, propertyName
        (the detected entity, e.g. US_SSN / CREDIT_DEBIT_CARD_NUMBER), propertyValue.
        Often empty even after a scan — prefer `data_classification_entities`."""
        resp = self.call(
            "GET",
            f"/projects/{{p}}/inventory/{resource_id}/sensitivity-annotations?pageSize={page_size}",
        )
        return resp.get("sensitivityAnnotations", [])
