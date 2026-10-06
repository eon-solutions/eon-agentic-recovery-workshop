"""AWS-native tools: the controls that are independent of Eon.

Eon's clean verdict is about the data in the snapshot. These two tools look at the
recovered bucket directly in the recovery account and answer two different questions:
is it reachable from the internet, and is what landed there actually clean? Both use
the attendee's own AWS credentials, which are scoped to that one bucket.
"""

from __future__ import annotations

import json
import math
import os
from collections import Counter

import boto3
from strands import tool

REGION = os.environ.get("AWS_REGION", "us-east-1")
ENCRYPTED_THRESHOLD = 7.5     # bits per byte; plaintext CSV sits near 4.5 to 5.5
SUSPICIOUS_SUFFIXES = (".locked", ".encrypted", ".enc", ".crypt", ".lockbit", ".akira")
NOTE_HINTS = ("recover", "readme", "decrypt", "restore_files", "how_to", "ransom")


def _s3():
    return boto3.Session(region_name=REGION).client("s3")


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@tool
def aws_verify_not_public(bucket: str) -> str:
    """Verify the recovered bucket is not publicly exposed, checking AWS directly.

    An AWS-native control independent of Eon: the bucket must have a complete
    public-access block (all four settings on) and no public bucket policy. Returns a
    fact, `exposed`, with the specific findings. For a resource holding regulated data
    an exposed result is a failed recovery; escalate and do not sign it off.

    Args:
        bucket: the recovery bucket name in the isolated recovery account
    """
    s3 = _s3()
    try:
        pab = None
        pab_all_on = False
        try:
            pab = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
            pab_all_on = all(pab.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls",
                                                   "BlockPublicPolicy", "RestrictPublicBuckets"))
        except Exception as exc:  # noqa: BLE001
            if "NoSuchPublicAccessBlockConfiguration" not in str(exc):
                raise
        policy_public = False
        try:
            policy_public = bool(s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"]["IsPublic"])
        except Exception as exc:  # noqa: BLE001
            if "NoSuchBucketPolicy" not in str(exc):
                raise
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": True, "detail": str(exc)})
    findings = []
    if pab is None:
        findings.append("no public-access-block configuration; public ACLs and policies are not blocked")
    elif not pab_all_on:
        findings.append("public-access-block incomplete: " + ", ".join(
            k for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy",
                        "RestrictPublicBuckets") if not pab.get(k)))
    if policy_public:
        findings.append("bucket policy status reports the bucket is public")
    return json.dumps({"check": "aws-native-exposure", "independentOfEon": True,
                       "bucket": bucket, "exposed": (not pab_all_on) or policy_public,
                       "publicAccessBlockAllOn": pab_all_on, "bucketPolicyIsPublic": policy_public,
                       "findings": findings})


@tool
def aws_prove_recovery(bucket: str, expected_encrypted_paths: list[str] | None = None,
                       max_objects: int = 200) -> str:
    """Prove the recovered data is clean by reading it: per-object Shannon entropy,
    ransomware artefacts, and a check that the files the attacker encrypted are back
    as plaintext.

    Plaintext CSV measures roughly 4.5 to 5.5 bits per byte; ciphertext sits above
    7.5. A recovery passes when no object is above the threshold, no object carries a
    ransomware extension, no ransom note is present, and every path in
    expected_encrypted_paths exists and is low-entropy.

    Args:
        bucket: the recovery bucket name in the isolated recovery account
        expected_encrypted_paths: object keys Eon's findings said were encrypted or
            renamed at the source; each must now be present and plaintext
        max_objects: cap on objects read
    """
    s3 = _s3()
    try:
        keys = []
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            keys += [o["Key"] for o in page.get("Contents", [])]
        keys = keys[:max_objects]
        objects = []
        for k in keys:
            body = s3.get_object(Bucket=bucket, Key=k)["Body"].read(262144)
            objects.append({"key": k, "bytes": len(body), "entropy": round(_entropy(body), 3)})
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": True, "detail": str(exc)})
    encrypted = [o for o in objects if o["entropy"] > ENCRYPTED_THRESHOLD]
    suspicious = [o["key"] for o in objects if o["key"].lower().endswith(SUSPICIOUS_SUFFIXES)]
    notes = [o["key"] for o in objects
             if "/" not in o["key"].strip("/") and any(h in o["key"].lower() for h in NOTE_HINTS)]
    present = {o["key"]: o for o in objects}
    missing, still_encrypted = [], []
    for p in (expected_encrypted_paths or []):
        p = p.lstrip("/")
        base = p[:-len(".locked")] if p.endswith(".locked") else p
        o = present.get(base)
        if not o:
            missing.append(base)
        elif o["entropy"] > ENCRYPTED_THRESHOLD:
            still_encrypted.append(base)
    entropies = [o["entropy"] for o in objects] or [0.0]
    clean = bool(objects) and not encrypted and not suspicious and not notes and not missing \
        and not still_encrypted
    return json.dumps({
        "check": "recovered-data-integrity", "independentOfEon": True, "bucket": bucket,
        "clean": clean, "objectCount": len(objects),
        "entropy": {"mean": round(sum(entropies) / len(entropies), 3),
                    "max": round(max(entropies), 3), "threshold": ENCRYPTED_THRESHOLD},
        "encryptedObjects": [o["key"] for o in encrypted],
        "suspiciousExtensions": suspicious, "ransomNotes": notes,
        "expectedPathsMissing": missing, "expectedPathsStillEncrypted": still_encrypted,
        "sample": objects[:12],
    })


AWS_TOOLS = [aws_verify_not_public, aws_prove_recovery]
