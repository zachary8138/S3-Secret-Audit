from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable

try:
    import boto3  # type: ignore
    from botocore.exceptions import BotoCoreError, ClientError  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None  # type: ignore
    BotoCoreError = Exception  # type: ignore
    ClientError = Exception  # type: ignore

from s3_audit.findings import Finding, Severity
from s3_audit.patterns import default_filename_indicators, default_secret_patterns, iter_matches


@dataclass(frozen=True)
class S3AuditConfig:
    scan_objects: bool
    max_objects_per_bucket: int
    max_bytes_per_object: int
    key_prefixes: list[str]
    regions: list[str]
    buckets: list[str]


def _is_bucket_public_via_acl(acl: dict) -> bool:
    grants = acl.get("Grants", []) or []
    for g in grants:
        grantee = g.get("Grantee") or {}
        uri = grantee.get("URI") or ""
        if uri.endswith("/AllUsers") or uri.endswith("/AuthenticatedUsers"):
            perm = g.get("Permission")
            if perm in {"READ", "WRITE", "READ_ACP", "WRITE_ACP", "FULL_CONTROL"}:
                return True
    return False


def _policy_allows_public_access(policy_str: str) -> bool:
    try:
        policy = json.loads(policy_str)
    except Exception:
        return False
    for st in policy.get("Statement", []) or []:
        if (st.get("Effect") or "").lower() != "allow":
            continue
        principal = st.get("Principal")
        principal_is_public = principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*")
        if not principal_is_public:
            continue
        actions = st.get("Action") or []
        if isinstance(actions, str):
            actions = [actions]
        actions = set(actions)
        if any(a in actions or a.lower() == "s3:*" for a in {"s3:GetObject", "s3:ListBucket", "s3:*"}):
            return True
    return False


def _safe_decode_bytes(b: bytes) -> str:
    try:
        return b.decode("utf-8", errors="replace")
    except Exception:
        return ""


def run_s3_audit(cfg: S3AuditConfig) -> Iterable[Finding]:
    if boto3 is None:
        yield Finding(
            check="aws_s3_dependency_missing",
            severity=Severity.HIGH,
            resource="aws:s3",
            summary="Missing dependency: boto3 (pip install s3-secret-audit)",
            details={},
        )
        return

    s3 = boto3.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", []) or []
    except (BotoCoreError, ClientError) as e:
        yield Finding(
            check="aws_s3_list_buckets",
            severity=Severity.HIGH,
            resource="aws:s3",
            summary="Failed to list buckets (credentials/permissions issue?)",
            details={"error": str(e)},
        )
        return

    if cfg.buckets:
        wanted = {n.strip() for n in cfg.buckets if n and n.strip()}
        available = {(b.get("Name") or "") for b in buckets}
        missing = sorted(wanted - available)
        for name in missing:
            yield Finding(
                check="aws_s3_bucket_not_found",
                severity=Severity.MEDIUM,
                resource=f"aws:s3:::{name}",
                summary="Requested bucket not found in ListBuckets result",
                details={"bucket": name},
            )
        buckets = [b for b in buckets if (b.get("Name") or "") in wanted]

    filename_indicators = [s.lower() for s in default_filename_indicators()]
    secret_patterns = default_secret_patterns()

    for b in buckets:
        name = b.get("Name") or ""
        if not name:
            continue
        resource = f"aws:s3:::{name}"

        public_reasons: list[str] = []
        public_access_block = None

        try:
            pab = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration") or {}
            public_access_block = pab
            if not all(bool(pab.get(k)) for k in ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]):
                public_reasons.append("PublicAccessBlock not fully enabled")
        except ClientError as e:
            code = (e.response.get("Error") or {}).get("Code")
            if code in {"NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock"}:
                public_reasons.append("No PublicAccessBlock configuration")
            else:
                yield Finding(
                    check="aws_s3_public_access_block",
                    severity=Severity.MEDIUM,
                    resource=resource,
                    summary="Could not read PublicAccessBlock configuration",
                    details={"error": str(e)},
                )

        try:
            acl = s3.get_bucket_acl(Bucket=name)
            if _is_bucket_public_via_acl(acl):
                public_reasons.append("Bucket ACL grants to AllUsers/AuthenticatedUsers")
        except ClientError as e:
            yield Finding(
                check="aws_s3_bucket_acl",
                severity=Severity.MEDIUM,
                resource=resource,
                summary="Could not read bucket ACL",
                details={"error": str(e)},
            )

        try:
            pol = s3.get_bucket_policy(Bucket=name).get("Policy")
            if pol and _policy_allows_public_access(pol):
                public_reasons.append("Bucket policy allows public access (Principal '*')")
        except ClientError as e:
            code = (e.response.get("Error") or {}).get("Code")
            if code not in {"NoSuchBucketPolicy"}:
                yield Finding(
                    check="aws_s3_bucket_policy",
                    severity=Severity.MEDIUM,
                    resource=resource,
                    summary="Could not read bucket policy",
                    details={"error": str(e)},
                )

        if public_reasons:
            yield Finding(
                check="aws_s3_public_bucket_risk",
                severity=Severity.HIGH,
                resource=resource,
                summary="Bucket appears potentially public/misconfigured",
                details={"reasons": public_reasons, "public_access_block": public_access_block},
            )

        if not cfg.scan_objects:
            continue

        prefixes = cfg.key_prefixes or [""]
        scanned = 0
        for prefix in prefixes:
            if scanned >= cfg.max_objects_per_bucket:
                break
            try:
                resp = s3.list_objects_v2(Bucket=name, Prefix=prefix, MaxKeys=min(1000, cfg.max_objects_per_bucket - scanned))
            except ClientError as e:
                yield Finding(
                    check="aws_s3_list_objects",
                    severity=Severity.MEDIUM,
                    resource=resource,
                    summary=f"Could not list objects for prefix '{prefix}'",
                    details={"error": str(e), "prefix": prefix},
                )
                continue

            for obj in resp.get("Contents") or []:
                if scanned >= cfg.max_objects_per_bucket:
                    break
                key = obj.get("Key") or ""
                if not key:
                    continue
                scanned += 1

                key_lower = key.lower()
                filename_flag = any(ind in key_lower for ind in filename_indicators)

                if not (filename_flag or public_reasons):
                    continue

                try:
                    getr = s3.get_object(Bucket=name, Key=key, Range=f"bytes=0-{cfg.max_bytes_per_object-1}")
                    body = getr["Body"].read()
                except ClientError as e:
                    yield Finding(
                        check="aws_s3_get_object",
                        severity=Severity.LOW,
                        resource=f"{resource}/{key}",
                        summary="Could not read object sample",
                        details={"error": str(e), "key": key},
                    )
                    continue

                text = _safe_decode_bytes(body)
                matches = list(iter_matches(text, secret_patterns))
                if matches:
                    yield Finding(
                        check="aws_s3_possible_secret_in_object",
                        severity=Severity.CRITICAL,
                        resource=f"{resource}/{key}",
                        summary="Object content matches secret/key pattern(s)",
                        details={
                            "key": key,
                            "matched": [
                                {"pattern": p.name, "severity": p.severity, "snippet": snippet}
                                for p, snippet in matches[:5]
                            ],
                            "bytes_sampled": len(body),
                        },
                    )
