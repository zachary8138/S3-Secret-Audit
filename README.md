# S3 Secret Audit

Read-only AWS S3 checks for public exposure misconfigurations and (optionally) sampled object content that may contain secrets or credentials.

## Requirements

- Python **3.10+**
- **boto3** (installed automatically)
- Valid **AWS credentials** with permissions to list and read bucket configuration (and objects, if scanning content)

Typical credential sources: environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), `~/.aws/credentials`, or an IAM instance/profile role.

## Installation

```bash
cd s3-audit
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

## First run (recommended)

Start with bucket configuration checks only (no object reads):

```bash
s3-secret-audit
```

Or limit to specific buckets:

```bash
s3-secret-audit --buckets my-bucket-a my-bucket-b
```

Then, if you are authorized to sample object content:

```bash
s3-secret-audit --scan-objects \
  --buckets my-bucket-a \
  --max-objects-per-bucket 10 \
  --key-prefixes config/ backup/
```

Treat `--scan-objects` output as **sensitive**: findings may include short content snippets that match secret patterns.

## Usage

```bash
# Bucket-level checks only (ACL, policy, Public Access Block)
s3-secret-audit

# Limit to named buckets
s3-secret-audit --buckets app-prod-logs app-prod-backups

# Also sample object keys and scan content for secret patterns
s3-secret-audit --scan-objects

# Limit sampling and focus on key prefixes
s3-secret-audit --scan-objects \
  --max-objects-per-bucket 50 \
  --key-prefixes backup/ config/ .env

# CI / automation
s3-secret-audit --scan-objects --fail-on high --jsonl s3-findings.jsonl
```

Run without installing (from repo root):

```bash
PYTHONPATH=src python3 -m s3_audit --scan-objects
```

## Scope

By default, the tool lists **all buckets** visible to the current AWS identity, then audits each one. Use `--buckets` to restrict the audit to named buckets.

There is no write/delete API usage; the tool only calls read/list APIs. Object sampling (`--scan-objects`) still downloads real object bytes into memory and may print match snippets to stdout / JSONL.

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--buckets` | *(all listable buckets)* | Limit audit to these bucket name(s) |
| `--scan-objects` | off | Sample objects and scan content for secret patterns |
| `--max-objects-per-bucket` | `25` | Max objects to consider per bucket when scanning |
| `--max-bytes-per-object` | `256000` | Max bytes to read per object (Range request) |
| `--key-prefixes` | *(all)* | Limit listing to these prefixes (e.g. `backup/`, `config/`) |
| `--regions` | *(none)* | Reserved for future use; not required for global bucket list |
| `--jsonl` | *(none)* | Append findings as JSON Lines to this file |
| `--fail-on` | *(none)* | Exit code `2` if any finding at or above this severity |

## What it checks

### Bucket configuration (always)

For each bucket:

- **Public Access Block** — all four block settings enabled
- **Bucket ACL** — grants to `AllUsers` or `AuthenticatedUsers`
- **Bucket policy** — heuristic for `Principal: "*"` with `s3:GetObject` / `s3:ListBucket` / `s3:*`

Aggregated as `aws_s3_public_bucket_risk` when any issue is detected.

### Object content (`--scan-objects`)

Samples up to `--max-objects-per-bucket` objects per bucket. Objects are fetched when:

- The key name matches sensitive filename indicators (e.g. `.env`, `credentials`, `id_rsa`), **or**
- The bucket already flagged public/misconfigured

Content is scanned with conservative regex patterns (AWS keys, GitHub tokens, private key blocks, generic `api_key=` assignments, etc.).

| Check | Severity | When |
|-------|----------|------|
| `aws_s3_public_bucket_risk` | high | Bucket may be public or misconfigured |
| `aws_s3_possible_secret_in_object` | critical | Object sample matches a secret pattern |
| `aws_s3_list_buckets` | high | Cannot list buckets (auth/permissions) |
| `aws_s3_bucket_not_found` | medium | `--buckets` name not returned by ListBuckets |
| `aws_s3_public_access_block` | medium | Cannot read Public Access Block |
| `aws_s3_bucket_acl` | medium | Cannot read bucket ACL |
| `aws_s3_bucket_policy` | medium | Cannot read bucket policy |
| `aws_s3_list_objects` | medium | Cannot list objects for a prefix |
| `aws_s3_get_object` | low | Cannot read a sampled object |
| `aws_s3_dependency_missing` | high | boto3 not installed |

## Output

Each finding is printed to stdout:

```text
[HIGH] aws_s3_public_bucket_risk aws:s3:::my-bucket - Bucket appears potentially public/misconfigured
```

With `--jsonl`, the same finding is appended as one JSON object per line.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Completed; no finding met `--fail-on` threshold (or `--fail-on` not set) |
| `2` | At least one finding met or exceeded `--fail-on` severity |

## IAM permissions (minimum)

Bucket audit only:

- `s3:ListAllMyBuckets`
- `s3:GetBucketPublicAccessBlock`
- `s3:GetBucketAcl`
- `s3:GetBucketPolicy`

With `--scan-objects`, also:

- `s3:ListBucket`
- `s3:GetObject`

Adjust policies to your scope (specific buckets/prefixes) as needed.

## Project layout

```text
s3-audit/
  pyproject.toml
  README.md
  src/s3_audit/
    __main__.py     # python -m s3_audit entry
    cli.py          # CLI entry point
    audit.py        # S3 audit logic
    findings.py     # Finding model and output
    patterns.py     # Filename indicators and secret regex patterns
```

## Authorization

Only run against AWS accounts and buckets you are **explicitly authorized** to assess. Object sampling reads real data; use least-privilege IAM and appropriate data-handling policies.

