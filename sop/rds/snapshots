# SOP: Review & Delete RDS/Aurora Snapshots

## Purpose

Standard Operating Procedure (SOP) to safely review and delete outdated RDS DB snapshots and Aurora cluster snapshots in the `takshana-saas-dev` AWS account, plus automation artifacts (Lambda cleanup script and Terraform backup lifecycle policy).

---

## Summary

This document contains:

1. A step-by-step manual SOP to review snapshots and safely delete them.
2. A Python AWS Lambda script (boto3) to automatically identify and delete old snapshots.
3. Terraform configuration to implement a backup lifecycle policy using AWS Backup (preferred long-term control).

---

## Safety & Pre-requisites

* **Permissions:** CloudOps engineer must have at minimum the following AWS IAM permissions:

  * `rds:DescribeDBSnapshots`, `rds:DescribeDBClusterSnapshots`, `rds:DeleteDBSnapshot`, `rds:DeleteDBClusterSnapshot`, `rds:ListTagsForResource`
  * `backup:CreateBackupVault`, `backup:CreateBackupPlan`, `backup:CreateBackupSelection`, `backup:TagResource` (if using AWS Backup)
  * `sns:Publish` (if sending notifications)
* **Backups:** Ensure that any snapshots required for compliance, recovery, or retention are excluded.
* **Communication:** Notify owners (via Slack / ticket) before deletion and keep a changelog.
* **Dry-run:** Always perform a dry-run first. Do not delete in production without approvals.

---

## 1) Manual SOP — Review & Delete

### Step 1 — Inventory

1. Generate a snapshot inventory using AWS Console or CLI.

CLI examples:

```bash
# Describe DB snapshots (RDS instance-level)
aws rds describe-db-snapshots --query 'DBSnapshots[*].[DBSnapshotIdentifier,DBInstanceIdentifier,SnapshotCreateTime,AllocatedStorage]' --output table

# Describe cluster snapshots (Aurora)
aws rds describe-db-cluster-snapshots --query 'DBClusterSnapshots[*].[DBClusterSnapshotIdentifier,DBClusterIdentifier,SnapshotCreateTime,AllocatedStorage]' --output table
```

2. Export results to CSV for sharing with teams (or use the snapshot list you already provided).

### Step 2 — Tag & Owner Validation

* For each snapshot, check tags and identify `Owner`, `Environment`, `Retention` and `CostCenter` tags.

```bash
# List tags for a snapshot (instance snapshot)
aws rds list-tags-for-resource --resource-name arn:aws:rds:<region>:<account-id>:snapshot:<snapshot-id>

# List tags for a cluster snapshot
aws rds list-tags-for-resource --resource-name arn:aws:rds:<region>:<account-id>:cluster-snapshot:<cluster-snapshot-id>
```

* If `Owner` is missing, escalate to the application team or tag it `owner:unassigned` and notify.

### Step 3 — Age & Usage Check

* Check snapshot creation date. Common policy:

  * Keep snapshots for **30 days** for dev/test
  * Keep **90 days** for QA/staging
  * Use longer retention for prod as per compliance
* Cross-check if snapshot is referenced by any automated restore job, documented rollback, or required for audits.

### Step 4 — Approvals

* Create a short approval ticket with the list of snapshot identifiers to be deleted and obtain sign-off from owners and FinOps.

### Step 5 — Dry-run Deletion (Safe test)

* Perform a dry-run by simulating deletion or copying snapshot identifiers into a temporary test script that logs what would be deleted.

Example (pseudo dry-run):

```bash
# (Pseudo) just print snapshots older than 90 days
aws rds describe-db-snapshots --query 'DBSnapshots[?SnapshotCreateTime<`2025-08-01`].[DBSnapshotIdentifier,SnapshotCreateTime]' --output table
```

### Step 6 — Delete Snapshots

* After approvals, execute deletion (careful: irreversible). Use CLI to delete RDS snapshots and DB cluster snapshots.

```bash
# Delete single DB snapshot
aws rds delete-db-snapshot --db-snapshot-identifier apps-contentdesigntime

# Delete Aurora DB cluster snapshot
aws rds delete-db-cluster-snapshot --db-cluster-snapshot-identifier content-perf-postgres-final-snapshot
```

* Monitor CloudTrail and AWS Console to confirm successful deletion.

### Step 7 — Post-Action Audit & Report

* Capture before/after storage metrics and monthly cost impact.
* Update Confluence with the cleanup event and results.
* Add the change to the team’s operational log and tag the ticket as `Done`.

---

## 2) Lambda Script — Automated Cleanup (Python)

**Behaviour:**

* Scans for both `DBSnapshots` and `DBClusterSnapshots`.
* Filters by age (days threshold) and optional exclude tags (e.g., `do-not-delete=true` or `Retention` tag).
* Supports `DRY_RUN` mode to preview deletions.
* Sends a summary to an SNS topic or logs to CloudWatch.

> **Important:** Run with least privilege IAM role and test on a non-prod account first.

```python
# lambda_rds_snapshot_cleanup.py
import os
import boto3
from datetime import datetime, timezone, timedelta

RDS = boto3.client('rds')
SNS = boto3.client('sns')

# Configuration via env vars
AGE_DAYS = int(os.environ.get('AGE_DAYS', '90'))
DRY_RUN = os.environ.get('DRY_RUN', 'true').lower() == 'true'
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')  # optional
EXCLUDE_TAG_KEY = os.environ.get('EXCLUDE_TAG_KEY', 'do-not-delete')
EXCLUDE_TAG_VALUE = os.environ.get('EXCLUDE_TAG_VALUE', 'true')
REGION = os.environ.get('AWS_REGION')


def list_db_snapshots():
    paginator = RDS.get_paginator('describe_db_snapshots')
    for page in paginator.paginate():
        for snap in page.get('DBSnapshots', []):
            yield snap


def list_cluster_snapshots():
    paginator = RDS.get_paginator('describe_db_cluster_snapshots')
    for page in paginator.paginate():
        for snap in page.get('DBClusterSnapshots', []):
            yield snap


def snapshot_tags(resource_arn):
    try:
        resp = RDS.list_tags_for_resource(ResourceName=resource_arn)
        return {t['Key']: t['Value'] for t in resp.get('TagList', [])}
    except Exception:
        return {}


def eligible(snap_time):
    cutoff = datetime.now(timezone.utc) - timedelta(days=AGE_DAYS)
    return snap_time < cutoff


def delete_snapshot(identifier, is_cluster=False):
    if DRY_RUN:
        print(f"DRY RUN: would delete {'cluster' if is_cluster else 'instance'} snapshot: {identifier}")
        return {'status': 'dry-run', 'id': identifier}

    try:
        if is_cluster:
            RDS.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=identifier)
        else:
            RDS.delete_db_snapshot(DBSnapshotIdentifier=identifier)
        print(f"Deleted: {identifier}")
        return {'status': 'deleted', 'id': identifier}
    except Exception as e:
        print(f"Failed to delete {identifier}: {e}")
        return {'status': 'failed', 'id': identifier, 'error': str(e)}


def lambda_handler(event, context):
    results = []

    # instance snapshots
    for snap in list_db_snapshots():
        sid = snap.get('DBSnapshotIdentifier')
        st = snap.get('SnapshotCreateTime')
        arn = snap.get('DBSnapshotArn') or snap.get('DBSnapshotIdentifier')
        if not st:
            continue
        tags = snapshot_tags(arn)
        if tags.get(EXCLUDE_TAG_KEY) == EXCLUDE_TAG_VALUE:
            print(f"Skipping {sid} due to exclude tag")
            continue
        if eligible(st):
            results.append(delete_snapshot(sid, is_cluster=False))

    # cluster snapshots
    for csnap in list_cluster_snapshots():
        sid = csnap.get('DBClusterSnapshotIdentifier')
        st = csnap.get('SnapshotCreateTime')
        arn = csnap.get('DBClusterSnapshotArn') or csnap.get('DBClusterSnapshotIdentifier')
        if not st:
            continue
        tags = snapshot_tags(arn)
        if tags.get(EXCLUDE_TAG_KEY) == EXCLUDE_TAG_VALUE:
            print(f"Skipping {sid} due to exclude tag")
            continue
        if eligible(st):
            results.append(delete_snapshot(sid, is_cluster=True))

    summary = {
        'total_processed': len(results),
        'results': results,
    }

    # publish summary
    if SNS_TOPIC_ARN:
        SNS.publish(TopicArn=SNS_TOPIC_ARN, Message=str(summary), Subject='RDS Snapshot Cleanup Report')

    return summary
```

### Lambda Deployment Notes

* **Runtime:** Python 3.11 (or 3.10)
* **Timeout:** 2–5 minutes (depends on number of snapshots)
* **Memory:** 128–256 MB
* **Environment variables:** `AGE_DAYS`, `DRY_RUN`, `SNS_TOPIC_ARN`, `EXCLUDE_TAG_KEY`, `EXCLUDE_TAG_VALUE`
* **Test flow:**

  1. Deploy with `DRY_RUN=true` and `AGE_DAYS=365` on prod to validate no accidental deletion.
  2. Check logs and SNS summary.
  3. When safe, set `DRY_RUN=false` and use desired `AGE_DAYS`.

### Required IAM Role Policy (example)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "rds:DescribeDBSnapshots",
        "rds:DescribeDBClusterSnapshots",
        "rds:DeleteDBSnapshot",
        "rds:DeleteDBClusterSnapshot",
        "rds:ListTagsForResource"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "sns:Publish"
      ],
      "Resource": "arn:aws:sns:<region>:<account-id>:<topic-name>"
    }
  ]
}
```

---

## 3) Terraform — AWS Backup Plan for Snapshot Lifecycle

**Goal:** Create a centralized AWS Backup plan to manage RDS snapshot lifecycle (expire after N days). Using AWS Backup is safer and auditable compared to ad-hoc deletion.

> This Terraform snippet creates a backup vault and a backup plan with a rule that retains daily backups for 30 days. Adjust `lifecycle` values for weekly/monthly rules as required.

```terraform
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
  }
}

provider "aws" {
  region = var.region
}

resource "aws_backup_vault" "rds_snapshots_vault" {
  name        = "rds-snapshots-vault"
  kms_key_arn = null
}

resource "aws_backup_plan" "rds_lifecycle_plan" {
  name = "rds-snapshot-lifecycle-plan"

  rule {
    rule_name         = "daily-30-days"
    target_vault_name = aws_backup_vault.rds_snapshots_vault.name
    schedule          = "cron(0 5 ? * * *)" # daily at 05:00 UTC

    lifecycle {
      delete_after = 30
    }

    recovery_point_tags = {
      ManagedBy = "FinOps"
    }
  }
}

# Example selection to include RDS resources by tag (requires IAM role)
resource "aws_iam_role" "backup_role" {
  name = "aws_backup_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "backup.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_backup_selection" "rds_selection" {
  name         = "rds-selection"
  iam_role_arn = aws_iam_role.backup_role.arn
  plan_id      = aws_backup_plan.rds_lifecycle_plan.id

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Backup"
    value = "true"
  }
}

variable "region" {
  type    = string
  default = "us-west-2"
}
```

### Notes on Terraform approach

* Tag RDS instances (or snapshots) with `Backup=true` to include them in policy.
* AWS Backup will manage recovery points and expiration (delete after N days).
* AWS Backup supports both RDS instance and RDS cluster backups; check provider docs for supported resource types and regions.

---

## Testing & Rollout Plan

1. **Sandbox:** Deploy the Lambda and Terraform in a non-prod account; run `DRY_RUN=true` for several runs.
2. **Validation:** Confirm only expected snapshots are flagged.
3. **Approval:** Obtain FinOps & App owner approval.
4. **Execute:** Turn off `DRY_RUN` and monitor for one scheduled run.
5. **Report:** Publish summary on Slack and Confluence.

---

## Rollback & Recovery

* Deleted snapshots cannot be recovered. If accidental deletion occurs, escalate to leadership and check if any point-in-time recovery or other backups exist.
* Keep exported inventory CSVs for at least 30 days after deletion.

---

## Change Log

* Document the date, operator, and snapshot identifiers deleted.

---




