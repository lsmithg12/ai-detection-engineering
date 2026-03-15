"""
simulator/generators/cloud.py — Cloud (AWS CloudTrail) event generator.

Generates ECS-formatted CloudTrail events for cloud attack techniques
mapped to MITRE ATT&CK.
"""
from __future__ import annotations

import json
import random

from simulator.generators import (
    PlatformGenerator,
    _now_iso,
)

_KNOWN_IPS = ["10.0.1.50", "10.0.1.51", "10.0.2.100", "203.0.113.10"]
_KNOWN_REGIONS = ["us-west-2"]
_KNOWN_USERS = ["alice", "bob", "svc-deploy", "svc-monitoring"]
_BUCKET_NAMES = ["corp-backups", "prod-assets", "dev-artifacts", "sensitive-data-bucket"]
_S3_KEYS = [
    "exports/employees.csv",
    "finance/q4-report.xlsx",
    "secrets/db-credentials.json",
    "backups/users.db",
]


def _generate_cloudtrail_event(
    event_name: str,
    service: str,
    source_ip: str,
    user_identity: dict,
    request_params: dict,
    technique_id: str,
    region: str = "us-east-1",
) -> dict:
    return {
        "@timestamp": _now_iso(),
        "event": {
            "category": "iam" if service == "iam" else "configuration",
            "type": "info",
            "kind": "event",
            "action": event_name,
            "outcome": "success",
            "provider": f"{service}.amazonaws.com",
            "dataset": "aws.cloudtrail",
        },
        "cloud": {
            "provider": "aws",
            "account": {"id": "123456789012"},
            "region": region,
            "service": {"name": service},
        },
        "source": {"ip": source_ip},
        "user": {
            "name": user_identity.get("user_name", "unknown"),
            "id": user_identity.get("account_id", "123456789012"),
        },
        "user_agent": {
            "original": user_identity.get("user_agent", "aws-cli/2.15.0"),
        },
        "aws": {
            "cloudtrail": {
                "event_type": "AwsApiCall",
                "event_source": f"{service}.amazonaws.com",
                "event_name": event_name,
                "request_parameters": json.dumps(request_params or {}),
                "user_identity": user_identity,
            },
        },
        "_simulation": {
            "type": "attack",
            "technique": technique_id,
            "platform": "cloud",
        },
    }


class CloudGenerator(PlatformGenerator):
    """Generates AWS CloudTrail ECS events for attack simulation and baselines."""

    platform = "cloud"
    event_types = ["api_call", "console_login", "iam_change"]

    def generate_attack(self, technique_id: str, **kwargs) -> list[dict]:
        if technique_id == "T1078.004":
            return self._t1078_004()
        elif technique_id == "T1530":
            return self._t1530()
        elif technique_id == "T1098.001":
            return self._t1098_001()
        elif technique_id == "T1537":
            return self._t1537()
        else:
            return []

    def generate_benign(self, event_type: str = "api_call", count: int = 5) -> list[dict]:
        benign_calls = [
            ("DescribeInstances", "ec2", {"Filters": []}),
            ("GetCallerIdentity", "sts", {}),
            ("ListBuckets", "s3", {}),
            ("DescribeSecurityGroups", "ec2", {}),
            ("GetUser", "iam", {"UserName": "alice"}),
            ("ListRoles", "iam", {}),
            ("DescribeSubnets", "ec2", {}),
            ("GetBucketAcl", "s3", {"Bucket": "corp-backups"}),
        ]
        events = []
        for _ in range(count):
            event_name, service, params = random.choice(benign_calls)
            source_ip = random.choice(_KNOWN_IPS)
            user = random.choice(_KNOWN_USERS)
            user_identity = {
                "type": "IAMUser",
                "user_name": user,
                "account_id": "123456789012",
                "user_agent": "aws-cli/2.15.0",
            }
            ev = _generate_cloudtrail_event(
                event_name=event_name,
                service=service,
                source_ip=source_ip,
                user_identity=user_identity,
                request_params=params,
                technique_id="baseline",
                region="us-west-2",
            )
            ev["_simulation"] = {
                "type": "baseline",
                "platform": "cloud",
                "expected_match": False,
            }
            events.append(ev)
        return events

    # ── Technique implementations ──────────────────────────────────────

    def _t1078_004(self) -> list[dict]:
        """T1078.004 — Valid Accounts: Cloud Accounts — unusual console login."""
        user_identity = {
            "type": "IAMUser",
            "user_name": "alice",
            "account_id": "123456789012",
            "arn": "arn:aws:iam::123456789012:user/alice",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }
        ev = _generate_cloudtrail_event(
            event_name="ConsoleLogin",
            service="signin",
            source_ip="198.51.100.1",
            user_identity=user_identity,
            request_params={"MFAUsed": "No"},
            technique_id="T1078.004",
            region="us-east-1",
        )
        ev["_simulation"]["expected_match"] = True
        ev["_simulation"]["description"] = (
            "Console login from external IP 198.51.100.1 in us-east-1 — "
            "account normally authenticates from us-west-2"
        )
        # Override event category for signin
        ev["event"]["category"] = "authentication"
        ev["event"]["type"] = "start"
        return [ev]

    def _t1530(self) -> list[dict]:
        """T1530 — Data from Cloud Storage — S3 GetObject from unusual principal."""
        user_identity = {
            "type": "AssumedRole",
            "user_name": "ExternalAuditor",
            "account_id": "999888777666",
            "arn": "arn:aws:sts::999888777666:assumed-role/ExternalAuditor/session",
            "user_agent": "Boto3/1.26.0 Python/3.11.0",
        }
        ev = _generate_cloudtrail_event(
            event_name="GetObject",
            service="s3",
            source_ip="203.0.113.75",
            user_identity=user_identity,
            request_params={
                "bucketName": "sensitive-data-bucket",
                "key": "exports/employees.csv",
            },
            technique_id="T1530",
            region="us-east-1",
        )
        ev["_simulation"]["expected_match"] = True
        ev["_simulation"]["description"] = (
            "S3 GetObject on sensitive-data-bucket/exports/employees.csv "
            "by cross-account role from external IP"
        )
        ev["event"]["category"] = "network"
        return [ev]

    def _t1098_001(self) -> list[dict]:
        """T1098.001 — Account Manipulation: Additional Cloud Credentials — CreateAccessKey."""
        user_identity = {
            "type": "IAMUser",
            "user_name": "bob",
            "account_id": "123456789012",
            "arn": "arn:aws:iam::123456789012:user/bob",
            "user_agent": "aws-cli/2.15.0 Python/3.11.0 Linux/5.15.0",
        }
        ev = _generate_cloudtrail_event(
            event_name="CreateAccessKey",
            service="iam",
            source_ip="198.51.100.42",
            user_identity=user_identity,
            request_params={"UserName": "admin"},
            technique_id="T1098.001",
            region="us-east-1",
        )
        ev["_simulation"]["expected_match"] = True
        ev["_simulation"]["description"] = (
            "IAM CreateAccessKey called for 'admin' user by non-admin principal from external IP"
        )
        return [ev]

    def _t1537(self) -> list[dict]:
        """T1537 — Transfer Data to Cloud Account — PutBucketPolicy with wildcard principal."""
        user_identity = {
            "type": "IAMUser",
            "user_name": "svc-deploy",
            "account_id": "123456789012",
            "arn": "arn:aws:iam::123456789012:user/svc-deploy",
            "user_agent": "aws-cli/2.15.0",
        }
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::corp-backups/*",
                }
            ],
        }
        ev = _generate_cloudtrail_event(
            event_name="PutBucketPolicy",
            service="s3",
            source_ip="198.51.100.99",
            user_identity=user_identity,
            request_params={
                "bucketName": "corp-backups",
                "bucketPolicy": json.dumps(policy),
            },
            technique_id="T1537",
            region="us-east-1",
        )
        ev["_simulation"]["expected_match"] = True
        ev["_simulation"]["description"] = (
            "S3 bucket policy set with wildcard (*) principal — enables public read access"
        )
        return [ev]
