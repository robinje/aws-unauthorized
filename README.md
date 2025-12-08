# Unauthorized API Calls Enriched Alerting

Detects unauthorized AWS API calls and sends enriched alerts with service, IP, and principal details.

Copyright 2025 Jason E. Robinson. Licensed under Apache 2.0.

## Quick Start

```bash
python deploy.py --email security@example.com
```

Confirm the email subscription when you receive it.

## What It Does

1. **Discovers** existing CloudTrail and log groups
2. **Creates** only missing components
3. **Deploys** Lambda with subscription filter trigger
4. **Sends** enriched alerts with actionable details

## Enriched Alert Output

When unauthorized API calls occur, you receive:

```
Unauthorized API Calls - 7 events in last 10 minutes

Account: 436556108963
Region:  us-east-1
Window:  2025-12-07T22:17:00Z to 2025-12-07T22:27:00Z

Summary:
  Total Events:      7
  Unique IPs:        3
  Unique Principals: 2

Details:
Service              API                 IP              Principal                           Error           Count
ec2.amazonaws.com    DescribeSubnets     203.0.113.10    arn:aws:iam::...:user/ci-runner     AccessDenied    3
s3.amazonaws.com     PutBucketPolicy     198.51.100.23   arn:aws:sts::...:assumed-role/app   AccessDenied    2
sts.amazonaws.com    AssumeRole          198.51.100.200  arn:aws:iam::...:user/old-admin     AccessDenied    2
```

## Options

| Option | Required | Description |
|--------|----------|-------------|
| `--email` | Yes (unless --dry-run) | Email for enriched alerts |
| `--region` | No | AWS region (default: us-east-1) |
| `--dry-run` | No | Preview changes without applying |

## Dry Run

```bash
python deploy.py --dry-run
```

## Validation

```bash
# Deploy
python deploy.py --email security@example.com

# Confirm email subscription

# Trigger an AccessDenied error to test (use your account ID)
aws sts assume-role \
  --role-arn arn:aws:iam::YOUR_ACCOUNT_ID:role/nonexistent \
  --role-session-name test 2>/dev/null || true

# Check Lambda logs
aws logs tail /aws/lambda/ops-cloudtrail-unauthorized --since 10m --follow

# Verify enriched email arrives
```

## Requirements

- Python 3.12+
- boto3
- AWS credentials with permissions listed below

## Required IAM Permissions

- cloudtrail:DescribeTrails, CreateTrail, StartLogging
- logs:DescribeLogGroups, CreateLogGroup, DescribeSubscriptionFilters, PutSubscriptionFilter
- sns:CreateTopic, Subscribe, ListSubscriptionsByTopic, GetTopicAttributes, ListTopics
- lambda:GetFunction, CreateFunction, UpdateFunctionCode, UpdateFunctionConfiguration, AddPermission
- iam:GetRole, CreateRole, PutRolePolicy, AttachRolePolicy
- s3:CreateBucket, PutBucketPolicy, PutPublicAccessBlock, HeadBucket
- sts:GetCallerIdentity

## Deployment Behavior

| Component | If Exists | If Missing |
|-----------|-----------|------------|
| CloudTrail | Use existing | Create with CloudWatch Logs |
| CloudWatch Log Group | Use existing | Create (no retention set) |
| Lambda Enricher | Update code | Create function and role |
| Subscription Filter | Use existing | Create to trigger Lambda |
| SNS Topic | Use existing | Create for alerts |
| Email Subscription | Skip if exists | Create and require confirmation |
