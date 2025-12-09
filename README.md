# Unauthorized API Calls Alerting

Detects unauthorized AWS API calls and sends reports with service, IP, and principal details.

Copyright 2025 Jason E. Robinson. Licensed under Apache 2.0.

## Prerequisites

- Existing CloudTrail with CloudWatch Logs integration

## Quick Start

```bash
python deploy.py --email security@example.com
```

Confirm the email subscription when you receive it.

## What It Does

1. **Discovers** existing CloudTrail with CloudWatch Logs
2. **Creates** SNS topics, Lambda function, IAM role, metrics filter, alarm
3. **Triggers** Lambda via CloudWatch Alarm when unauthorized calls detected
4. **Queries** CloudWatch Logs for event details
5. **Sends** report via email

## Report Output

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
| `--email` | Yes (unless --dry-run or --delete) | Email for reports |
| `--region` | No | AWS region (default: us-east-1) |
| `--dry-run` | No | Preview changes |
| `--delete` | No | Delete all resources |

## Project Structure

```
aws-unauthorized/
├── deploy.py                            # Deployment script
├── lambda/
│   └── ops_cloudtrail_unauthorized.py   # Lambda function
└── README.md
```

## Cleanup

```bash
python deploy.py --delete
```

## Resources Created

| Resource | Name |
|----------|------|
| SNS Topic (alarm) | unauth-api-alarm |
| SNS Topic (report) | unauth-api-report |
| IAM Role | ops-cloudtrail-unauthorized-role |
| Lambda Function | ops-cloudtrail-unauthorized |
| Metrics Filter | unauth-api-metric |
| CloudWatch Alarm | unauth-api-alarm |

## Flow

```
CloudTrail → Log Group → Metrics Filter → Alarm → SNS (alarm) → Lambda → SNS (report) → Email
```

## Required IAM Permissions

- cloudtrail:DescribeTrails
- sns:CreateTopic, DeleteTopic, Subscribe, ListSubscriptionsByTopic
- iam:CreateRole, GetRole, DeleteRole, AttachRolePolicy, DetachRolePolicy, PutRolePolicy, DeleteRolePolicy
- lambda:CreateFunction, GetFunction, UpdateFunctionCode, UpdateFunctionConfiguration, DeleteFunction, AddPermission, RemovePermission
- logs:PutMetricFilter, DeleteMetricFilter
- cloudwatch:PutMetricAlarm, DeleteAlarms
- sts:GetCallerIdentity
