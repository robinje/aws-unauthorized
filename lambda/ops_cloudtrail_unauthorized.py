"""
Lambda function for enriching unauthorized API call alerts.

Function name: ops-cloudtrail-unauthorized
Trigger: CloudWatch Alarm (via SNS) from metrics filter

Triggered by CloudWatch Alarm when metrics filter detects AccessDenied or
UnauthorizedOperation events. Queries CloudWatch Logs for the last N minutes
using filter_log_events, aggregates events, then publishes enriched alert
with service, IP, and principal details to SNS for email delivery.

Copyright 2025 Jason E. Robinson
Licensed under the Apache License, Version 2.0
https://www.apache.org/licenses/LICENSE-2.0
"""

import json
import logging
import os
from collections import defaultdict
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()

# Environment configuration
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
LOG_GROUP_NAME = os.environ.get("LOG_GROUP_NAME", "")
REPORT_TOPIC_ARN = os.environ.get("REPORT_TOPIC_ARN", "")
AWS_REGION = os.environ.get("AWS_REGION", "")
AWS_ACCOUNT_ID = os.environ.get("AWS_ACCOUNT_ID", "")

try:
    QUERY_WINDOW_MINUTES = int(os.environ.get("QUERY_WINDOW_MINUTES", "10"))
except ValueError:
    QUERY_WINDOW_MINUTES = 10

logger.setLevel(getattr(logging, LOG_LEVEL.upper(), logging.INFO))

# Boto3 clients
logs_client = boto3.client("logs")
sns_client = boto3.client("sns")

# Filter pattern for unauthorized API calls (CloudWatch Logs filter syntax)
FILTER_PATTERN = '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }'


def query_unauthorized_events() -> list:
    """Query CloudWatch Logs for unauthorized events using filter_log_events.

    Returns:
        list of parsed CloudTrail events.
    """
    end_time = int(datetime.now(timezone.utc).timestamp() * 1000)
    start_time = end_time - (QUERY_WINDOW_MINUTES * 60 * 1000)

    logger.info(
        "Querying CloudWatch Logs",
        extra={
            "log_group": LOG_GROUP_NAME,
            "start_time": start_time,
            "end_time": end_time,
            "window_minutes": QUERY_WINDOW_MINUTES,
        },
    )

    events = []
    next_token = None

    try:
        while True:
            params = {
                "logGroupName": LOG_GROUP_NAME,
                "startTime": start_time,
                "endTime": end_time,
                "filterPattern": FILTER_PATTERN,
                "limit": 100,
            }
            if next_token:
                params["nextToken"] = next_token

            response = logs_client.filter_log_events(**params)

            for event in response.get("events", []):
                message = event.get("message", "")
                try:
                    parsed = json.loads(message)
                    events.append(parsed)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse event: %s", message[:100])

            next_token = response.get("nextToken")
            if not next_token:
                break

            # Limit total events to prevent runaway queries
            if len(events) >= 500:
                logger.warning("Reached event limit, stopping query")
                break

    except ClientError as err:
        logger.error("Failed to query logs: %s", err)
        raise RuntimeError(f"Failed to query CloudWatch Logs: {err}") from err

    logger.info("Retrieved %d events", len(events))
    return events


def aggregate_events(events: list) -> list:
    """Aggregate events by service, API, IP, principal, and error code.

    Args:
        events: List of parsed CloudTrail events.

    Returns:
        list of aggregated rows sorted by count descending.
    """
    aggregation = defaultdict(int)

    for event in events:
        key = (
            event.get("eventSource", "-"),
            event.get("eventName", "-"),
            event.get("sourceIPAddress", "-"),
            event.get("userIdentity", {}).get("arn", "-"),
            event.get("errorCode", "-"),
        )
        aggregation[key] += 1

    rows = []
    for key, count in aggregation.items():
        rows.append({
            "eventSource": key[0],
            "eventName": key[1],
            "sourceIPAddress": key[2],
            "principalArn": key[3],
            "errorCode": key[4],
            "count": count,
        })

    # Sort by count descending
    rows.sort(key=lambda x: x.get("count", 0), reverse=True)

    # Limit to top 50
    return rows[:50]


def truncate_arn(arn: str, max_length: int = 40) -> str:
    """Shorten ARN for display, keeping meaningful suffix.

    Args:
        arn: Full ARN string.
        max_length: Maximum display length.

    Returns:
        Truncated ARN with ellipsis prefix if shortened.
    """
    if not arn or len(arn) <= max_length:
        return arn or "-"

    # Keep the meaningful part (usually user/role name at the end)
    return "..." + arn[-(max_length - 3):]


def format_report(aggregated: list, total_events: int) -> str:
    """Build human-readable report message.

    Args:
        aggregated: Aggregated event rows.
        total_events: Total number of events before aggregation.

    Returns:
        Formatted message string for email.
    """
    account_id = AWS_ACCOUNT_ID or "Unknown"
    region = AWS_REGION or "Unknown"

    # Calculate time window
    end_time = datetime.now(timezone.utc)
    start_time = datetime.fromtimestamp(
        end_time.timestamp() - (QUERY_WINDOW_MINUTES * 60),
        tz=timezone.utc,
    )

    # Collect unique IPs and principals
    unique_ips = set()
    unique_principals = set()

    for row in aggregated:
        source_ip = row.get("sourceIPAddress", "-")
        principal = row.get("principalArn", "-")

        if source_ip and source_ip != "-":
            unique_ips.add(source_ip)
        if principal and principal != "-":
            unique_principals.add(principal)

    # Build message
    lines = [
        f"Unauthorized API Calls - {total_events} events in last {QUERY_WINDOW_MINUTES} minutes",
        "",
        f"Account: {account_id}",
        f"Region:  {region}",
        f"Window:  {start_time.strftime('%Y-%m-%dT%H:%M:%SZ')} to {end_time.strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "",
        "Summary:",
        f"  Total Events:      {total_events}",
        f"  Unique IPs:        {len(unique_ips)}",
        f"  Unique Principals: {len(unique_principals)}",
        "",
    ]

    if aggregated:
        # Header
        lines.append("Details:")
        lines.append(f"{'Service':<20} {'API':<20} {'IP':<16} {'Principal':<40} {'Error':<16} {'Count':>5}")

        # Data rows
        for row in aggregated:
            lines.append(
                f"{row.get('eventSource', '-'):<20} "
                f"{row.get('eventName', '-'):<20} "
                f"{row.get('sourceIPAddress', '-'):<16} "
                f"{truncate_arn(row.get('principalArn', '-')):<40} "
                f"{row.get('errorCode', '-'):<16} "
                f"{row.get('count', 0):>5}"
            )
    else:
        lines.append("No detailed events found in query window.")

    return "\n".join(lines)


def publish_report(message: str):
    """Publish report to SNS topic.

    Args:
        message: Formatted report message.
    """
    try:
        sns_client.publish(
            TopicArn=REPORT_TOPIC_ARN,
            Subject="AWS Alert: Unauthorized API Calls",
            Message=message,
        )
        logger.info("Published report to %s", REPORT_TOPIC_ARN)
    except ClientError as err:
        logger.error("Failed to publish to SNS: %s", err)
        raise RuntimeError(f"Failed to publish report: {err}") from err


def lambda_handler(event: dict, context) -> dict:
    """Lambda entry point. Queries recent unauthorized events and publishes alert.

    Function name: ops-cloudtrail-unauthorized

    Triggered by CloudWatch Alarm via SNS when metrics filter threshold crossed.
    The alarm event is not parsed - we query CloudWatch Logs directly for the
    full picture over the configured time window.

    Args:
        event: SNS event from CloudWatch Alarm (not parsed, just triggers query).
        context: Lambda context.

    Returns:
        dict with statusCode and body.
    """
    logger.info(
        "Triggered by CloudWatch Alarm",
        extra={
            "function_name": getattr(context, "function_name", "unknown"),
            "request_id": getattr(context, "aws_request_id", "unknown"),
        },
    )

    # Validate required environment variables
    if not LOG_GROUP_NAME:
        logger.error("LOG_GROUP_NAME environment variable not set")
        return {"statusCode": 500, "body": "Configuration error: LOG_GROUP_NAME not set"}
    if not REPORT_TOPIC_ARN:
        logger.error("REPORT_TOPIC_ARN environment variable not set")
        return {"statusCode": 500, "body": "Configuration error: REPORT_TOPIC_ARN not set"}

    try:
        events = query_unauthorized_events()
        aggregated = aggregate_events(events)
        message = format_report(aggregated, len(events))
        publish_report(message)
        logger.info("Report published successfully")
        return {"statusCode": 200, "body": "Published"}
    except ClientError as err:
        logger.error("AWS API error: %s", err)
        return {"statusCode": 502, "body": f"AWS error: {err}"}
    except RuntimeError as err:
        logger.error("Processing error: %s", err)
        return {"statusCode": 500, "body": str(err)}
    except Exception as err:
        logger.error("Unexpected error: %s", err)
        return {"statusCode": 500, "body": f"Unexpected error: {err}"}
