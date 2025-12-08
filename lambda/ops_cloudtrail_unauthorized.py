"""
Lambda function for enriching unauthorized API call alerts.

Function name: ops-cloudtrail-unauthorized
Trigger: CloudWatch Logs subscription filter on unauthorized API events

Triggered by subscription filter matching AccessDenied/UnauthorizedOperation
events in CloudTrail logs. Queries the last N minutes via Logs Insights to
aggregate events, then publishes enriched alert with service, IP, and
principal details to SNS for email delivery.

Copyright 2025 Jason E. Robinson
Licensed under the Apache License, Version 2.0
https://www.apache.org/licenses/LICENSE-2.0
"""

import logging
import os
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()

# Environment configuration
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
LOG_GROUP_NAME = os.environ.get("LOG_GROUP_NAME", "")
ENRICHED_TOPIC_ARN = os.environ.get("ENRICHED_TOPIC_ARN", "")
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

# Logs Insights query for unauthorized API calls
QUERY_TEMPLATE = """
fields @timestamp, eventSource, eventName, sourceIPAddress,
       userIdentity.arn as principalArn, errorCode
| filter errorCode like /UnauthorizedOperation|AccessDenied/
| stats count(*) as attempts by eventSource, eventName, sourceIPAddress, principalArn, errorCode
| sort attempts desc
| limit 50
"""


def run_logs_insights_query() -> list:
    """Execute Logs Insights query and poll for results.

    Returns:
        list of query result rows.
    """
    end_time = int(datetime.now(timezone.utc).timestamp())
    start_time = end_time - (QUERY_WINDOW_MINUTES * 60)

    logger.info(
        "Running Logs Insights query",
        extra={
            "log_group": LOG_GROUP_NAME,
            "start_time": start_time,
            "end_time": end_time,
            "window_minutes": QUERY_WINDOW_MINUTES,
        },
    )

    try:
        response = logs_client.start_query(
            logGroupName=LOG_GROUP_NAME,
            startTime=start_time,
            endTime=end_time,
            queryString=QUERY_TEMPLATE.strip(),
        )
        query_id = response.get("queryId")
    except ClientError as err:
        logger.error("Failed to start query: %s", err)
        raise RuntimeError(f"Failed to start Logs Insights query: {err}") from err

    if not query_id:
        logger.error("No queryId returned from start_query")
        raise RuntimeError("Failed to start Logs Insights query: no queryId returned")

    # Poll for results
    max_attempts = 30
    poll_interval = 1

    for _ in range(max_attempts):
        try:
            result = logs_client.get_query_results(queryId=query_id)
            status = result.get("status", "")

            if status == "Complete":
                return result.get("results", [])
            elif status in ("Failed", "Cancelled", "Timeout"):
                logger.error("Query %s: %s", status, query_id)
                raise RuntimeError(f"Logs Insights query {status}: {query_id}")

            time.sleep(poll_interval)

        except ClientError as err:
            logger.error("Failed to get query results: %s", err)
            raise RuntimeError(f"Failed to get query results: {err}") from err

    logger.error("Query timed out after %d attempts", max_attempts)
    raise RuntimeError(f"Logs Insights query timed out: {query_id}")


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
    return "..." + arn[-(max_length - 3) :]


def format_enriched_message(query_results: list) -> str:
    """Build human-readable enriched message.

    Args:
        query_results: Results from Logs Insights query.

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

    # Aggregate statistics
    total_events = 0
    unique_ips = set()
    unique_principals = set()
    rows = []

    for result in query_results:
        row_data = {}
        for field in result:
            row_data[field.get("field", "")] = field.get("value", "")

        try:
            attempts = int(row_data.get("attempts", "0"))
        except (ValueError, TypeError):
            attempts = 0
        total_events += attempts

        source_ip = row_data.get("sourceIPAddress", "-")
        principal = row_data.get("principalArn", "-")

        if source_ip and source_ip != "-":
            unique_ips.add(source_ip)
        if principal and principal != "-":
            unique_principals.add(principal)

        rows.append(
            {
                "eventSource": row_data.get("eventSource", "-"),
                "eventName": row_data.get("eventName", "-"),
                "sourceIPAddress": source_ip,
                "principalArn": principal,
                "errorCode": row_data.get("errorCode", "-"),
                "attempts": attempts,
            }
        )

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

    if rows:
        # Header
        lines.append("Details:")
        lines.append(f"{'Service':<20} {'API':<20} {'IP':<16} {'Principal':<40} {'Error':<16} {'Count':>5}")

        # Data rows
        for row in rows:
            lines.append(
                f"{row.get('eventSource', '-'):<20} "
                f"{row.get('eventName', '-'):<20} "
                f"{row.get('sourceIPAddress', '-'):<16} "
                f"{truncate_arn(row.get('principalArn', '-')):<40} "
                f"{row.get('errorCode', '-'):<16} "
                f"{row.get('attempts', 0):>5}"
            )
    else:
        lines.append("No detailed events found in query window.")

    return "\n".join(lines)


def publish_enriched_alert(message: str):
    """Publish enriched message to SNS topic.

    Args:
        message: Formatted enriched message.
    """
    subject = "AWS Alert: Unauthorized API Calls"

    try:
        sns_client.publish(
            TopicArn=ENRICHED_TOPIC_ARN,
            Subject=subject,
            Message=message,
        )
        logger.info("Published enriched alert to %s", ENRICHED_TOPIC_ARN)
    except ClientError as err:
        logger.error("Failed to publish to SNS: %s", err)
        raise RuntimeError(f"Failed to publish enriched alert: {err}") from err


def lambda_handler(event: dict, context) -> dict:
    """Lambda entry point. Queries recent unauthorized events and publishes alert.

    Function name: ops-cloudtrail-unauthorized

    Triggered by subscription filter. The event contents are ignored - we query
    Logs Insights for the full picture over the configured time window.

    Args:
        event: Subscription filter event (ignored, just triggers the query).
        context: Lambda context.

    Returns:
        dict with statusCode and body.
    """
    logger.debug(
        "Triggered by subscription filter",
        extra={
            "function_name": getattr(context, "function_name", "unknown"),
            "request_id": getattr(context, "aws_request_id", "unknown"),
        },
    )

    # Validate required environment variables
    if not LOG_GROUP_NAME:
        logger.error("LOG_GROUP_NAME environment variable not set")
        return {"statusCode": 500, "body": "Configuration error: LOG_GROUP_NAME not set"}
    if not ENRICHED_TOPIC_ARN:
        logger.error("ENRICHED_TOPIC_ARN environment variable not set")
        return {"statusCode": 500, "body": "Configuration error: ENRICHED_TOPIC_ARN not set"}

    try:
        query_results = run_logs_insights_query()
        enriched_message = format_enriched_message(query_results)
        publish_enriched_alert(enriched_message)
        logger.debug("Enriched alert published successfully")
        return {"statusCode": 200, "body": "Published"}
    except ClientError as err:
        logger.error("AWS API error: %s", err)
        return {"statusCode": 502, "body": f"AWS error: {err}"}
    except RuntimeError as err:
        logger.error("Processing error: %s", err)
        return {"statusCode": 500, "body": str(err)}
