"""
Deployment script for unauthorized API call alerting.

Discovers existing CloudTrail and deploys alerting resources via boto3.
Requires an existing CloudTrail with CloudWatch Logs integration.

Copyright 2025 Jason E. Robinson
Licensed under the Apache License, Version 2.0
https://www.apache.org/licenses/LICENSE-2.0
"""

import argparse
import io
import json
import sys
import time
import zipfile
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

# Resource naming
ALARM_TOPIC_NAME = "unauth-api-alarm"
REPORT_TOPIC_NAME = "unauth-api-report"
LAMBDA_FUNCTION_NAME = "ops-cloudtrail-unauthorized"
LAMBDA_ROLE_NAME = "ops-cloudtrail-unauthorized-role"
METRIC_FILTER_NAME = "unauth-api-metric"
ALARM_NAME = "unauth-api-alarm"


class DeploymentContext:
    """Holds deployment state and boto3 clients."""

    def __init__(self, region: str, dry_run: bool = False):
        self.region = region
        self.dry_run = dry_run
        self.account_id = ""

        self.sts = boto3.client("sts", region_name=region)
        self.cloudtrail = boto3.client("cloudtrail", region_name=region)
        self.logs = boto3.client("logs", region_name=region)
        self.sns = boto3.client("sns", region_name=region)
        self.iam = boto3.client("iam", region_name=region)
        self.lambda_client = boto3.client("lambda", region_name=region)
        self.cloudwatch = boto3.client("cloudwatch", region_name=region)

        self.log_group_name = ""
        self.log_group_arn = ""
        self.alarm_topic_arn = ""
        self.report_topic_arn = ""
        self.role_arn = ""

    def get_account_id(self):
        """Get AWS account ID."""
        if not self.account_id:
            response = self.sts.get_caller_identity()
            self.account_id = response.get("Account", "")
        return self.account_id


def log(message: str, dry_run: bool = False):
    """Print log message."""
    prefix = "[DRY-RUN] " if dry_run else ""
    print(f"{prefix}{message}")


def create_sns_topics(ctx: DeploymentContext, email: str):
    """Create alarm topic (Lambda subscribes) and report topic (email subscribes)."""
    if ctx.dry_run:
        log(f"Would create SNS topics: {ALARM_TOPIC_NAME}, {REPORT_TOPIC_NAME}", dry_run=True)
        if email:
            log(f"Would subscribe email: {email}", dry_run=True)
        ctx.alarm_topic_arn = f"arn:aws:sns:{ctx.region}:{ctx.get_account_id()}:{ALARM_TOPIC_NAME}"
        ctx.report_topic_arn = f"arn:aws:sns:{ctx.region}:{ctx.get_account_id()}:{REPORT_TOPIC_NAME}"
        return

    # Alarm topic - Lambda subscribes to this
    response = ctx.sns.create_topic(Name=ALARM_TOPIC_NAME)
    ctx.alarm_topic_arn = response.get("TopicArn", "")
    log(f"Alarm topic: {ctx.alarm_topic_arn}")

    # Report topic - email subscribes to this
    response = ctx.sns.create_topic(Name=REPORT_TOPIC_NAME)
    ctx.report_topic_arn = response.get("TopicArn", "")
    log(f"Report topic: {ctx.report_topic_arn}")

    # Subscribe email to report topic
    paginator = ctx.sns.get_paginator("list_subscriptions_by_topic")
    for page in paginator.paginate(TopicArn=ctx.report_topic_arn):
        for sub in page.get("Subscriptions", []):
            if sub.get("Protocol") == "email" and sub.get("Endpoint") == email:
                log(f"Email already subscribed: {email}")
                return

    ctx.sns.subscribe(TopicArn=ctx.report_topic_arn, Protocol="email", Endpoint=email)
    log(f"Email subscription pending: {email}")


def create_lambda_role(ctx: DeploymentContext) -> str:
    """Create or get IAM role for Lambda."""
    if ctx.dry_run:
        log(f"Would create IAM role: {LAMBDA_ROLE_NAME}", dry_run=True)
        return f"arn:aws:iam::{ctx.get_account_id()}:role/{LAMBDA_ROLE_NAME}"

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    try:
        response = ctx.iam.create_role(
            RoleName=LAMBDA_ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Role for unauthorized API call alerting Lambda",
        )
        arn = response.get("Role", {}).get("Arn", "")
        log(f"Created IAM role: {LAMBDA_ROLE_NAME}")
    except ClientError as err:
        if "EntityAlreadyExists" in str(err):
            response = ctx.iam.get_role(RoleName=LAMBDA_ROLE_NAME)
            arn = response.get("Role", {}).get("Arn", "")
            log(f"IAM role exists: {LAMBDA_ROLE_NAME}")
        else:
            raise

    # Attach basic execution policy
    try:
        ctx.iam.attach_role_policy(
            RoleName=LAMBDA_ROLE_NAME,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
    except ClientError as err:
        if "PolicyNotAttachable" in str(err):
            raise
        log(f"Policy already attached or no change needed: {LAMBDA_ROLE_NAME}")

    # Inline policy for logs and SNS
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "logs:FilterLogEvents",
                "Resource": ctx.log_group_arn,
            },
            {
                "Effect": "Allow",
                "Action": "sns:Publish",
                "Resource": ctx.report_topic_arn,
            },
        ],
    }

    ctx.iam.put_role_policy(
        RoleName=LAMBDA_ROLE_NAME,
        PolicyName="FilterLogEventsAndSNS",
        PolicyDocument=json.dumps(inline_policy),
    )

    return arn


def create_lambda_zip() -> bytes:
    """Create zip of Lambda code in memory."""
    lambda_file = Path(__file__).parent / "lambda" / "ops_cloudtrail_unauthorized.py"
    if not lambda_file.exists():
        raise RuntimeError(f"Lambda code not found: {lambda_file}")

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(lambda_file, "ops_cloudtrail_unauthorized.py")
    zip_buffer.seek(0)
    return zip_buffer.read()


def create_lambda(ctx: DeploymentContext):
    """Create or update Lambda function."""
    if ctx.dry_run:
        log(f"Would create Lambda: {LAMBDA_FUNCTION_NAME}", dry_run=True)
        return f"arn:aws:lambda:{ctx.region}:{ctx.get_account_id()}:function:{LAMBDA_FUNCTION_NAME}"

    zip_bytes = create_lambda_zip()
    log(f"Lambda package: {len(zip_bytes)} bytes")

    environment = {
        "Variables": {
            "LOG_LEVEL": "INFO",
            "LOG_GROUP_NAME": ctx.log_group_name,
            "REPORT_TOPIC_ARN": ctx.report_topic_arn,
            "QUERY_WINDOW_MINUTES": "10",
            "AWS_ACCOUNT_ID": ctx.get_account_id(),
        }
    }

    arn = ""
    try:
        response = ctx.lambda_client.get_function(FunctionName=LAMBDA_FUNCTION_NAME)
        arn = response.get("Configuration", {}).get("FunctionArn", "")
        # Update existing
        ctx.lambda_client.update_function_code(FunctionName=LAMBDA_FUNCTION_NAME, ZipFile=zip_bytes)
        time.sleep(2)
        ctx.lambda_client.update_function_configuration(
            FunctionName=LAMBDA_FUNCTION_NAME,
            Role=ctx.role_arn,
            Handler="ops_cloudtrail_unauthorized.lambda_handler",
            Runtime="python3.12",
            Timeout=60,
            MemorySize=256,
            Environment=environment,
        )
        log(f"Updated Lambda: {LAMBDA_FUNCTION_NAME}")
    except ClientError as err:
        if "ResourceNotFoundException" in str(err):
            # Create new - retry for IAM propagation
            for attempt in range(5):
                try:
                    response = ctx.lambda_client.create_function(
                        FunctionName=LAMBDA_FUNCTION_NAME,
                        Runtime="python3.12",
                        Role=ctx.role_arn,
                        Handler="ops_cloudtrail_unauthorized.lambda_handler",
                        Code={"ZipFile": zip_bytes},
                        Timeout=60,
                        MemorySize=256,
                        Environment=environment,
                    )
                    arn = response.get("FunctionArn", "")
                    log(f"Created Lambda: {LAMBDA_FUNCTION_NAME}")
                    break
                except ClientError as create_err:
                    if "InvalidParameterValueException" in str(create_err) and attempt < 4:
                        log("Waiting for IAM role propagation...")
                        time.sleep(5)
                    else:
                        raise
        else:
            raise

    # Wait for Lambda to be active before adding permissions
    log("Waiting for Lambda to become active...")
    waiter = ctx.lambda_client.get_waiter("function_active")
    waiter.wait(FunctionName=LAMBDA_FUNCTION_NAME)

    # Add SNS permission for alarm topic to invoke Lambda
    try:
        ctx.lambda_client.remove_permission(FunctionName=LAMBDA_FUNCTION_NAME, StatementId="sns-invoke")
        log("Removed existing SNS invoke permission")
    except ClientError as err:
        if "ResourceNotFoundException" not in str(err):
            log(f"Could not remove existing permission: {err}")

    ctx.lambda_client.add_permission(
        FunctionName=LAMBDA_FUNCTION_NAME,
        StatementId="sns-invoke",
        Action="lambda:InvokeFunction",
        Principal="sns.amazonaws.com",
        SourceArn=ctx.alarm_topic_arn,
    )

    # Subscribe Lambda to alarm topic
    paginator = ctx.sns.get_paginator("list_subscriptions_by_topic")
    for page in paginator.paginate(TopicArn=ctx.alarm_topic_arn):
        for sub in page.get("Subscriptions", []):
            if sub.get("Protocol") == "lambda" and sub.get("Endpoint") == arn:
                return

    ctx.sns.subscribe(TopicArn=ctx.alarm_topic_arn, Protocol="lambda", Endpoint=arn)


def create_metric_filter(ctx: DeploymentContext):
    """Create CloudWatch Logs metric filter."""
    if ctx.dry_run:
        log(f"Would create metric filter: {METRIC_FILTER_NAME}", dry_run=True)
        return

    filter_pattern = '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") || ($.errorCode = "*AccessDenied*") }'

    ctx.logs.put_metric_filter(
        logGroupName=ctx.log_group_name,
        filterName=METRIC_FILTER_NAME,
        filterPattern=filter_pattern,
        metricTransformations=[
            {
                "metricName": "UnauthorizedAPICalls",
                "metricNamespace": "CloudTrailMetrics",
                "metricValue": "1",
                "defaultValue": 0,
            }
        ],
    )
    log(f"Metric filter: {METRIC_FILTER_NAME}")


def create_alarm(ctx: DeploymentContext):
    """Create CloudWatch alarm."""
    if ctx.dry_run:
        log(f"Would create alarm: {ALARM_NAME}", dry_run=True)
        return

    ctx.cloudwatch.put_metric_alarm(
        AlarmName=ALARM_NAME,
        AlarmDescription="Alarm for unauthorized API calls",
        MetricName="UnauthorizedAPICalls",
        Namespace="CloudTrailMetrics",
        Statistic="Sum",
        Period=300,
        EvaluationPeriods=1,
        Threshold=1,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        TreatMissingData="notBreaching",
        AlarmActions=[ctx.alarm_topic_arn],
    )
    log(f"Alarm: {ALARM_NAME}")


def delete_alarm(ctx: DeploymentContext):
    """Delete CloudWatch alarm."""
    try:
        ctx.cloudwatch.delete_alarms(AlarmNames=[ALARM_NAME])
        log(f"Deleted alarm: {ALARM_NAME}")
    except ClientError as err:
        if "ResourceNotFound" in str(err):
            log(f"Alarm not found: {ALARM_NAME}")
        else:
            log(f"Failed to delete alarm {ALARM_NAME}: {err}")


def delete_metric_filter(ctx: DeploymentContext):
    """Delete metric filter."""
    if not ctx.log_group_name:
        try:
            get_cloudtrail_log_group(ctx)
        except RuntimeError:
            log("CloudTrail log group not found, skipping metric filter deletion")
            return

    try:
        ctx.logs.delete_metric_filter(logGroupName=ctx.log_group_name, filterName=METRIC_FILTER_NAME)
        log(f"Deleted metric filter: {METRIC_FILTER_NAME}")
    except ClientError as err:
        if "ResourceNotFoundException" in str(err):
            log(f"Metric filter not found: {METRIC_FILTER_NAME}")
        else:
            log(f"Failed to delete metric filter {METRIC_FILTER_NAME}: {err}")


def delete_lambda(ctx: DeploymentContext):
    """Delete Lambda function."""
    try:
        ctx.lambda_client.delete_function(FunctionName=LAMBDA_FUNCTION_NAME)
        log(f"Deleted Lambda: {LAMBDA_FUNCTION_NAME}")
    except ClientError as err:
        if "ResourceNotFoundException" in str(err):
            log(f"Lambda not found: {LAMBDA_FUNCTION_NAME}")
        else:
            log(f"Failed to delete Lambda {LAMBDA_FUNCTION_NAME}: {err}")


def delete_lambda_role(ctx: DeploymentContext):
    """Delete IAM role."""
    try:
        # Detach managed policies
        ctx.iam.detach_role_policy(
            RoleName=LAMBDA_ROLE_NAME,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
        log(f"Detached managed policy from {LAMBDA_ROLE_NAME}")
    except ClientError as err:
        if "NoSuchEntity" not in str(err):
            log(f"Failed to detach managed policy: {err}")

    try:
        # Delete inline policies
        ctx.iam.delete_role_policy(RoleName=LAMBDA_ROLE_NAME, PolicyName="FilterLogEventsAndSNS")
        log(f"Deleted inline policy from {LAMBDA_ROLE_NAME}")
    except ClientError as err:
        if "NoSuchEntity" not in str(err):
            log(f"Failed to delete inline policy: {err}")

    try:
        ctx.iam.delete_role(RoleName=LAMBDA_ROLE_NAME)
        log(f"Deleted IAM role: {LAMBDA_ROLE_NAME}")
    except ClientError as err:
        if "NoSuchEntity" in str(err):
            log(f"IAM role not found: {LAMBDA_ROLE_NAME}")
        else:
            log(f"Failed to delete IAM role {LAMBDA_ROLE_NAME}: {err}")


def delete_sns_topics(ctx: DeploymentContext):
    """Delete both SNS topics (alarm and report are separate)."""
    for name in [ALARM_TOPIC_NAME, REPORT_TOPIC_NAME]:
        topic_arn = f"arn:aws:sns:{ctx.region}:{ctx.get_account_id()}:{name}"
        try:
            ctx.sns.delete_topic(TopicArn=topic_arn)
            log(f"Deleted SNS topic: {name}")
        except ClientError as err:
            if "NotFound" in str(err):
                log(f"SNS topic not found: {name}")
            else:
                log(f"Failed to delete SNS topic {name}: {err}")


def get_cloudtrail_log_group(ctx: DeploymentContext):
    """Get CloudTrail log group or fail."""
    response = ctx.cloudtrail.describe_trails()
    for trail in response.get("trailList", []):
        arn = trail.get("CloudWatchLogsLogGroupArn", "")
        if arn:
            # ARN format: arn:aws:logs:region:account:log-group:name:*
            # Log group name may contain colons, so join everything after index 6
            parts = arn.split(":")
            if len(parts) >= 7:
                ctx.log_group_arn = arn
                # Join parts 6+ and strip trailing :* suffix
                log_group_name = ":".join(parts[6:])
                if log_group_name.endswith(":*"):
                    log_group_name = log_group_name[:-2]
                ctx.log_group_name = log_group_name
                return
    raise RuntimeError("CloudTrail with CloudWatch Logs not configured")


def deploy(ctx: DeploymentContext, email: str):
    """Deploy all resources with rollback on failure."""
    get_cloudtrail_log_group(ctx)
    log(f"Region: {ctx.region}, Account: {ctx.get_account_id()}")
    log(f"Log group: {ctx.log_group_name}")

    try:
        create_sns_topics(ctx, email)
        ctx.role_arn = create_lambda_role(ctx)
        create_lambda(ctx)
        create_metric_filter(ctx)
        create_alarm(ctx)
    except (ClientError, RuntimeError) as err:
        log(f"Deployment failed: {err}")
        log("Rolling back created resources...")
        delete(ctx)
        raise RuntimeError(f"Deployment failed and rolled back: {err}") from err

    log("Deployment complete")
    log("Confirm the SNS email subscription to receive alerts")


def remove_email_subscription(ctx: DeploymentContext, email: str):
    """Remove an email subscription from the report topic."""
    if ctx.dry_run:
        log(f"Would remove email subscription: {email}", dry_run=True)
        return

    report_topic_arn = f"arn:aws:sns:{ctx.region}:{ctx.get_account_id()}:{REPORT_TOPIC_NAME}"

    try:
        paginator = ctx.sns.get_paginator("list_subscriptions_by_topic")
        for page in paginator.paginate(TopicArn=report_topic_arn):
            for sub in page.get("Subscriptions", []):
                if sub.get("Protocol") == "email" and sub.get("Endpoint") == email:
                    sub_arn = sub.get("SubscriptionArn", "")
                    if sub_arn and sub_arn != "PendingConfirmation":
                        ctx.sns.unsubscribe(SubscriptionArn=sub_arn)
                        log(f"Removed email subscription: {email}")
                        return
                    elif sub_arn == "PendingConfirmation":
                        log(f"Subscription pending confirmation, cannot remove: {email}")
                        return
        log(f"Email subscription not found: {email}")
    except ClientError as err:
        if "NotFound" in str(err):
            log(f"Report topic not found: {REPORT_TOPIC_NAME}")
        else:
            raise RuntimeError(f"Failed to remove subscription: {err}") from err


def delete(ctx: DeploymentContext):
    """Delete all resources."""
    if ctx.dry_run:
        log("Would delete all resources", dry_run=True)
        return

    delete_alarm(ctx)
    delete_metric_filter(ctx)
    delete_lambda(ctx)
    delete_lambda_role(ctx)
    delete_sns_topics(ctx)
    log("Deletion complete")


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Deploy unauthorized API call alerting")
    parser.add_argument("--email", help="Email for alerts (required for deploy)")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes")
    parser.add_argument("--delete", action="store_true", help="Delete all resources")
    parser.add_argument("--remove-email", metavar="EMAIL", help="Remove an email subscription")

    args = parser.parse_args()

    # Validate arguments
    if args.remove_email and args.delete:
        parser.error("--remove-email and --delete cannot be used together")
    if not args.delete and not args.remove_email and not args.dry_run and not args.email:
        parser.error("--email is required for deployment")

    try:
        ctx = DeploymentContext(region=args.region, dry_run=args.dry_run)
        if args.delete:
            delete(ctx)
        elif args.remove_email:
            remove_email_subscription(ctx, args.remove_email)
        else:
            deploy(ctx, args.email or "")
    except RuntimeError as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(1)


if __name__ == "__main__":
    main()
