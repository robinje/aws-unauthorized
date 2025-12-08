"""
Deployment script for unauthorized API call alerting.

Discovers existing infrastructure and creates only missing components.
Sets up CloudTrail, subscription filter, Lambda enricher, and SNS alerting.

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
TRAIL_NAME = "unauth-api-trail"
LOG_GROUP_NAME = "/aws/cloudtrail/unauth-api-trail"
SUBSCRIPTION_FILTER_NAME = "unauth-api-filter"
SNS_TOPIC_NAME = "unauth-api-alerts"
LAMBDA_NAME = "ops-cloudtrail-unauthorized"
LAMBDA_ROLE_NAME = "ops-cloudtrail-unauthorized-role"
CLOUDTRAIL_ROLE_NAME = "unauth-api-cloudtrail-role"
BUCKET_PREFIX = "unauth-api-cloudtrail"

# Subscription filter pattern for unauthorized API calls
FILTER_PATTERN = '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }'


class DeploymentContext:
    """Holds deployment state and boto3 clients."""

    def __init__(self, region: str, dry_run: bool = False):
        self.region = region
        self.dry_run = dry_run
        self.account_id = ""

        # Boto3 clients
        self.sts = boto3.client("sts", region_name=region)
        self.cloudtrail = boto3.client("cloudtrail", region_name=region)
        self.logs = boto3.client("logs", region_name=region)
        self.sns = boto3.client("sns", region_name=region)
        self.lambda_client = boto3.client("lambda", region_name=region)
        self.iam = boto3.client("iam", region_name=region)
        self.s3 = boto3.client("s3", region_name=region)

        # Discovered/created resources
        self.log_group_name = ""
        self.log_group_arn = ""
        self.sns_topic_arn = ""
        self.lambda_arn = ""
        self.lambda_role_arn = ""

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


# =============================================================================
# Discovery Functions
# =============================================================================


def find_cloudtrail_with_logs(ctx: DeploymentContext) -> dict:
    """Find a CloudTrail trail with CloudWatch Logs integration.

    Returns:
        dict with trail info, or empty dict if none found.
    """
    try:
        response = ctx.cloudtrail.describe_trails()
        trails = response.get("trailList", [])

        for trail in trails:
            if trail.get("CloudWatchLogsLogGroupArn"):
                log(f"Found CloudTrail with logs: {trail.get('Name')}")
                return trail

        return {}
    except ClientError as err:
        log(f"Error checking CloudTrail: {err}")
        return {}


def find_log_group(ctx: DeploymentContext, name: str) -> dict:
    """Check if a log group exists.

    Returns:
        dict with log group info, or empty dict if not found.
    """
    try:
        response = ctx.logs.describe_log_groups(logGroupNamePrefix=name)
        for group in response.get("logGroups", []):
            if group.get("logGroupName") == name:
                log(f"Found log group: {name}")
                return group
        return {}
    except ClientError as err:
        log(f"Error checking log group: {err}")
        return {}


def find_subscription_filter(ctx: DeploymentContext, log_group: str) -> dict:
    """Find existing subscription filter on log group.

    Returns:
        dict with filter info, or empty dict if not found.
    """
    try:
        response = ctx.logs.describe_subscription_filters(logGroupName=log_group)
        filters = response.get("subscriptionFilters", [])

        for f in filters:
            if f.get("filterName") == SUBSCRIPTION_FILTER_NAME:
                log(f"Found subscription filter: {SUBSCRIPTION_FILTER_NAME}")
                return f

        return {}
    except ClientError as err:
        log(f"Error checking subscription filters: {err}")
        return {}


def find_sns_topic(ctx: DeploymentContext, name: str) -> dict:
    """Find SNS topic by name.

    Returns:
        dict with topic ARN, or empty dict if not found.
    """
    try:
        account_id = ctx.get_account_id()
        topic_arn = f"arn:aws:sns:{ctx.region}:{account_id}:{name}"

        ctx.sns.get_topic_attributes(TopicArn=topic_arn)
        log(f"Found SNS topic: {name}")
        return {"TopicArn": topic_arn}
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") == "NotFound":
            return {}
        log(f"Error checking SNS topic: {err}")
        return {}


def find_lambda(ctx: DeploymentContext, name: str) -> dict:
    """Check if Lambda function exists.

    Returns:
        dict with function info, or empty dict if not found.
    """
    try:
        response = ctx.lambda_client.get_function(FunctionName=name)
        log(f"Found Lambda function: {name}")
        return response.get("Configuration", {})
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return {}
        log(f"Error checking Lambda: {err}")
        return {}


def find_iam_role(ctx: DeploymentContext, name: str) -> dict:
    """Check if IAM role exists.

    Returns:
        dict with role info, or empty dict if not found.
    """
    try:
        response = ctx.iam.get_role(RoleName=name)
        log(f"Found IAM role: {name}")
        return response.get("Role", {})
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return {}
        log(f"Error checking IAM role: {err}")
        return {}


# =============================================================================
# Creation Functions
# =============================================================================


def create_cloudtrail_bucket(ctx: DeploymentContext) -> str:
    """Create S3 bucket for CloudTrail logs.

    Returns:
        Bucket name.
    """
    account_id = ctx.get_account_id()
    bucket_name = f"{BUCKET_PREFIX}-{account_id}-{ctx.region}"

    if ctx.dry_run:
        log(f"Would create S3 bucket: {bucket_name}", dry_run=True)
        return bucket_name

    try:
        # Check if bucket exists
        try:
            ctx.s3.head_bucket(Bucket=bucket_name)
            log(f"S3 bucket exists: {bucket_name}")
            return bucket_name
        except ClientError:
            pass

        # Create bucket
        if ctx.region == "us-east-1":
            ctx.s3.create_bucket(Bucket=bucket_name)
        else:
            ctx.s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": ctx.region},
            )
        log(f"Created S3 bucket: {bucket_name}")

        # Block public access
        ctx.s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

        # Set bucket policy for CloudTrail
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailAclCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": f"arn:aws:s3:::{bucket_name}",
                },
                {
                    "Sid": "AWSCloudTrailWrite",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*",
                    "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
                },
            ],
        }
        ctx.s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))

        return bucket_name

    except ClientError as err:
        raise RuntimeError(f"Failed to create S3 bucket: {err}") from err


def create_log_group(ctx: DeploymentContext, name: str) -> str:
    """Create CloudWatch Log Group.

    Returns:
        Log group ARN.
    """
    if ctx.dry_run:
        log(f"Would create log group: {name}", dry_run=True)
        account_id = ctx.get_account_id()
        return f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{name}:*"

    try:
        ctx.logs.create_log_group(logGroupName=name)
        log(f"Created log group: {name}")
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") != "ResourceAlreadyExistsException":
            raise RuntimeError(f"Failed to create log group: {err}") from err
        log(f"Log group exists: {name}")

    # Get ARN
    response = ctx.logs.describe_log_groups(logGroupNamePrefix=name)
    for group in response.get("logGroups", []):
        if group.get("logGroupName") == name:
            return group.get("arn", "")

    return ""


def create_cloudtrail_logs_role(ctx: DeploymentContext) -> str:
    """Create IAM role for CloudTrail to write to CloudWatch Logs.

    Returns:
        Role ARN.
    """
    if ctx.dry_run:
        log(f"Would create IAM role: {CLOUDTRAIL_ROLE_NAME}", dry_run=True)
        account_id = ctx.get_account_id()
        return f"arn:aws:iam::{account_id}:role/{CLOUDTRAIL_ROLE_NAME}"

    # Check if role exists
    existing = find_iam_role(ctx, CLOUDTRAIL_ROLE_NAME)
    if existing:
        return existing.get("Arn", "")

    try:
        # Trust policy
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }

        response = ctx.iam.create_role(
            RoleName=CLOUDTRAIL_ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Allows CloudTrail to write to CloudWatch Logs",
        )
        role_arn = response.get("Role", {}).get("Arn", "")
        log(f"Created IAM role: {CLOUDTRAIL_ROLE_NAME}")

        # Inline policy for CloudWatch Logs
        logs_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": f"arn:aws:logs:{ctx.region}:{ctx.get_account_id()}:log-group:{LOG_GROUP_NAME}:*",
                }
            ],
        }

        ctx.iam.put_role_policy(
            RoleName=CLOUDTRAIL_ROLE_NAME,
            PolicyName="CloudWatchLogsAccess",
            PolicyDocument=json.dumps(logs_policy),
        )

        # Wait for role to propagate
        time.sleep(10)

        return role_arn

    except ClientError as err:
        raise RuntimeError(f"Failed to create CloudTrail role: {err}") from err


def create_cloudtrail(ctx: DeploymentContext, bucket: str, log_group_arn: str, role_arn: str):
    """Create CloudTrail trail with CloudWatch Logs integration."""
    if ctx.dry_run:
        log(f"Would create CloudTrail: {TRAIL_NAME}", dry_run=True)
        return

    try:
        ctx.cloudtrail.create_trail(
            Name=TRAIL_NAME,
            S3BucketName=bucket,
            IsMultiRegionTrail=True,
            EnableLogFileValidation=True,
            CloudWatchLogsLogGroupArn=log_group_arn,
            CloudWatchLogsRoleArn=role_arn,
        )
        log(f"Created CloudTrail: {TRAIL_NAME}")

        ctx.cloudtrail.start_logging(Name=TRAIL_NAME)
        log(f"Started logging for: {TRAIL_NAME}")

    except ClientError as err:
        if err.response.get("Error", {}).get("Code") == "TrailAlreadyExistsException":
            log(f"CloudTrail exists: {TRAIL_NAME}")
            return
        raise RuntimeError(f"Failed to create CloudTrail: {err}") from err


def create_sns_topic(ctx: DeploymentContext, name: str) -> str:
    """Create SNS topic.

    Returns:
        Topic ARN.
    """
    if ctx.dry_run:
        log(f"Would create SNS topic: {name}", dry_run=True)
        account_id = ctx.get_account_id()
        return f"arn:aws:sns:{ctx.region}:{account_id}:{name}"

    try:
        response = ctx.sns.create_topic(Name=name)
        topic_arn = response.get("TopicArn", "")
        log(f"Created SNS topic: {name}")
        return topic_arn
    except ClientError as err:
        raise RuntimeError(f"Failed to create SNS topic: {err}") from err


def create_lambda_role(ctx: DeploymentContext) -> str:
    """Create IAM role for Lambda function.

    Returns:
        Role ARN.
    """
    if ctx.dry_run:
        log(f"Would create IAM role: {LAMBDA_ROLE_NAME}", dry_run=True)
        account_id = ctx.get_account_id()
        return f"arn:aws:iam::{account_id}:role/{LAMBDA_ROLE_NAME}"

    # Check if role exists
    existing = find_iam_role(ctx, LAMBDA_ROLE_NAME)
    if existing:
        return existing.get("Arn", "")

    try:
        # Trust policy
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

        response = ctx.iam.create_role(
            RoleName=LAMBDA_ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description="Role for unauthorized API call enrichment Lambda",
        )
        role_arn = response.get("Role", {}).get("Arn", "")
        log(f"Created IAM role: {LAMBDA_ROLE_NAME}")

        # Attach basic execution policy
        ctx.iam.attach_role_policy(
            RoleName=LAMBDA_ROLE_NAME,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )

        # Inline policy for Logs Insights and SNS
        inline_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["logs:StartQuery", "logs:GetQueryResults"],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": "sns:Publish",
                    "Resource": f"arn:aws:sns:{ctx.region}:{ctx.get_account_id()}:{SNS_TOPIC_NAME}",
                },
            ],
        }

        ctx.iam.put_role_policy(
            RoleName=LAMBDA_ROLE_NAME,
            PolicyName="LogsInsightsAndSNS",
            PolicyDocument=json.dumps(inline_policy),
        )

        # Wait for role to propagate
        time.sleep(10)

        return role_arn

    except ClientError as err:
        raise RuntimeError(f"Failed to create Lambda role: {err}") from err


def create_lambda_zip() -> bytes:
    """Create in-memory zip from lambda directory.

    Returns:
        Zip file contents as bytes.
    """
    zip_buffer = io.BytesIO()
    lambda_file = Path(__file__).parent / "lambda" / "ops_cloudtrail_unauthorized.py"

    if not lambda_file.exists():
        raise RuntimeError(f"Lambda file not found: {lambda_file}")

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(lambda_file, "ops_cloudtrail_unauthorized.py")

    zip_buffer.seek(0)
    return zip_buffer.read()


def create_lambda(ctx: DeploymentContext, role_arn: str) -> str:
    """Create or update Lambda function.

    Returns:
        Function ARN.
    """
    zip_bytes = create_lambda_zip()

    if ctx.dry_run:
        log(f"Would create/update Lambda: {LAMBDA_NAME}", dry_run=True)
        account_id = ctx.get_account_id()
        return f"arn:aws:lambda:{ctx.region}:{account_id}:function:{LAMBDA_NAME}"

    # Check if function exists
    existing = find_lambda(ctx, LAMBDA_NAME)

    env_vars = {
        "LOG_LEVEL": "INFO",
        "LOG_GROUP_NAME": ctx.log_group_name,
        "ENRICHED_TOPIC_ARN": ctx.sns_topic_arn,
        "QUERY_WINDOW_MINUTES": "10",
        "AWS_ACCOUNT_ID": ctx.get_account_id(),
    }

    try:
        if existing:
            # Update code
            ctx.lambda_client.update_function_code(
                FunctionName=LAMBDA_NAME,
                ZipFile=zip_bytes,
            )
            log(f"Updated Lambda code: {LAMBDA_NAME}")

            # Wait for update to complete
            time.sleep(5)

            # Update configuration
            ctx.lambda_client.update_function_configuration(
                FunctionName=LAMBDA_NAME,
                Environment={"Variables": env_vars},
            )
            log(f"Updated Lambda configuration: {LAMBDA_NAME}")

            function_arn = existing.get("FunctionArn", "")
        else:
            # Create function
            response = ctx.lambda_client.create_function(
                FunctionName=LAMBDA_NAME,
                Runtime="python3.12",
                Role=role_arn,
                Handler="ops_cloudtrail_unauthorized.lambda_handler",
                Code={"ZipFile": zip_bytes},
                Description="Enriches unauthorized API call alerts",
                Timeout=60,
                MemorySize=256,
                Environment={"Variables": env_vars},
            )
            function_arn = response.get("FunctionArn", "")
            log(f"Created Lambda: {LAMBDA_NAME}")

            # Wait for function to be active
            time.sleep(5)

        # Set reserved concurrency to 1
        ctx.lambda_client.put_function_concurrency(
            FunctionName=LAMBDA_NAME,
            ReservedConcurrentExecutions=1,
        )
        log(f"Set reserved concurrency to 1: {LAMBDA_NAME}")

        return function_arn

    except ClientError as err:
        raise RuntimeError(f"Failed to create/update Lambda: {err}") from err


def add_lambda_invoke_permission(ctx: DeploymentContext, lambda_arn: str, log_group_arn: str):
    """Add permission for CloudWatch Logs to invoke Lambda."""
    if ctx.dry_run:
        log("Would add Lambda invoke permission for CloudWatch Logs", dry_run=True)
        return

    try:
        ctx.lambda_client.add_permission(
            FunctionName=LAMBDA_NAME,
            StatementId="CloudWatchLogsInvoke",
            Action="lambda:InvokeFunction",
            Principal="logs.amazonaws.com",
            SourceArn=log_group_arn,
        )
        log("Added Lambda invoke permission for CloudWatch Logs")
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") == "ResourceConflictException":
            log("Lambda invoke permission already exists")
            return
        raise RuntimeError(f"Failed to add Lambda permission: {err}") from err


def create_subscription_filter(ctx: DeploymentContext, log_group: str, lambda_arn: str):
    """Create subscription filter to trigger Lambda."""
    if ctx.dry_run:
        log(f"Would create subscription filter: {SUBSCRIPTION_FILTER_NAME}", dry_run=True)
        return

    try:
        ctx.logs.put_subscription_filter(
            logGroupName=log_group,
            filterName=SUBSCRIPTION_FILTER_NAME,
            filterPattern=FILTER_PATTERN,
            destinationArn=lambda_arn,
        )
        log(f"Created subscription filter: {SUBSCRIPTION_FILTER_NAME}")
    except ClientError as err:
        raise RuntimeError(f"Failed to create subscription filter: {err}") from err


def subscribe_email(ctx: DeploymentContext, topic_arn: str, email: str):
    """Subscribe email to SNS topic."""
    if ctx.dry_run:
        log(f"Would subscribe {email} to SNS topic", dry_run=True)
        return

    try:
        # Check for existing subscription
        response = ctx.sns.list_subscriptions_by_topic(TopicArn=topic_arn)
        for sub in response.get("Subscriptions", []):
            if sub.get("Protocol") == "email" and sub.get("Endpoint") == email:
                log(f"Email already subscribed: {email}")
                return

        ctx.sns.subscribe(
            TopicArn=topic_arn,
            Protocol="email",
            Endpoint=email,
        )
        log(f"Subscribed {email} to SNS topic (confirmation required)")
    except ClientError as err:
        raise RuntimeError(f"Failed to subscribe email: {err}") from err


# =============================================================================
# Orchestration
# =============================================================================


def deploy(ctx: DeploymentContext, email: str):
    """Main deployment orchestration."""
    log("=" * 60)
    log("Unauthorized API Call Alerting - Deployment")
    log("=" * 60)
    log(f"Region: {ctx.region}")
    log(f"Account: {ctx.get_account_id()}")
    log(f"Dry run: {ctx.dry_run}")
    log("")

    # Step 1: Check for existing CloudTrail with logs
    log("Step 1: Checking CloudTrail...")
    trail = find_cloudtrail_with_logs(ctx)

    if trail:
        ctx.log_group_arn = trail.get("CloudWatchLogsLogGroupArn", "")
        # Extract log group name from ARN
        # Format: arn:aws:logs:region:account:log-group:name:*
        arn_parts = ctx.log_group_arn.split(":")
        if len(arn_parts) >= 7:
            ctx.log_group_name = arn_parts[6]
        log(f"Using existing log group: {ctx.log_group_name}")
    else:
        log("No CloudTrail with CloudWatch Logs found, will create...")
        ctx.log_group_name = LOG_GROUP_NAME

        # Create log group
        ctx.log_group_arn = create_log_group(ctx, LOG_GROUP_NAME)

        # Create CloudTrail role
        cloudtrail_role_arn = create_cloudtrail_logs_role(ctx)

        # Create S3 bucket
        bucket = create_cloudtrail_bucket(ctx)

        # Create CloudTrail
        create_cloudtrail(ctx, bucket, ctx.log_group_arn, cloudtrail_role_arn)

    log("")

    # Step 2: Create SNS topic
    log("Step 2: Setting up SNS topic...")
    existing_topic = find_sns_topic(ctx, SNS_TOPIC_NAME)
    if existing_topic:
        ctx.sns_topic_arn = existing_topic.get("TopicArn", "")
    else:
        ctx.sns_topic_arn = create_sns_topic(ctx, SNS_TOPIC_NAME)
    log("")

    # Step 3: Create Lambda role and function
    log("Step 3: Setting up Lambda function...")
    ctx.lambda_role_arn = create_lambda_role(ctx)
    ctx.lambda_arn = create_lambda(ctx, ctx.lambda_role_arn)
    log("")

    # Step 4: Add Lambda invoke permission
    log("Step 4: Configuring Lambda permissions...")
    add_lambda_invoke_permission(ctx, ctx.lambda_arn, ctx.log_group_arn)
    log("")

    # Step 5: Create subscription filter
    log("Step 5: Setting up subscription filter...")
    existing_filter = find_subscription_filter(ctx, ctx.log_group_name)
    if not existing_filter:
        create_subscription_filter(ctx, ctx.log_group_name, ctx.lambda_arn)
    log("")

    # Step 6: Subscribe email
    log("Step 6: Setting up email subscription...")
    if email:
        subscribe_email(ctx, ctx.sns_topic_arn, email)
    else:
        log("No email provided, skipping subscription")
    log("")

    # Done
    log("=" * 60)
    log("Deployment complete!")
    log("")
    log("Next steps:")
    log("1. Check your email and confirm the SNS subscription")
    log("2. Test by triggering an AccessDenied error:")
    log("   aws sts assume-role \\")
    log(f"     --role-arn arn:aws:iam::{ctx.get_account_id()}:role/nonexistent \\")
    log("     --role-session-name test 2>/dev/null || true")
    log("")
    log("3. Check Lambda logs:")
    log(f"   aws logs tail /aws/lambda/{LAMBDA_NAME} --since 10m --follow")
    log("=" * 60)


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Deploy unauthorized API call alerting")
    parser.add_argument(
        "--email",
        help="Email address for enriched alerts (required unless --dry-run)",
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region (default: us-east-1)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be created without making changes",
    )

    args = parser.parse_args()

    if not args.dry_run and not args.email:
        parser.error("--email is required unless using --dry-run")

    try:
        ctx = DeploymentContext(region=args.region, dry_run=args.dry_run)
        deploy(ctx, args.email)
    except RuntimeError as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(1)


if __name__ == "__main__":
    main()
