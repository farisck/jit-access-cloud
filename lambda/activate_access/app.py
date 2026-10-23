"""
activate_access

Invoked by EventBridge Scheduler at the requested access start time.

Statuses only move forward:
  scheduled  -> activating -> active
  scheduled  -> expired            (the window was already over)
  activating -> expired            (the window ended before any grant)
  activating -> cleanup_pending    (written by revoke_access; this function
                                    then removes the policy it attached)

The permission comes exclusively from the fixed PERMISSION_CATALOG.  Every
granted statement also carries an aws:CurrentTime limit, so a policy that
lands late can never authorize requests after the approved end time.
"""

import copy
import json
import math
import os
import time

import boto3
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb")
iam = boto3.client("iam")
sns = boto3.client("sns")

TABLE_NAME = os.environ["REQUESTS_TABLE_NAME"]
TOPIC_ARN = os.environ["NOTIFICATIONS_TOPIC_ARN"]
TARGET_ROLE_NAME = os.environ["TARGET_ROLE_NAME"]
PERMISSION_CATALOG = json.loads(os.environ["PERMISSION_CATALOG"])

# Only used when Lambda gives us no context object (unit tests).
DEFAULT_TIMEOUT_MS = 15000
# Extra time beyond this invocation's own timeout before an in-flight IAM
# call is treated as impossible.
ACTIVATION_SAFETY_MARGIN_SECONDS = 120

table = dynamodb.Table(TABLE_NAME)


def _policy_name(request_id):
    return f"jit-grant-{request_id}"


def _notify(request_id, actor, expires_epoch):
    try:
        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject=f"Access activated: {request_id}"[:100],
            Message=(
                f"requestId={request_id}\n"
                f"status=active\n"
                f"activatedBy={actor}\n"
                f"expiresAt={expires_epoch}"
            ),
        )
    except ClientError as exc:
        print(f"SNS publish failed (non-fatal): {exc}")


def _is_conditional_failure(exc):
    return (
        exc.response.get("Error", {}).get("Code")
        == "ConditionalCheckFailedException"
    )


def _get_current_status(request_id):
    response = table.get_item(
        Key={"requestId": request_id},
        ConsistentRead=True,
    )
    item = response.get("Item")
    return item.get("status") if item else "not_found"


def _delete_granted_policy(policy_name):
    try:
        iam.delete_role_policy(
            RoleName=TARGET_ROLE_NAME,
            PolicyName=policy_name,
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code != "NoSuchEntity":
            print(
                f"CRITICAL: failed to remove policy {policy_name}: {exc}"
            )
            raise


def _mark_expired_after_claim(request_id):
    """End an activation whose window closed before any policy was attached."""
    try:
        table.update_item(
            Key={"requestId": request_id},
            UpdateExpression="SET #s = :expired",
            ConditionExpression="#s = :activating",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":expired": "expired",
                ":activating": "activating",
            },
        )
    except ClientError as exc:
        if not _is_conditional_failure(exc):
            raise
    return _get_current_status(request_id)


def _activation_deadline(context, claim_epoch):
    """Latest moment this invocation could still be talking to IAM."""
    remaining_ms = (
        DEFAULT_TIMEOUT_MS
        if context is None
        else context.get_remaining_time_in_millis()
    )
    return (
        claim_epoch
        + math.ceil(remaining_ms / 1000)
        + ACTIVATION_SAFETY_MARGIN_SECONDS
    )


def _time_limited_statement(statement, end_epoch):
    """Copy a catalog statement and make it stop matching at end_epoch."""
    if not isinstance(statement, dict):
        raise ValueError("Catalog entry must be a policy statement object")

    limited = copy.deepcopy(statement)
    condition = limited.setdefault("Condition", {})
    if not isinstance(condition, dict):
        raise ValueError("Catalog Condition must be an object")

    date_less_than = condition.setdefault("DateLessThan", {})
    if (
        not isinstance(date_less_than, dict)
        or "aws:CurrentTime" in date_less_than
    ):
        raise ValueError(
            "Catalog entry already limits aws:CurrentTime; "
            "refusing to guess which limit wins"
        )

    date_less_than["aws:CurrentTime"] = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(end_epoch)
    )
    return limited


def _build_policy_document(statement, end_epoch):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [_time_limited_statement(statement, end_epoch)],
    })


def handler(event, context):
    request_id = event.get("requestId")
    if not request_id:
        raise ValueError(
            f"activate_access invoked without requestId: {event}"
        )

    response = table.get_item(
        Key={"requestId": request_id},
        ConsistentRead=True,
    )
    item = response.get("Item")

    if not item:
        print(f"Request {request_id} not found; activation skipped")
        return {"requestId": request_id, "status": "not_found"}

    if item.get("status") != "scheduled":
        print(
            f"Request {request_id} has status "
            f"{item.get('status')}; activation skipped"
        )
        return {
            "requestId": request_id,
            "status": item.get("status"),
        }

    try:
        start_epoch = int(item["accessStartAt"])
        end_epoch = int(item["accessEndAt"])
    except (KeyError, TypeError, ValueError):
        raise ValueError(
            f"Request {request_id} has an invalid access window"
        )

    now_epoch = int(time.time())

    if now_epoch < start_epoch:
        raise ValueError(
            f"Request {request_id} was invoked before its start time"
        )

    if now_epoch >= end_epoch:
        try:
            table.update_item(
                Key={"requestId": request_id},
                UpdateExpression="SET #s = :expired",
                ConditionExpression="#s = :scheduled",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":expired": "expired",
                    ":scheduled": "scheduled",
                },
            )
        except ClientError as exc:
            if _is_conditional_failure(exc):
                return {
                    "requestId": request_id,
                    "status": _get_current_status(request_id),
                }
            raise
        return {"requestId": request_id, "status": "expired"}

    permission_key = item.get("permission")
    policy_doc = PERMISSION_CATALOG.get(permission_key)
    if not policy_doc:
        raise ValueError(
            f"No policy template found for permission {permission_key}"
        )

    policy_name = item.get("policyName", _policy_name(request_id))

    # Build the policy before claiming, so a bad catalog entry can never
    # leave a request stuck in "activating".
    policy_document = _build_policy_document(policy_doc, end_epoch)

    claim_epoch = int(time.time())
    deadline_epoch = _activation_deadline(context, claim_epoch)

    try:
        table.update_item(
            Key={"requestId": request_id},
            UpdateExpression=(
                "SET #s = :activating, activationClaimedAt = :claimed, "
                "activationDeadline = :deadline"
            ),
            ConditionExpression="#s = :scheduled",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":activating": "activating",
                ":scheduled": "scheduled",
                ":claimed": str(claim_epoch),
                ":deadline": str(deadline_epoch),
            },
        )
    except ClientError as exc:
        if _is_conditional_failure(exc):
            return {
                "requestId": request_id,
                "status": _get_current_status(request_id),
            }
        raise

    # No policy has been attached yet, so ending here is safe.
    if int(time.time()) >= end_epoch:
        return {
            "requestId": request_id,
            "status": _mark_expired_after_claim(request_id),
        }

    iam.put_role_policy(
        RoleName=TARGET_ROLE_NAME,
        PolicyName=policy_name,
        PolicyDocument=policy_document,
    )

    # IAM is not transactional with DynamoDB.  The conditional write below
    # is the real guard: if revoke_access moved the request out of
    # "activating" while PutRolePolicy was in flight, this write fails and
    # we remove the policy we just attached.  A failed delete is raised on
    # purpose; the request is already cleanup_pending, so the reconciler
    # keeps retrying it.
    try:
        table.update_item(
            Key={"requestId": request_id},
            UpdateExpression="SET #s = :active, activatedAt = :at",
            ConditionExpression="#s = :activating",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":active": "active",
                ":activating": "activating",
                ":at": str(int(time.time())),
            },
        )
    except ClientError as exc:
        if not _is_conditional_failure(exc):
            raise
        _delete_granted_policy(policy_name)
        return {
            "requestId": request_id,
            "status": _get_current_status(request_id),
        }

    _notify(
        request_id,
        "eventbridge-scheduler",
        end_epoch,
    )

    return {
        "requestId": request_id,
        "status": "active",
        "expiresAt": end_epoch,
    }