
"""
activate_access

Invoked by EventBridge Scheduler at the requested access start time.

Only requests still in the "scheduled" state can be activated.
The permission comes exclusively from the fixed PERMISSION_CATALOG.
"""

import json
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


def handler(event, context):
    request_id = event.get("requestId")
    if not request_id:
        raise ValueError(
            f"activate_access invoked without requestId: {event}"
        )

    response = table.get_item(Key={"requestId": request_id})
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
        table.update_item(
            Key={"requestId": request_id},
            UpdateExpression="SET #s = :status",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":status": "expired"},
        )
        return {"requestId": request_id, "status": "expired"}

    permission_key = item.get("permission")
    policy_doc = PERMISSION_CATALOG.get(permission_key)
    if not policy_doc:
        raise ValueError(
            f"No policy template found for permission {permission_key}"
        )

    policy_name = item.get("policyName", _policy_name(request_id))

    iam.put_role_policy(
        RoleName=TARGET_ROLE_NAME,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [policy_doc],
        }),
    )

    table.update_item(
        Key={"requestId": request_id},
        UpdateExpression=(
            "SET #s = :status, activatedAt = :at"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":status": "active",
            ":at": str(now_epoch),
        },
    )

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
