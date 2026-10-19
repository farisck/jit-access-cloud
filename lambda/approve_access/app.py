
"""
approve_access

Approves or denies JIT access requests.

Immediate requests:
  - Grant the catalog permission now.
  - Schedule revocation at expiry.

Future-window requests:
  - Schedule activation at accessStartAt.
  - Schedule revocation at accessEndAt.
  - Do not grant IAM permission before the start time.
"""
import json
import os
import time

import boto3
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb")
iam = boto3.client("iam")
scheduler = boto3.client("scheduler")
sns = boto3.client("sns")

TABLE_NAME = os.environ["REQUESTS_TABLE_NAME"]
TOPIC_ARN = os.environ["NOTIFICATIONS_TOPIC_ARN"]
TARGET_ROLE_NAME = os.environ["TARGET_ROLE_NAME"]
REVOKE_FUNCTION_ARN = os.environ["REVOKE_FUNCTION_ARN"]
ACTIVATE_FUNCTION_ARN = os.environ["ACTIVATE_FUNCTION_ARN"]
SCHEDULER_ROLE_ARN = os.environ["SCHEDULER_ROLE_ARN"]
SCHEDULE_GROUP_NAME = os.environ["SCHEDULE_GROUP_NAME"]
PERMISSION_CATALOG = json.loads(os.environ["PERMISSION_CATALOG"])

table = dynamodb.Table(TABLE_NAME)


def _response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body),
    }


def _policy_name(request_id):
    return f"jit-grant-{request_id}"


def _parse_groups_claim(groups_raw):
    if isinstance(groups_raw, list):
        return groups_raw

    cleaned = str(groups_raw).strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]

    return [group.strip() for group in cleaned.split(",") if group.strip()]


def _schedule(name, timestamp, target_arn, request_id, reason=None):
    """Create a one-time UTC schedule."""
    timestamp = int(timestamp)
    expression_time = time.strftime(
        "%Y-%m-%dT%H:%M:%S",
        time.gmtime(timestamp),
    )

    payload = {"requestId": request_id}
    if reason:
        payload["reason"] = reason

    scheduler.create_schedule(
        Name=name,
        GroupName=SCHEDULE_GROUP_NAME,
        ScheduleExpression=f"at({expression_time})",
        FlexibleTimeWindow={"Mode": "OFF"},
        ActionAfterCompletion="DELETE",
        Target={
            "Arn": target_arn,
            "RoleArn": SCHEDULER_ROLE_ARN,
            "Input": json.dumps(payload),
        },
    )


def _delete_schedule(name):
    """Best-effort cleanup for a schedule created by this invocation."""
    try:
        scheduler.delete_schedule(
            Name=name,
            GroupName=SCHEDULE_GROUP_NAME,
        )
    except ClientError as exc:
        print(f"Could not clean up schedule {name}: {exc}")


def _notify(item, new_status, actor, expires_epoch=None):
    try:
        message = (
            f"requestId={item['requestId']}\n"
            f"status={new_status}\n"
            f"actedBy={actor}"
        )
        if expires_epoch is not None:
            message += f"\nexpiresAt={expires_epoch}"

        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject=f"Access request {new_status}: {item['requestId']}"[:100],
            Message=message,
        )
    except ClientError as exc:
        print(f"SNS publish failed (non-fatal): {exc}")


def handler(event, context):
    try:
        claims = event["requestContext"]["authorizer"]["jwt"]["claims"]
        approver_id = claims["sub"]
        approver_email = claims.get("email", "")
        groups = _parse_groups_claim(claims.get("cognito:groups", ""))
    except (KeyError, TypeError):
        return _response(401, {"message": "Missing or invalid authorization token"})

    if "approvers" not in groups:
        return _response(
            403,
            {"message": "Only members of the approvers group may approve or deny requests"},
        )

    request_id = (event.get("pathParameters") or {}).get("requestId")
    if not request_id:
        return _response(400, {"message": "requestId path parameter is required"})

    try:
        payload = json.loads(event.get("body") or "{}")
    except (json.JSONDecodeError, TypeError):
        return _response(400, {"message": "Request body must be valid JSON"})

    if not isinstance(payload, dict):
        return _response(400, {"message": "Request body must be a JSON object"})

    decision = payload.get("decision")
    if decision not in ("approve", "deny"):
        return _response(400, {"message": "'decision' must be 'approve' or 'deny'"})

    item_response = table.get_item(Key={"requestId": request_id})
    item = item_response.get("Item")

    if not item:
        return _response(404, {"message": "Request not found"})

    if item.get("status") != "pending":
        return _response(
            409,
            {"message": f"Request is not pending (current status: {item.get('status')})"},
        )

    now_epoch = int(time.time())
    actor = approver_email or approver_id

    if decision == "deny":
        table.update_item(
            Key={"requestId": request_id},
            UpdateExpression="SET #s = :status, decidedBy = :by, decidedAt = :at",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":status": "denied",
                ":by": actor,
                ":at": str(now_epoch),
            },
        )
        _notify(item, "denied", actor)
        return _response(200, {"requestId": request_id, "status": "denied"})

    permission_key = item.get("permission")
    policy_doc = PERMISSION_CATALOG.get(permission_key)
    if not policy_doc:
        return _response(
            500,
            {"message": f"No policy template found for permission '{permission_key}'"},
        )

    policy_name = _policy_name(request_id)
    has_start = item.get("accessStartAt") is not None
    has_end = item.get("accessEndAt") is not None

    # A future-window request must contain both boundaries.
    if has_start != has_end:
        return _response(
            400,
            {"message": "A scheduled access window requires both accessStartAt and accessEndAt"},
        )

    if has_start and has_end:
        try:
            start_epoch = int(item["accessStartAt"])
            end_epoch = int(item["accessEndAt"])
        except (TypeError, ValueError):
            return _response(400, {"message": "Access window timestamps are invalid"})

        if start_epoch <= now_epoch:
            return _response(409, {"message": "Access start time must be in the future"})

        if end_epoch <= start_epoch:
            return _response(400, {"message": "Access end time must be after its start time"})

        activate_name = f"jit-activate-{request_id}"
        revoke_name = f"jit-revoke-{request_id}"
        created_schedules = []

        try:
            _schedule(
                activate_name,
                start_epoch,
                ACTIVATE_FUNCTION_ARN,
                request_id,
            )
            created_schedules.append(activate_name)

            _schedule(
                revoke_name,
                end_epoch,
                REVOKE_FUNCTION_ARN,
                request_id,
                reason="scheduled_expiry",
            )
            created_schedules.append(revoke_name)

        except ClientError as exc:
            print(f"Could not create future-window schedules for {request_id}: {exc}")
            for schedule_name in reversed(created_schedules):
                _delete_schedule(schedule_name)

            return _response(
                500,
                {"message": "Could not schedule the access window; access was not granted"},
            )

        try:
            table.update_item(
                Key={"requestId": request_id},
                UpdateExpression=(
                    "SET #s = :status, decidedBy = :by, decidedAt = :at, "
                    "accessStartAt = :start, accessEndAt = :end, "
                    "expiresAt = :exp, scheduleName = :sched, "
                    "activationScheduleName = :activate, policyName = :pol"
                ),
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":status": "scheduled",
                    ":by": actor,
                    ":at": str(now_epoch),
                    ":start": str(start_epoch),
                    ":end": str(end_epoch),
                    ":exp": str(end_epoch),
                    ":sched": revoke_name,
                    ":activate": activate_name,
                    ":pol": policy_name,
                },
            )
        except ClientError as exc:
            print(f"Could not save scheduled request {request_id}: {exc}")
            for schedule_name in reversed(created_schedules):
                _delete_schedule(schedule_name)

            return _response(
                500,
                {"message": "Could not save the scheduled access request"},
            )

        _notify(item, "scheduled", actor, end_epoch)
        return _response(
            200,
            {
                "requestId": request_id,
                "status": "scheduled",
                "accessStartAt": start_epoch,
                "accessEndAt": end_epoch,
            },
        )

    # Legacy duration-based requests: grant now and schedule revocation.
    try:
        duration_minutes = int(item.get("durationMinutes", 60))
        if duration_minutes <= 0:
            raise ValueError("durationMinutes must be positive")
    except (TypeError, ValueError):
        return _response(400, {"message": "Request duration is invalid"})

    expires_epoch = now_epoch + duration_minutes * 60

    try:
        iam.put_role_policy(
            RoleName=TARGET_ROLE_NAME,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [policy_doc],
            }),
        )
    except ClientError as exc:
        print(f"put_role_policy failed for {request_id}: {exc}")
        return _response(500, {"message": "Could not grant the requested access"})

    schedule_name = f"jit-revoke-{request_id}"

    try:
        _schedule(
            schedule_name,
            expires_epoch,
            REVOKE_FUNCTION_ARN,
            request_id,
            reason="scheduled_expiry",
        )
    except ClientError as exc:
        print(f"create_schedule failed for {request_id}: {exc}; rolling back the grant")
        try:
            iam.delete_role_policy(
                RoleName=TARGET_ROLE_NAME,
                PolicyName=policy_name,
            )
        except ClientError as rollback_exc:
            print(f"Rollback delete_role_policy also failed: {rollback_exc}")

        return _response(
            500,
            {"message": "Could not schedule the automatic revocation; grant was not applied"},
        )

    try:
        table.update_item(
            Key={"requestId": request_id},
            UpdateExpression=(
                "SET #s = :status, decidedBy = :by, decidedAt = :at, "
                "expiresAt = :exp, scheduleName = :sched, policyName = :pol"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":status": "active",
                ":by": actor,
                ":at": str(now_epoch),
                ":exp": str(expires_epoch),
                ":sched": schedule_name,
                ":pol": policy_name,
            },
        )
    except ClientError as exc:
        print(f"Could not save active request {request_id}: {exc}")
        _delete_schedule(schedule_name)
        try:
            iam.delete_role_policy(
                RoleName=TARGET_ROLE_NAME,
                PolicyName=policy_name,
            )
        except ClientError as rollback_exc:
            print(f"Rollback delete_role_policy also failed: {rollback_exc}")

        return _response(500, {"message": "Could not save the approved access request"})

    _notify(item, "active", actor, expires_epoch)
    return _response(
        200,
        {
            "requestId": request_id,
            "status": "active",
            "expiresAt": expires_epoch,
        },
    )
