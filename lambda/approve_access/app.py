"""
approve_access

API Gateway-triggered (POST /requests/{requestId}/approve), behind the
Cognito JWT authorizer. The caller must be in the "approvers" Cognito
group - checked here, not assumed from network position.

Body: { "decision": "approve" }  or  { "decision": "deny" }

On approval:
  1. Look up the permission template for the request's requested
     "permission" key in PERMISSION_CATALOG (never arbitrary JSON - this
     is what keeps the whole system safe to run in a real AWS account for
     a demo: the set of grantable permissions is fixed and reviewed ahead
     of time, not whatever text a requester typed).
  2. Attach it as ONE inline policy on TARGET_ROLE_NAME, named after this
     request's id, so it can be found and removed unambiguously later.
  3. Schedule a ONE-TIME EventBridge Schedule that invokes revoke_access
     at the exact requested expiry - the revocation is scheduled in the
     same action as the grant, never a separate step someone could forget.
  4. Update DynamoDB to "active" with the expiry and scheduler name.

This function's IAM role can only PutRolePolicy on the one target role
(not any other role in the account), and can only create schedules under
this project's schedule group.
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
SCHEDULER_ROLE_ARN = os.environ["SCHEDULER_ROLE_ARN"]
SCHEDULE_GROUP_NAME = os.environ["SCHEDULE_GROUP_NAME"]

# The fixed, reviewed catalog of what can ever be granted. Keys here MUST
# match request_access's ALLOWED_PERMISSIONS (fed from the same source at
# deploy time via the CloudFormation template).
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
    """
    Cognito's ID token has cognito:groups as a real JSON array, e.g.
    ["approvers"]. But API Gateway's HTTP API JWT authorizer flattens all
    claims into a string-only map before handing them to Lambda, and for
    array claims it uses Java's array toString format - literal square
    brackets, comma-space separated, NOT JSON (e.g. "[approvers]" or
    "[approvers, admins]" for multiple groups, or "[]" for none). A naive
    comma-split leaves the brackets attached to the token's first/last
    entry, so "approvers" never matches "[approvers]" and every approver
    gets incorrectly denied. This strips the brackets before splitting.
    """
    if isinstance(groups_raw, list):
        return groups_raw
    cleaned = str(groups_raw).strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]
    return [g.strip() for g in cleaned.split(",") if g.strip()]


def handler(event, context):
    try:
        claims = event["requestContext"]["authorizer"]["jwt"]["claims"]
        approver_id = claims["sub"]
        approver_email = claims.get("email", "")
        groups_raw = claims.get("cognito:groups", "")
        groups = _parse_groups_claim(groups_raw)
    except (KeyError, TypeError):
        return _response(401, {"message": "Missing or invalid authorization token"})

    if "approvers" not in groups:
        return _response(403, {"message": "Only members of the approvers group may approve or deny requests"})

    request_id = (event.get("pathParameters") or {}).get("requestId")
    if not request_id:
        return _response(400, {"message": "requestId path parameter is required"})

    try:
        payload = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _response(400, {"message": "Request body must be valid JSON"})

    decision = payload.get("decision")
    if decision not in ("approve", "deny"):
        return _response(400, {"message": "'decision' must be 'approve' or 'deny'"})

    item_resp = table.get_item(Key={"requestId": request_id})
    item = item_resp.get("Item")
    if not item:
        return _response(404, {"message": "Request not found"})
    if item.get("status") != "pending":
        return _response(409, {"message": f"Request is not pending (current status: {item.get('status')})"})

    now_epoch = int(time.time())

    if decision == "deny":
        table.update_item(
            Key={"requestId": request_id},
            UpdateExpression="SET #s = :status, decidedBy = :by, decidedAt = :at",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":status": "denied", ":by": approver_email or approver_id, ":at": str(now_epoch)},
        )
        _notify(item, "denied", approver_email or approver_id)
        return _response(200, {"requestId": request_id, "status": "denied"})

    # --- approve ---
    permission_key = item.get("permission")
    policy_doc = PERMISSION_CATALOG.get(permission_key)
    if not policy_doc:
        return _response(500, {"message": f"No policy template found for permission '{permission_key}'"})

    policy_name = _policy_name(request_id)
    duration_minutes = int(item.get("durationMinutes", 60))
    expires_epoch = now_epoch + duration_minutes * 60

    try:
        iam.put_role_policy(
            RoleName=TARGET_ROLE_NAME,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [policy_doc]}),
        )
    except ClientError as exc:
        print(f"put_role_policy failed for {request_id}: {exc}")
        return _response(500, {"message": "Could not grant the requested access"})

    # Schedule the revocation in the same action as the grant - EventBridge
    # Scheduler's "at()" expression takes an ISO-8601 timestamp with no
    # timezone offset (it's evaluated in the schedule's own timezone,
    # UTC by default here).
    expires_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(expires_epoch))
    schedule_name = f"jit-revoke-{request_id}"

    try:
        scheduler.create_schedule(
            Name=schedule_name,
            GroupName=SCHEDULE_GROUP_NAME,
            ScheduleExpression=f"at({expires_iso})",
            FlexibleTimeWindow={"Mode": "OFF"},
            ActionAfterCompletion="DELETE",
            Target={
                "Arn": REVOKE_FUNCTION_ARN,
                "RoleArn": SCHEDULER_ROLE_ARN,
                "Input": json.dumps({"requestId": request_id, "reason": "scheduled_expiry"}),
            },
        )
    except ClientError as exc:
        # Roll back the grant rather than leave standing access with no
        # revocation scheduled - that failure mode is exactly what this
        # project exists to prevent.
        print(f"create_schedule failed for {request_id}: {exc}; rolling back the grant")
        try:
            iam.delete_role_policy(RoleName=TARGET_ROLE_NAME, PolicyName=policy_name)
        except ClientError as rollback_exc:
            print(f"Rollback delete_role_policy also failed: {rollback_exc}")
        return _response(500, {"message": "Could not schedule the automatic revocation; grant was not applied"})

    table.update_item(
        Key={"requestId": request_id},
        UpdateExpression=(
            "SET #s = :status, decidedBy = :by, decidedAt = :at, "
            "expiresAt = :exp, scheduleName = :sched, policyName = :pol"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":status": "active",
            ":by": approver_email or approver_id,
            ":at": str(now_epoch),
            ":exp": str(expires_epoch),
            ":sched": schedule_name,
            ":pol": policy_name,
        },
    )

    _notify(item, "active", approver_email or approver_id, expires_epoch)
    return _response(200, {"requestId": request_id, "status": "active", "expiresAt": expires_epoch})


def _notify(item, new_status, actor, expires_epoch=None):
    try:
        msg = f"requestId={item['requestId']}\nstatus={new_status}\nactedBy={actor}"
        if expires_epoch:
            msg += f"\nexpiresAt={expires_epoch}"
        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject=f"Access request {new_status}: {item['requestId']}"[:100],
            Message=msg,
        )
    except ClientError as exc:  # noqa: BLE001
        print(f"SNS publish failed (non-fatal): {exc}")
