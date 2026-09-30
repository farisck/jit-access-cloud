"""
revoke_access

Two invocation paths:
  1. EventBridge Scheduler (automatic, at the requested expiry) - the event
     is exactly what approve_access put in Target.Input:
     {"requestId": "...", "reason": "scheduled_expiry"}
  2. API Gateway (manual early revoke), DELETE /requests/{requestId} behind
     the Cognito JWT authorizer, restricted to the approvers group or the
     original requester.

Whichever path calls it, the actual removal logic is identical and
idempotent: if the policy is already gone (already revoked, or somehow
never applied), that is treated as success, not an error - a JIT system
should never fail loudly just because someone revoked something twice.

If IAM genuinely refuses to remove the policy for any OTHER reason, this
function re-raises so the invocation is recorded as a Lambda error. That is
deliberate: a revocation that fails must be loud (a CloudWatch alarm and an
SNS page), never silent, since standing access nobody knows about is the
exact failure mode this whole project exists to prevent.

This function's IAM role can only DeleteRolePolicy on the one target role.
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

table = dynamodb.Table(TABLE_NAME)


def _api_response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
        "body": json.dumps(body),
    }


def _is_api_gateway_event(event):
    return isinstance(event, dict) and "requestContext" in event and "http" in event.get("requestContext", {})


def _revoke(request_id, reason, actor):
    item_resp = table.get_item(Key={"requestId": request_id})
    item = item_resp.get("Item")
    if not item:
        print(f"revoke_access: no such request {request_id} (already deleted?) - treating as no-op success")
        return {"requestId": request_id, "status": "not_found"}

    current_status = item.get("status")
    if current_status != "active":
        # Idempotent: already revoked/expired/denied - nothing to do.
        print(f"revoke_access: {request_id} is '{current_status}', not 'active' - no-op success")
        return {"requestId": request_id, "status": current_status}

    policy_name = item.get("policyName", f"jit-grant-{request_id}")
    now_epoch = int(time.time())

    try:
        iam.delete_role_policy(RoleName=TARGET_ROLE_NAME, PolicyName=policy_name)
    except iam.exceptions.NoSuchEntityException:
        # Policy already gone - fine, proceed to mark it revoked.
        print(f"revoke_access: policy {policy_name} already absent - proceeding")
    except ClientError as exc:
        # A genuine, unexpected failure to remove standing access. Mark it
        # in DynamoDB so it's visible in the audit trail, publish an urgent
        # SNS alert, then RE-RAISE so this Lambda invocation is recorded as
        # an error - that's what makes the CloudWatch alarm fire.
        print(f"revoke_access: delete_role_policy FAILED for {request_id}: {exc}")
        table.update_item(
            Key={"requestId": request_id},
            UpdateExpression="SET #s = :status, revokeFailureReason = :err",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":status": "revoke_failed", ":err": str(exc)},
        )
        try:
            sns.publish(
                TopicArn=TOPIC_ARN,
                Subject=f"URGENT: revocation failed for {request_id}"[:100],
                Message=f"requestId={request_id}\nManual intervention required - standing access may still be active.\nerror={exc}",
            )
        except ClientError:
            pass
        raise

    new_status = "expired" if reason == "scheduled_expiry" else "revoked_early"
    table.update_item(
        Key={"requestId": request_id},
        UpdateExpression="SET #s = :status, revokedAt = :at, revokedBy = :by",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":status": new_status, ":at": str(now_epoch), ":by": actor or "scheduler"},
    )

    try:
        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject=f"Access revoked: {request_id}"[:100],
            Message=f"requestId={request_id}\nstatus={new_status}\nrevokedBy={actor or 'scheduler'}",
        )
    except ClientError as exc:  # noqa: BLE001
        print(f"SNS publish failed (non-fatal): {exc}")

    return {"requestId": request_id, "status": new_status}


def handler(event, context):
    if _is_api_gateway_event(event):
        try:
            claims = event["requestContext"]["authorizer"]["jwt"]["claims"]
            caller_id = claims["sub"]
            caller_email = claims.get("email", "")
            groups_raw = claims.get("cognito:groups", "")
            groups = groups_raw if isinstance(groups_raw, list) else [g.strip() for g in str(groups_raw).split(",") if g]
        except (KeyError, TypeError):
            return _api_response(401, {"message": "Missing or invalid authorization token"})

        request_id = (event.get("pathParameters") or {}).get("requestId")
        if not request_id:
            return _api_response(400, {"message": "requestId path parameter is required"})

        item = table.get_item(Key={"requestId": request_id}).get("Item")
        if not item:
            return _api_response(404, {"message": "Request not found"})

        is_owner = item.get("requesterId") == caller_id
        is_approver = "approvers" in groups
        if not (is_owner or is_approver):
            return _api_response(403, {"message": "Only the requester or an approver may revoke this grant"})

        result = _revoke(request_id, reason="manual_revoke", actor=caller_email or caller_id)
        return _api_response(200, result)

    # EventBridge Scheduler path: event is exactly the Target.Input JSON.
    request_id = event.get("requestId")
    reason = event.get("reason", "scheduled_expiry")
    if not request_id:
        raise ValueError(f"revoke_access invoked with no requestId in event: {event}")

    return _revoke(request_id, reason=reason, actor=None)
