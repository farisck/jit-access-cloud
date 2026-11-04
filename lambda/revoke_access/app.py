"""
revoke_access

Two invocation paths:
  1. EventBridge Scheduler (automatic, at the approved end time) - the event
     is exactly what approve_access put in Target.Input:
     {"requestId": "...", "reason": "scheduled_expiry"}
  2. API Gateway (manual early revoke), DELETE /requests/{requestId} behind
     the Cognito JWT authorizer, restricted to the approvers group or the
     original requester.

Statuses only move forward.  What revoke does depends on where the request is:

  scheduled   Nothing was ever granted: the activation claim and this write
              both need "scheduled", so only one can win.  Go straight to
              the terminal status (expired / revoked_early).  No IAM call.
  active      Activation has finished, so nothing is in flight.  Record
              cleanup_pending, delete the policy, then finalize.
  activating  An activation may still be talking to IAM.  Record
              cleanup_pending with cleanupNotBefore = the activation's own
              deadline, try one delete, and leave finalizing to the
              reconciler, which needs repeated clean passes.
  cleanup_pending / terminal   No-op.

A failed IAM delete never changes the status.  It is recorded, alerted,
and re-raised, so the failure is loud and the request stays cleanup_pending
for the reconciler to retry.
"""
import json
import os
import time

import boto3
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb")
iam = boto3.client("iam")
sns = boto3.client("sns")
scheduler = boto3.client("scheduler")

TABLE_NAME = os.environ["REQUESTS_TABLE_NAME"]
TOPIC_ARN = os.environ["NOTIFICATIONS_TOPIC_ARN"]
TARGET_ROLE_NAME = os.environ["TARGET_ROLE_NAME"]
SCHEDULE_GROUP_NAME = os.environ["SCHEDULE_GROUP_NAME"]

# Used only if an "activating" request has no recorded activationDeadline.
FALLBACK_ACTIVATION_DEADLINE_SECONDS = 180
# How many times to re-read and retry when another writer moves the request.
MAX_STATE_RETRIES = 3
# The only outcomes a saved revocation intent may carry.
INTENT_TARGETS = ("expired", "revoked_early")

table = dynamodb.Table(TABLE_NAME)


def _api_response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
        "body": json.dumps(body),
    }


def _is_api_gateway_event(event):
    return isinstance(event, dict) and "requestContext" in event and "http" in event.get("requestContext", {})


def _parse_groups_claim(groups_raw):
    """
    See approve_access/app.py for the full explanation: API Gateway's HTTP
    API JWT authorizer stringifies array claims using Java's array
    toString format (literal brackets, e.g. "[approvers]"), not JSON, so a
    naive comma-split leaves brackets attached and breaks membership
    checks. This strips them first.
    """
    if isinstance(groups_raw, list):
        return groups_raw
    cleaned = str(groups_raw).strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]
    return [g.strip() for g in cleaned.split(",") if g.strip()]


def _is_conditional_failure(exc):
    return (
        exc.response.get("Error", {}).get("Code")
        == "ConditionalCheckFailedException"
    )


def _terminal_status(reason):
    return "expired" if reason == "scheduled_expiry" else "revoked_early"


def _notify(subject, message):
    try:
        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject=subject[:100],
            Message=message,
        )
    except ClientError as exc:
        print(f"SNS publish failed (non-fatal): {exc}")


def _current_status(request_id):
    item = table.get_item(
        Key={"requestId": request_id},
        ConsistentRead=True,
    ).get("Item")
    return item.get("status") if item else "not_found"


def _cancel_schedules(item):
    """Best effort: a terminal or pending status already blocks late runs."""
    for schedule_key in ("activationScheduleName", "scheduleName"):
        schedule_name = item.get(schedule_key)
        if not schedule_name:
            continue
        try:
            scheduler.delete_schedule(
                Name=schedule_name,
                GroupName=SCHEDULE_GROUP_NAME,
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "ResourceNotFoundException":
                print(f"revoke_access: could not delete schedule {schedule_name}: {exc}")


def _delete_policy(policy_name):
    """Delete the named inline policy.  Returns "deleted" or "absent".

    Any other IAM error propagates to the caller.
    """
    try:
        iam.delete_role_policy(
            RoleName=TARGET_ROLE_NAME,
            PolicyName=policy_name,
        )
    except iam.exceptions.NoSuchEntityException:
        return "absent"
    return "deleted"


def _record_cleanup_failure(request_id, exc):
    """Make a failed delete durable and loud.  The status is NOT changed."""
    print(f"revoke_access: delete_role_policy FAILED for {request_id}: {exc}")
    try:
        table.update_item(
            Key={"requestId": request_id},
            UpdateExpression=(
                "SET revokeFailureReason = :err, lastCleanupAttemptAt = :at "
                "ADD cleanupAttempts :one"
            ),
            ConditionExpression="#s = :pending",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":err": str(exc),
                ":at": str(int(time.time())),
                ":one": 1,
                ":pending": "cleanup_pending",
            },
        )
    except ClientError as write_exc:
        # Never hide the original IAM error behind a bookkeeping failure.
        print(f"revoke_access: could not record failure for {request_id}: {write_exc}")

    _notify(
        f"URGENT: revocation failed for {request_id}",
        (
            f"requestId={request_id}\nDurable cleanup is pending. "
            f"The reconciler will retry.\nerror={exc}"
        ),
    )


def _record_revocation_intent(request_id, target_status, actor):
    """Durably save WHY this request is being revoked, before moving it.

    Only valid while the request is still "activating".  if_not_exists keeps
    the first saved intent, so a retry or a second revoker can never change
    it.  Returns the intent that is actually saved, which may differ from
    target_status if an earlier attempt already recorded one.
    """
    response = table.update_item(
        Key={"requestId": request_id},
        UpdateExpression=(
            "SET revocationIntentTarget = "
            "if_not_exists(revocationIntentTarget, :target), "
            "revocationIntentAt = if_not_exists(revocationIntentAt, :at), "
            "revocationIntentBy = if_not_exists(revocationIntentBy, :by)"
        ),
        ConditionExpression="#s = :activating",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":target": target_status,
            ":activating": "activating",
            ":at": str(int(time.time())),
            ":by": actor or "scheduler",
        },
        ReturnValues="ALL_NEW",
    )
    saved = response.get("Attributes", {}).get("revocationIntentTarget")
    if saved not in INTENT_TARGETS:
        raise RuntimeError(
            f"saved revocation intent for {request_id} is invalid: {saved!r}"
        )
    return saved


def _mark_cleanup_pending(request_id, from_status, target_status, actor, not_before):
    """Persist the revocation before touching IAM."""
    table.update_item(
        Key={"requestId": request_id},
        UpdateExpression=(
            "SET #s = :pending, cleanupTargetStatus = :target, "
            "cleanupNotBefore = :not_before, revokedAt = :at, revokedBy = :by"
        ),
        ConditionExpression="#s = :from_status",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":pending": "cleanup_pending",
            ":target": target_status,
            ":not_before": str(not_before),
            ":from_status": from_status,
            ":at": str(int(time.time())),
            ":by": actor or "scheduler",
        },
    )


def _finalize(request_id, target_status):
    """Move cleanup_pending to its terminal status, only if still pending."""
    try:
        table.update_item(
            Key={"requestId": request_id},
            UpdateExpression="SET #s = :status, cleanedUpAt = :at",
            ConditionExpression="#s = :pending",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":status": target_status,
                ":pending": "cleanup_pending",
                ":at": str(int(time.time())),
            },
        )
    except ClientError as exc:
        if not _is_conditional_failure(exc):
            raise
        return _current_status(request_id)
    return target_status


def _revoke_scheduled(request_id, item, reason, actor):
    target_status = _terminal_status(reason)
    table.update_item(
        Key={"requestId": request_id},
        UpdateExpression="SET #s = :status, revokedAt = :at, revokedBy = :by",
        ConditionExpression="#s = :scheduled",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":status": target_status,
            ":scheduled": "scheduled",
            ":at": str(int(time.time())),
            ":by": actor or "scheduler",
        },
    )

    if reason != "scheduled_expiry":
        _cancel_schedules(item)

    _notify(
        f"Access revoked: {request_id}",
        (
            f"requestId={request_id}\nstatus={target_status}\n"
            f"revokedBy={actor or 'scheduler'}"
        ),
    )
    return {"requestId": request_id, "status": target_status}


def _revoke_active(request_id, item, reason, actor):
    target_status = _terminal_status(reason)
    _mark_cleanup_pending(
        request_id, "active", target_status, actor, int(time.time())
    )

    if reason != "scheduled_expiry":
        _cancel_schedules(item)

    policy_name = item.get("policyName", f"jit-grant-{request_id}")
    try:
        outcome = _delete_policy(policy_name)
    except ClientError as exc:
        _record_cleanup_failure(request_id, exc)
        raise
    print(f"revoke_access: policy {policy_name} {outcome} for {request_id}")

    final_status = _finalize(request_id, target_status)
    _notify(
        f"Access revoked: {request_id}",
        (
            f"requestId={request_id}\nstatus={final_status}\n"
            f"revokedBy={actor or 'scheduler'}"
        ),
    )
    return {"requestId": request_id, "status": final_status}


def _revoke_activating(request_id, item, reason, actor):
    target_status = _terminal_status(reason)
    try:
        not_before = int(item["activationDeadline"])
    except (KeyError, TypeError, ValueError):
        not_before = int(time.time()) + FALLBACK_ACTIVATION_DEADLINE_SECONDS

    target_status = _record_revocation_intent(request_id, target_status, actor)
    _mark_cleanup_pending(
        request_id, "activating", target_status, actor, not_before
    )

    if reason != "scheduled_expiry":
        _cancel_schedules(item)

    # One delete attempt now.  Even a clean result is NOT proof that an
    # in-flight activation has stopped, so only the reconciler finalizes.
    policy_name = item.get("policyName", f"jit-grant-{request_id}")
    try:
        outcome = _delete_policy(policy_name)
    except ClientError as exc:
        _record_cleanup_failure(request_id, exc)
        raise
    print(
        f"revoke_access: policy {policy_name} {outcome}; "
        f"{request_id} stays cleanup_pending for the reconciler"
    )

    _notify(
        f"Access revoked: {request_id}",
        (
            f"requestId={request_id}\nstatus=cleanup_pending\n"
            f"targetStatus={target_status}\nrevokedBy={actor or 'scheduler'}"
        ),
    )
    return {"requestId": request_id, "status": "cleanup_pending"}


def _revoke(request_id, reason, actor):
    for _ in range(MAX_STATE_RETRIES):
        item = table.get_item(
            Key={"requestId": request_id},
            ConsistentRead=True,
        ).get("Item")
        if not item:
            print(f"revoke_access: no such request {request_id} - treating as no-op success")
            return {"requestId": request_id, "status": "not_found"}

        status = item.get("status")
        try:
            if status == "scheduled":
                return _revoke_scheduled(request_id, item, reason, actor)
            if status == "active":
                return _revoke_active(request_id, item, reason, actor)
            if status == "activating":
                return _revoke_activating(request_id, item, reason, actor)
        except ClientError as exc:
            if _is_conditional_failure(exc):
                # Another writer moved the request; re-read and decide again.
                continue
            raise

        # cleanup_pending is owned by the reconciler; anything else is
        # already terminal.  Both are idempotent no-ops.
        print(f"revoke_access: {request_id} is '{status}' - nothing to do")
        return {"requestId": request_id, "status": status}

    raise RuntimeError(
        f"revoke_access could not claim {request_id} after "
        f"{MAX_STATE_RETRIES} attempts"
    )


def handler(event, context):
    if _is_api_gateway_event(event):
        try:
            claims = event["requestContext"]["authorizer"]["jwt"]["claims"]
            caller_id = claims["sub"]
            caller_email = claims.get("email", "")
            groups_raw = claims.get("cognito:groups", "")
            groups = _parse_groups_claim(groups_raw)
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