"""
reconcile_cleanup

Runs on a schedule and finishes revocations that revoke_access could not
safely finish itself.

Requests in "cleanup_pending" and "activating" are discovered through the
status-index GSI. That index is eventually consistent, so every candidate is
re-read with a strongly consistent GetItem before anything is done to it.
Stale "activating" requests are recovered only when their activation deadline
has passed and a valid, persisted revocation intent exists. Missing or invalid
recovery information is never guessed; unrecoverable cases may trigger a
one-time SNS alert after the configured grace period.

For each pending request this function, on every run:

  1. Deletes the request's own inline policy (jit-grant-<requestId>).
     "Deleted" and "already absent" are both fine; any other IAM error keeps
     the request pending, is recorded durably, and is alerted.

  2. Counts a "clean pass" only when ALL of these hold:
       - the policy was already absent (nothing was deleted this run), and
       - the request's cleanupNotBefore time has passed.  That time comes
         from the activation's own recorded deadline, so any invocation
         that claimed the request before the revoke has stopped by then.

  3. Finalizes to the request's cleanupTargetStatus (expired or
     revoked_early) only on a SECOND clean pass, at least
     MIN_PASS_GAP_SECONDS after the first.  If a late policy ever shows up
     in between, it is deleted and the count restarts from zero.

Finalizing is a conditional write on "cleanup_pending", so running this
twice, or racing another writer, cannot overwrite anything.

If anything failed, the invocation raises at the end (after every request
has been tried) so the failure is visible to CloudWatch.
"""
import os
import time

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb")
iam = boto3.client("iam")
sns = boto3.client("sns")

TABLE_NAME = os.environ["REQUESTS_TABLE_NAME"]
TOPIC_ARN = os.environ["NOTIFICATIONS_TOPIC_ARN"]
TARGET_ROLE_NAME = os.environ["TARGET_ROLE_NAME"]

STATUS_INDEX_NAME = "status-index"
PENDING_STATUS = "cleanup_pending"
TERMINAL_STATUSES = ("expired", "revoked_early")
ACTIVATING_STATUS = "activating"

# Two clean passes must be at least this far apart, so a retried or
# overlapping invocation cannot count as a "separate run".
MIN_PASS_GAP_SECONDS = 30
# Stop starting new work when the invocation is about to time out; the next
# scheduled run continues where this one stopped.
MIN_REMAINING_MS = 5000
# Alert on the first failure for a request, then once per this many failures.
ALERT_EVERY_N_FAILURES = 10
# A stuck "activating" request is only alerted on once its access window
# ended this long ago.  Until then the normal scheduled revoke may simply
# not have fired yet.
UNRECOVERABLE_ALERT_GRACE_SECONDS = 300

table = dynamodb.Table(TABLE_NAME)


def _is_conditional_failure(exc):
    return (
        exc.response.get("Error", {}).get("Code")
        == "ConditionalCheckFailedException"
    )


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _notify(subject, message):
    try:
        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject=subject[:100],
            Message=message,
        )
        return True
    except ClientError as exc:
        print(f"SNS publish failed (non-fatal): {exc}")
        return False


def _request_ids_with_status(status):
    """Yield every request id the status-index reports for one status."""
    query = {
        "IndexName": STATUS_INDEX_NAME,
        "KeyConditionExpression": Key("status").eq(status),
    }
    while True:
        page = table.query(**query)
        for item in page.get("Items", []):
            request_id = item.get("requestId")
            if request_id:
                yield request_id
        last_key = page.get("LastEvaluatedKey")
        if not last_key:
            return
        query["ExclusiveStartKey"] = last_key


def _candidate_request_ids():
    """Yield cleanup_pending ids first, then activating ids, each once.

    The index is eventually consistent and a request can move between our
    two queries, so the same id may appear in both results.
    """
    seen = set()
    for status in (PENDING_STATUS, ACTIVATING_STATUS):
        for request_id in _request_ids_with_status(status):
            if request_id not in seen:
                seen.add(request_id)
                yield request_id


def _delete_policy(policy_name):
    """Delete the named inline policy.  Returns "deleted" or "absent"."""
    try:
        iam.delete_role_policy(
            RoleName=TARGET_ROLE_NAME,
            PolicyName=policy_name,
        )
    except iam.exceptions.NoSuchEntityException:
        return "absent"
    return "deleted"


def _guarded_update(
    request_id,
    update_expression,
    values,
    condition_expression=None,
    condition_names=None,
):
    """Write only while the request is still cleanup_pending."""
    names = {"#s": "status"}
    if condition_names:
        names.update(condition_names)

    try:
        table.update_item(
            Key={"requestId": request_id},
            UpdateExpression=update_expression,
            ConditionExpression=condition_expression or "#s = :pending",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues={
                ":pending": PENDING_STATUS,
                **values,
            },
        )
    except ClientError as exc:
        if _is_conditional_failure(exc):
            print(
                f"reconcile_cleanup: conditional update conflict "
                f"for {request_id}; another invocation may have changed it"
            )
            return False
        raise
    return True


def _record_failure(request_id, item, reason):
    """Keep the request pending, make the failure durable, and alert."""
    attempts = _int_or_none(item.get("cleanupAttempts")) or 0
    print(f"reconcile_cleanup: FAILED for {request_id}: {reason}")

    try:
        table.update_item(
            Key={"requestId": request_id},
            UpdateExpression=(
                "SET revokeFailureReason = :err, lastCleanupAttemptAt = :at, "
                "cleanCleanupPasses = :zero "
                "REMOVE lastCleanPassAt "
                "ADD cleanupAttempts :one"
            ),
            ConditionExpression="#s = :pending",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":err": str(reason),
                ":at": str(int(time.time())),
                ":zero": 0,
                ":one": 1,
                ":pending": PENDING_STATUS,
            },
        )
    except ClientError as write_exc:
        # Never let bookkeeping hide the original problem.
        print(f"reconcile_cleanup: could not record failure for {request_id}: {write_exc}")

    if attempts % ALERT_EVERY_N_FAILURES == 0:
        _notify(
            f"URGENT: cleanup still failing for {request_id}",
            (
                f"requestId={request_id}\n"
                f"The request stays cleanup_pending and will be retried.\n"
                f"failures so far={attempts + 1}\nerror={reason}"
            ),
        )


def _alert_unrecoverable_once(request_id, item, now):
    """Alert once for an overdue activating request we cannot recover.

    If SNS publishing fails, conditionally remove this attempt's marker so a
    later reconciliation run can retry the alert.
    """
    access_end = _int_or_none(item.get("accessEndAt"))
    if access_end is None:
        return
    if now < access_end + UNRECOVERABLE_ALERT_GRACE_SECONDS:
        return

    marker = str(now)
    try:
        table.update_item(
            Key={"requestId": request_id},
            UpdateExpression="SET unrecoverableAlertedAt = :now",
            ConditionExpression=(
                "#s = :activating "
                "AND attribute_not_exists(unrecoverableAlertedAt)"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":now": marker,
                ":activating": ACTIVATING_STATUS,
            },
        )
    except ClientError as exc:
        if not _is_conditional_failure(exc):
            # Not marked, so the next run will try again.
            print(
                f"reconcile_cleanup: could not record alert marker "
                f"for {request_id}: {exc}"
            )
        return

    published = _notify(
        f"URGENT: stuck activation for {request_id}",
        (
            f"requestId={request_id}\n"
            f"The request is still 'activating' well after its access "
            f"window ended, and no revocation intent was saved, so the "
            f"reconciler cannot safely recover it.\n"
            f"Check the revoke Lambda logs and the request in DynamoDB."
        ),
    )
    if published:
        return

    try:
        table.update_item(
            Key={"requestId": request_id},
            UpdateExpression="REMOVE unrecoverableAlertedAt",
            ConditionExpression=(
                "#s = :activating "
                "AND unrecoverableAlertedAt = :marker"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":activating": ACTIVATING_STATUS,
                ":marker": marker,
            },
        )
    except ClientError as exc:
        if not _is_conditional_failure(exc):
            print(
                f"reconcile_cleanup: could not clear alert marker "
                f"for {request_id}: {exc}"
            )


def _recover_stale_activating(request_id, item, now):
    """Move a stale activating request to cleanup_pending, only when safe.

    Needs BOTH a passed activationDeadline AND a saved revocation intent.
    The deadline alone never proves a revocation was requested, so a missing
    or invalid intent is left untouched and never guessed.
    Returns one of: waiting, unrecoverable, recovered, skipped, failed.
    """
    deadline = _int_or_none(item.get("activationDeadline"))
    if deadline is None:
        print(
            f"reconcile_cleanup: {request_id} is activating with a missing "
            f"or invalid activationDeadline; leaving it unchanged"
        )
        _alert_unrecoverable_once(request_id, item, now)
        return "unrecoverable"

    if now < deadline:
        return "waiting"

    target = item.get("revocationIntentTarget")
    if target not in TERMINAL_STATUSES:
        print(
            f"reconcile_cleanup: {request_id} is activating past its "
            f"deadline with no valid revocation intent ({target!r}); "
            f"leaving it unchanged"
        )
        _alert_unrecoverable_once(request_id, item, now)
        return "unrecoverable"

    try:
        table.update_item(
            Key={"requestId": request_id},
            UpdateExpression=(
                "SET #s = :pending, cleanupTargetStatus = :target, "
                "cleanupNotBefore = :not_before, recoveredAt = :now"
            ),
            ConditionExpression=(
                "#s = :activating AND #intent = :target "
                "AND #deadline = :not_before"
            ),
            ExpressionAttributeNames={
                "#s": "status",
                "#intent": "revocationIntentTarget",
                "#deadline": "activationDeadline",
            },
            ExpressionAttributeValues={
                ":pending": PENDING_STATUS,
                ":activating": ACTIVATING_STATUS,
                ":target": target,
                ":not_before": item["activationDeadline"],
                ":now": str(now),
            },
        )
    except ClientError as exc:
        if _is_conditional_failure(exc):
            print(
                f"reconcile_cleanup: recovery conflict for {request_id}; "
                f"another writer changed it"
            )
            return "skipped"
        print(f"reconcile_cleanup: could not recover {request_id}: {exc}")
        return "failed"

    _notify(
        f"Stale activation recovered: {request_id}",
        (
            f"requestId={request_id}\n"
            f"An activation stayed in 'activating' past its deadline. "
            f"It is now cleanup_pending with target {target}."
        ),
    )
    return "recovered"


def _reconcile_one(request_id, now):
    """Return one of: skipped, waiting, pass_recorded, finalized, reset, failed."""
    # The GSI can be stale: always decide from a consistent read.
    item = table.get_item(
        Key={"requestId": request_id},
        ConsistentRead=True,
    ).get("Item")
    if not item:
        return "skipped"
    if item.get("status") == ACTIVATING_STATUS:
        return _recover_stale_activating(request_id, item, now)
    if item.get("status") != PENDING_STATUS:
        return "skipped"

    target_status = item.get("cleanupTargetStatus")
    if target_status not in TERMINAL_STATUSES:
        _record_failure(
            request_id, item,
            f"invalid cleanupTargetStatus {target_status!r}; refusing to finalize",
        )
        return "failed"

    not_before = _int_or_none(item.get("cleanupNotBefore"))
    if not_before is None:
        _record_failure(
            request_id, item,
            "missing or invalid cleanupNotBefore; refusing to finalize",
        )
        return "failed"

    policy_name = item.get("policyName") or f"jit-grant-{request_id}"

    try:
        outcome = _delete_policy(policy_name)
    except ClientError as exc:
        _record_failure(request_id, item, exc)
        return "failed"

    due = now >= not_before

    if outcome == "deleted":
        # A policy existed: either this is the first cleanup, or a late
        # PutRolePolicy landed.  Either way it is not a clean pass.
        _guarded_update(
            request_id,
            "SET cleanCleanupPasses = :zero, lastCleanupAttemptAt = :now "
            "REMOVE lastCleanPassAt",
            {":zero": 0, ":now": str(now)},
        )
        if due:
            _notify(
                f"Late policy removed for {request_id}",
                (
                    f"requestId={request_id}\n"
                    f"policy={policy_name} was still attached after its "
                    f"cleanup deadline and has been deleted."
                ),
            )
        return "reset"

    if not due:
        return "waiting"

    passes = _int_or_none(item.get("cleanCleanupPasses")) or 0
    last_pass_at = _int_or_none(item.get("lastCleanPassAt")) or 0

    if passes < 1:
        if "cleanCleanupPasses" in item:
            pass_condition = (
                "#s = :pending AND #passes = :observed_passes "
                "AND attribute_not_exists(#last_pass)"
            )
            pass_values = {
                ":one": 1,
                ":now": str(now),
                ":observed_passes": item["cleanCleanupPasses"],
            }
        else:
            pass_condition = (
                "#s = :pending "
                "AND attribute_not_exists(#passes) "
                "AND attribute_not_exists(#last_pass)"
            )
            pass_values = {
                ":one": 1,
                ":now": str(now),
            }

        recorded = _guarded_update(
            request_id,
            "SET #passes = :one, #last_pass = :now, "
            "lastCleanupAttemptAt = :now",
            pass_values,
            condition_expression=pass_condition,
            condition_names={
                "#passes": "cleanCleanupPasses",
                "#last_pass": "lastCleanPassAt",
            },
        )
        return "pass_recorded" if recorded else "skipped"

    if now - last_pass_at < MIN_PASS_GAP_SECONDS:
        return "waiting"

    final_condition = "#s = :pending AND #passes = :observed_passes"
    final_values = {
        ":target": target_status,
        ":now": str(now),
        ":observed_passes": item["cleanCleanupPasses"],
    }
    if "lastCleanPassAt" in item:
        final_condition += " AND #last_pass = :observed_last_pass"
        final_values[":observed_last_pass"] = item["lastCleanPassAt"]
    else:
        final_condition += " AND attribute_not_exists(#last_pass)"

    finalized = _guarded_update(
        request_id,
        "SET #s = :target, cleanedUpAt = :now",
        final_values,
        condition_expression=final_condition,
        condition_names={
            "#passes": "cleanCleanupPasses",
            "#last_pass": "lastCleanPassAt",
        },
    )
    if not finalized:
        return "skipped"

    _notify(
        f"Access revoked: {request_id}",
        f"requestId={request_id}\nstatus={target_status}\nfinalizedBy=reconciler",
    )
    return "finalized"


def handler(event, context):
    summary = {
        "skipped": 0,
        "waiting": 0,
        "pass_recorded": 0,
        "finalized": 0,
        "reset": 0,
        "recovered": 0,
        "unrecoverable": 0,
        "failed": 0,
        "stopped_early": False,
    }

    for request_id in _candidate_request_ids():
        if (
            context is not None
            and context.get_remaining_time_in_millis() < MIN_REMAINING_MS
        ):
            summary["stopped_early"] = True
            print("reconcile_cleanup: out of time; the next run continues")
            break

        try:
            outcome = _reconcile_one(request_id, int(time.time()))
        except Exception as exc:
            # One bad request must not stop the others from being cleaned up.
            print(
                f"reconcile_cleanup: unexpected error for {request_id}: {exc!r}"
            )
            outcome = "failed"
        summary[outcome] += 1

    print(f"reconcile_cleanup: {summary}")

    if summary["failed"]:
        raise RuntimeError(
            f"{summary['failed']} cleanup(s) failed and remain pending; "
            f"see logs: {summary}"
        )
    return summary