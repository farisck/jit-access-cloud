"""
request_access

API Gateway-triggered (POST /requests), behind the Cognito JWT authorizer.
Any authenticated employee can call this.

Body: { "permission": "s3-read-demo-bucket", "reason": "...", "accessStartAt": "...", "accessEndAt": "..." }

"permission" must be one of the keys in PERMISSION_CATALOG (a small, fixed
set of safe, pre-defined grants - see approve_access for why arbitrary IAM
JSON from a requester is not accepted). Access windows must be in the
future and are capped by MAX_DURATION_MINUTES. Legacy durationMinutes
requests remain supported.

This function's IAM role only has dynamodb:PutItem on the requests table
and sns:Publish on the notifications topic - it cannot touch IAM at all.
"""
import json
import os
import time
import uuid
from datetime import datetime

import boto3

dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")

TABLE_NAME = os.environ["REQUESTS_TABLE_NAME"]
TOPIC_ARN = os.environ["NOTIFICATIONS_TOPIC_ARN"]
MAX_DURATION_MINUTES = int(os.environ.get("MAX_DURATION_MINUTES", "480"))  # 8 hours
MAX_REASON_LENGTH = 500

# Kept in sync with approve_access's PERMISSION_CATALOG - only the keys
# matter here, used purely for validating the request up front.
ALLOWED_PERMISSIONS = set(json.loads(os.environ.get("PERMISSION_CATALOG_KEYS", "[]")))

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


def handler(event, context):
    try:
        claims = event["requestContext"]["authorizer"]["jwt"]["claims"]
        requester_id = claims["sub"]
        requester_email = claims.get("email", "")
    except (KeyError, TypeError):
        return _response(401, {"message": "Missing or invalid authorization token"})

    try:
        payload = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _response(400, {"message": "Request body must be valid JSON"})

    permission = payload.get("permission", "")
    reason = (payload.get("reason") or "").strip()
    duration_minutes = payload.get("durationMinutes")
    start_value = payload.get("accessStartAt")
    end_value = payload.get("accessEndAt")

    if permission not in ALLOWED_PERMISSIONS:
        return _response(
            400,
            {
                "message": "Unknown permission requested",
                "allowed": sorted(ALLOWED_PERMISSIONS),
            },
        )

    if not reason or len(reason) > MAX_REASON_LENGTH:
        return _response(400, {"message": f"'reason' is required (max {MAX_REASON_LENGTH} characters)"})

    now_epoch = int(time.time())
    access_start_epoch = None
    access_end_epoch = None

    if start_value is not None or end_value is not None:
        if not isinstance(start_value, str) or not isinstance(end_value, str):
            return _response(
                400,
                {"message": "Both accessStartAt and accessEndAt are required"},
            )

        try:
            start_dt = datetime.fromisoformat(start_value.replace("Z", "+00:00"))
            end_dt = datetime.fromisoformat(end_value.replace("Z", "+00:00"))
        except ValueError:
            return _response(
                400,
                {"message": "Access timestamps must be valid ISO 8601 datetimes"},
            )

        if (
            start_dt.tzinfo is None
            or start_dt.utcoffset() is None
            or end_dt.tzinfo is None
            or end_dt.utcoffset() is None
        ):
            return _response(
                400,
                {"message": "Access timestamps must include a timezone"},
            )

        start_timestamp = start_dt.timestamp()
        end_timestamp = end_dt.timestamp()
        if start_timestamp <= time.time():
            return _response(400, {"message": "accessStartAt must be in the future"})
        if end_timestamp <= start_timestamp:
            return _response(
                400,
                {"message": "accessEndAt must be after accessStartAt"},
            )

        access_start_epoch = int(start_timestamp)
        access_end_epoch = int(end_timestamp)
        duration_seconds = access_end_epoch - access_start_epoch
        if duration_seconds <= 0:
            return _response(
                400,
                {"message": "Access window must be at least one minute"},
            )
        if duration_seconds % 60 != 0:
            return _response(
                400,
                {"message": "Access window must have a whole-minute duration"},
            )
        duration_minutes = int(duration_seconds // 60)
        if duration_minutes > MAX_DURATION_MINUTES:
            return _response(
                400,
                {"message": f"Access window cannot exceed {MAX_DURATION_MINUTES} minutes"},
            )

    elif (
        not isinstance(duration_minutes, int)
        or isinstance(duration_minutes, bool)
        or not (0 < duration_minutes <= MAX_DURATION_MINUTES)
    ):
        return _response(
            400,
            {"message": f"'durationMinutes' must be a whole number between 1 and {MAX_DURATION_MINUTES}"},
        )

    request_id = str(uuid.uuid4())

    item = {
        "requestId": request_id,
        "requesterId": requester_id,
        "requesterEmail": requester_email,
        "permission": permission,
        "reason": reason,
        "durationMinutes": duration_minutes,
        "status": "pending",
        "requestedAt": str(now_epoch),
    }
    if access_start_epoch is not None and access_end_epoch is not None:
        item["accessStartAt"] = str(access_start_epoch)
        item["accessEndAt"] = str(access_end_epoch)

    try:
        table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(requestId)",
        )
    except Exception as exc:  # noqa: BLE001
        print(f"DynamoDB put_item failed: {exc}")
        return _response(500, {"message": "Could not create the request"})

    try:
        sns.publish(
            TopicArn=TOPIC_ARN,
            Subject=f"New access request from {requester_email or requester_id}"[:100],
            Message=(
                f"requestId={request_id}\n"
                f"requester={requester_email or requester_id}\n"
                f"permission={permission}\n"
                f"durationMinutes={duration_minutes}\n"
                f"reason={reason}"
            ),
        )
    except Exception as exc:  # noqa: BLE001
        # Don't fail the request over a notification hiccup - the approver
        # can still see it via GET /requests.
        print(f"SNS publish failed (non-fatal): {exc}")

    return _response(200, {"requestId": request_id, "status": "pending"})
