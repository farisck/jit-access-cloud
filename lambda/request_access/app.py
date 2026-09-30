"""
request_access

API Gateway-triggered (POST /requests), behind the Cognito JWT authorizer.
Any authenticated employee can call this.

Body: { "permission": "s3-read-demo-bucket", "reason": "...", "durationMinutes": 60 }

"permission" must be one of the keys in PERMISSION_CATALOG (a small, fixed
set of safe, pre-defined grants - see approve_access for why arbitrary IAM
JSON from a requester is not accepted). durationMinutes is capped by
MAX_DURATION_MINUTES so no one can request a "temporary" grant that lasts
for months.

This function's IAM role only has dynamodb:PutItem on the requests table
and sns:Publish on the notifications topic - it cannot touch IAM at all.
"""
import json
import os
import time
import uuid

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

    if not isinstance(duration_minutes, int) or not (0 < duration_minutes <= MAX_DURATION_MINUTES):
        return _response(
            400,
            {"message": f"'durationMinutes' must be a whole number between 1 and {MAX_DURATION_MINUTES}"},
        )

    request_id = str(uuid.uuid4())
    now_epoch = int(time.time())

    try:
        table.put_item(
            Item={
                "requestId": request_id,
                "requesterId": requester_id,
                "requesterEmail": requester_email,
                "permission": permission,
                "reason": reason,
                "durationMinutes": duration_minutes,
                "status": "pending",
                "requestedAt": str(now_epoch),
            },
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
