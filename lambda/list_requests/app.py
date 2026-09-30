"""
list_requests

API Gateway-triggered (GET /requests), behind the Cognito JWT authorizer.

  GET /requests               -> the caller's own requests, any status,
                                  newest first (uses requester-index)
  GET /requests?status=pending -> requests in a given status, newest first
                                  (uses status-index). Any caller can view
                                  this - it's a request queue, not a secret
                                  - but only approvers can act on it via
                                  approve_access, which checks separately.

Pagination: ?limit=20 (default 20, capped 50), ?cursor=<value> from a
previous response's "nextCursor".

This function's IAM role only has dynamodb:Query on this table and its
two indexes.
"""
import base64
import json
import os
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key

dynamodb = boto3.resource("dynamodb")

TABLE_NAME = os.environ["REQUESTS_TABLE_NAME"]
REQUESTER_INDEX_NAME = os.environ.get("REQUESTER_INDEX_NAME", "requester-index")
STATUS_INDEX_NAME = os.environ.get("STATUS_INDEX_NAME", "status-index")
DEFAULT_LIMIT = 20
MAX_LIMIT = 50

table = dynamodb.Table(TABLE_NAME)


def _decimal_default(obj):
    if isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def _response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
        "body": json.dumps(body, default=_decimal_default),
    }


def _encode_cursor(key):
    if not key:
        return None
    return base64.urlsafe_b64encode(json.dumps(key, default=_decimal_default).encode()).decode()


def _decode_cursor(cursor):
    if not cursor:
        return None
    try:
        return json.loads(base64.urlsafe_b64decode(cursor.encode()))
    except Exception:  # noqa: BLE001
        return None


def handler(event, context):
    try:
        claims = event["requestContext"]["authorizer"]["jwt"]["claims"]
        caller_id = claims["sub"]
    except (KeyError, TypeError):
        return _response(401, {"message": "Missing or invalid authorization token"})

    params = event.get("queryStringParameters") or {}
    status_filter = params.get("status")

    try:
        limit = min(int(params.get("limit", DEFAULT_LIMIT)), MAX_LIMIT)
        if limit < 1:
            limit = DEFAULT_LIMIT
    except (TypeError, ValueError):
        limit = DEFAULT_LIMIT

    exclusive_start_key = _decode_cursor(params.get("cursor"))
    query_kwargs = {"Limit": limit, "ScanIndexForward": False}
    if exclusive_start_key:
        query_kwargs["ExclusiveStartKey"] = exclusive_start_key

    if status_filter:
        query_kwargs["IndexName"] = STATUS_INDEX_NAME
        query_kwargs["KeyConditionExpression"] = Key("status").eq(status_filter)
        mode = f"status:{status_filter}"
    else:
        query_kwargs["IndexName"] = REQUESTER_INDEX_NAME
        query_kwargs["KeyConditionExpression"] = Key("requesterId").eq(caller_id)
        mode = "mine"

    try:
        result = table.query(**query_kwargs)
    except Exception as exc:  # noqa: BLE001
        print(f"DynamoDB query failed: {exc}")
        return _response(500, {"message": "Could not list requests"})

    requests = [
        {
            "requestId": i.get("requestId"),
            "requesterEmail": i.get("requesterEmail"),
            "permission": i.get("permission"),
            "reason": i.get("reason"),
            "durationMinutes": i.get("durationMinutes"),
            "status": i.get("status"),
            "requestedAt": i.get("requestedAt"),
            "decidedBy": i.get("decidedBy"),
            "expiresAt": i.get("expiresAt"),
            "revokedAt": i.get("revokedAt"),
        }
        for i in result.get("Items", [])
    ]

    return _response(200, {"mode": mode, "requests": requests, "nextCursor": _encode_cursor(result.get("LastEvaluatedKey"))})
