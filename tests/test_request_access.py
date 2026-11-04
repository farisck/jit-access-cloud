import importlib.util
import json
import os
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch


class RequestAccessTests(unittest.TestCase):
    def setUp(self):
        self.table = Mock()
        self.sns = Mock()

        boto3 = types.ModuleType("boto3")
        boto3.resource = Mock(return_value=Mock(Table=Mock(return_value=self.table)))
        boto3.client = Mock(return_value=self.sns)

        app_path = (
            Path(__file__).resolve().parents[1]
            / "lambda"
            / "request_access"
            / "app.py"
        )
        spec = importlib.util.spec_from_file_location("request_access_app", app_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)

        self.app = importlib.util.module_from_spec(spec)
        with (
            patch.dict(
                os.environ,
                {
                    "REQUESTS_TABLE_NAME": "requests",
                    "NOTIFICATIONS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:alerts",
                    "MAX_DURATION_MINUTES": "480",
                    "PERMISSION_CATALOG_KEYS": '["s3-read-demo-bucket"]',
                },
            ),
            patch.dict(sys.modules, {"boto3": boto3}),
        ):
            spec.loader.exec_module(self.app)

    @staticmethod
    def make_event(body=None, claims=None):
        if claims is None:
            claims = {"sub": "user-123", "email": "user@example.com"}
        return {
            "requestContext": {"authorizer": {"jwt": {"claims": claims}}},
            "body": body,
        }

    @staticmethod
    def response_body(response):
        return json.loads(response["body"])

    def test_valid_request_is_stored_and_notified(self):
        response = self.app.handler(
            self.make_event(
                json.dumps(
                    {
                        "permission": "s3-read-demo-bucket",
                        "reason": "Investigate production issue",
                        "durationMinutes": 60,
                    }
                ),
            ),
            None,
        )

        self.assertEqual(response["statusCode"], 200)
        result = self.response_body(response)
        self.assertEqual(result["status"], "pending")
        self.assertTrue(result["requestId"])

        item = self.table.put_item.call_args.kwargs["Item"]
        self.assertEqual(item["requestId"], result["requestId"])
        self.assertEqual(item["requesterId"], "user-123")
        self.assertEqual(item["requesterEmail"], "user@example.com")
        self.assertEqual(item["permission"], "s3-read-demo-bucket")
        self.assertEqual(item["reason"], "Investigate production issue")
        self.assertEqual(item["durationMinutes"], 60)
        self.assertEqual(item["status"], "pending")
        self.assertEqual(
            self.table.put_item.call_args.kwargs["ConditionExpression"],
            "attribute_not_exists(requestId)",
        )
        self.sns.publish.assert_called_once()

    def test_missing_authorization_returns_401(self):
        response = self.app.handler({"requestContext": {}, "body": "{}"}, None)

        self.assertEqual(response["statusCode"], 401)
        self.table.put_item.assert_not_called()

    def test_invalid_json_returns_400(self):
        response = self.app.handler(self.make_event("{"), None)

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(
            self.response_body(response)["message"],
            "Request body must be valid JSON",
        )
        self.table.put_item.assert_not_called()

    def test_unknown_permission_returns_400(self):
        response = self.app.handler(
            self.make_event(
                json.dumps(
                    {
                        "permission": "admin",
                        "reason": "Need access",
                        "durationMinutes": 60,
                    }
                ),
            ),
            None,
        )

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(
            self.response_body(response)["message"],
            "Unknown permission requested",
        )
        self.table.put_item.assert_not_called()

    def test_missing_or_oversized_reason_returns_400(self):
        for reason in (" ", "x" * 501):
            with self.subTest(reason_length=len(reason)):
                response = self.app.handler(
                    self.make_event(
                        json.dumps(
                            {
                                "permission": "s3-read-demo-bucket",
                                "reason": reason,
                                "durationMinutes": 60,
                            }
                        ),
                    ),
                    None,
                )

                self.assertEqual(response["statusCode"], 400)
                self.table.put_item.assert_not_called()

    def test_invalid_duration_returns_400(self):
        for duration in (None, 0, 481, "60"):
            with self.subTest(duration=duration):
                response = self.app.handler(
                    self.make_event(
                        json.dumps(
                            {
                                "permission": "s3-read-demo-bucket",
                                "reason": "Need access",
                                "durationMinutes": duration,
                            }
                        ),
                    ),
                    None,
                )

                self.assertEqual(response["statusCode"], 400)
                self.table.put_item.assert_not_called()

    def test_database_failure_returns_500(self):
        self.table.put_item.side_effect = RuntimeError("DynamoDB unavailable")

        response = self.app.handler(
            self.make_event(
                json.dumps(
                    {
                        "permission": "s3-read-demo-bucket",
                        "reason": "Need access",
                        "durationMinutes": 60,
                    }
                ),
            ),
            None,
        )

        self.assertEqual(response["statusCode"], 500)
        self.assertEqual(
            self.response_body(response)["message"],
            "Could not create the request",
        )
        self.sns.publish.assert_not_called()

    def test_notification_failure_does_not_fail_request(self):
        self.sns.publish.side_effect = RuntimeError("SNS unavailable")

        response = self.app.handler(
            self.make_event(
                json.dumps(
                    {
                        "permission": "s3-read-demo-bucket",
                        "reason": "Need access",
                        "durationMinutes": 60,
                    }
                ),
            ),
            None,
        )

        self.assertEqual(response["statusCode"], 200)
        self.table.put_item.assert_called_once()


    @staticmethod
    def make_window(start, end):
        return {
            "permission": "s3-read-demo-bucket",
            "reason": "Test time-limited access",
            "accessStartAt": start.isoformat(),
            "accessEndAt": end.isoformat(),
        }

    def test_valid_future_access_window_is_stored(self):
        start = datetime.now(timezone.utc) + timedelta(minutes=10)
        end = start + timedelta(minutes=60)

        response = self.app.handler(
            self.make_event(json.dumps(self.make_window(start, end))),
            None,
        )

        self.assertEqual(response["statusCode"], 200)
        item = self.table.put_item.call_args.kwargs["Item"]
        self.assertEqual(item["durationMinutes"], 60)
        self.assertEqual(int(item["accessStartAt"]), int(start.timestamp()))
        self.assertEqual(int(item["accessEndAt"]), int(end.timestamp()))

    def test_overnight_access_window_is_valid(self):
        local_tz = timezone(timedelta(hours=5, minutes=30))
        tomorrow = datetime.now(local_tz).date() + timedelta(days=1)

        start = datetime(
            tomorrow.year,
            tomorrow.month,
            tomorrow.day,
            23,
            30,
            tzinfo=local_tz,
        )
        end = start + timedelta(hours=1)

        response = self.app.handler(
            self.make_event(json.dumps(self.make_window(start, end))),
            None,
        )

        self.assertEqual(response["statusCode"], 200)
        item = self.table.put_item.call_args.kwargs["Item"]
        self.assertEqual(item["durationMinutes"], 60)

    def test_past_access_start_returns_400(self):
        start = datetime.now(timezone.utc) - timedelta(minutes=5)
        end = start + timedelta(minutes=30)

        response = self.app.handler(
            self.make_event(json.dumps(self.make_window(start, end))),
            None,
        )

        self.assertEqual(response["statusCode"], 400)
        self.table.put_item.assert_not_called()

    def test_end_before_start_returns_400(self):
        start = datetime.now(timezone.utc) + timedelta(hours=2)
        end = start - timedelta(minutes=30)

        response = self.app.handler(
            self.make_event(json.dumps(self.make_window(start, end))),
            None,
        )

        self.assertEqual(response["statusCode"], 400)
        self.table.put_item.assert_not_called()

    def test_access_window_over_eight_hours_returns_400(self):
        start = datetime.now(timezone.utc) + timedelta(minutes=10)
        end = start + timedelta(minutes=481)

        response = self.app.handler(
            self.make_event(json.dumps(self.make_window(start, end))),
            None,
        )

        self.assertEqual(response["statusCode"], 400)
        self.table.put_item.assert_not_called()

    def test_missing_or_malformed_access_timestamps_return_400(self):
        start = datetime.now(timezone.utc) + timedelta(minutes=10)
        end = start + timedelta(minutes=60)

        payloads = [
            {
                "permission": "s3-read-demo-bucket",
                "reason": "Test access",
            },
            {
                **self.make_window(start, end),
                "accessStartAt": "not-a-timestamp",
            },
            {
                **self.make_window(start, end),
                "accessEndAt": "not-a-timestamp",
            },
        ]

        for payload in payloads:
            with self.subTest(payload=payload):
                response = self.app.handler(
                    self.make_event(json.dumps(payload)),
                    None,
                )

                self.assertEqual(response["statusCode"], 400)
                self.table.put_item.assert_not_called()


if __name__ == "__main__":
    unittest.main()
