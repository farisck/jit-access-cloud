
import importlib.util
import json
import os
import unittest
from unittest.mock import Mock


os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
os.environ["REQUESTS_TABLE_NAME"] = "ci-test-table"
os.environ["NOTIFICATIONS_TOPIC_ARN"] = (
    "arn:aws:sns:us-east-1:000000000000:ci-test-topic"
)
os.environ["TARGET_ROLE_NAME"] = "ci-test-target-role"
os.environ["PERMISSION_CATALOG"] = json.dumps({
    "s3-read-demo-bucket": {
        "Effect": "Allow",
        "Action": ["s3:GetObject"],
        "Resource": "arn:aws:s3:::demo-bucket/*",
    }
})

app_path = os.path.join(
    os.path.dirname(__file__),
    "..",
    "lambda",
    "activate_access",
    "app.py",
)

spec = importlib.util.spec_from_file_location(
    "activate_access_app", app_path
)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class ActivateAccessTests(unittest.TestCase):
    def setUp(self):
        self.table = Mock()
        self.iam = Mock()
        self.sns = Mock()

        self.original_table = app.table
        self.original_iam = app.iam
        self.original_sns = app.sns

        app.table = self.table
        app.iam = self.iam
        app.sns = self.sns

    def tearDown(self):
        app.table = self.original_table
        app.iam = self.original_iam
        app.sns = self.original_sns

    def test_missing_request_id_raises_error(self):
        with self.assertRaises(ValueError):
            app.handler({}, None)

    def test_missing_request_is_noop(self):
        self.table.get_item.return_value = {}

        result = app.handler({"requestId": "req-123"}, None)

        self.assertEqual(result["status"], "not_found")
        self.iam.put_role_policy.assert_not_called()

    def test_cancelled_request_is_not_activated(self):
        self.table.get_item.return_value = {
            "Item": {
                "requestId": "req-123",
                "status": "revoked_early",
                "permission": "s3-read-demo-bucket",
            }
        }

        result = app.handler({"requestId": "req-123"}, None)

        self.assertEqual(result["status"], "revoked_early")
        self.iam.put_role_policy.assert_not_called()
        self.table.update_item.assert_not_called()

    def test_early_invocation_does_not_grant_access(self):
        import time

        now = int(time.time())
        self.table.get_item.return_value = {
            "Item": {
                "requestId": "req-123",
                "status": "scheduled",
                "permission": "s3-read-demo-bucket",
                "accessStartAt": str(now + 600),
                "accessEndAt": str(now + 3600),
            }
        }

        with self.assertRaises(ValueError):
            app.handler({"requestId": "req-123"}, None)

        self.iam.put_role_policy.assert_not_called()

    def test_expired_window_does_not_grant_access(self):
        import time

        now = int(time.time())
        self.table.get_item.return_value = {
            "Item": {
                "requestId": "req-123",
                "status": "scheduled",
                "permission": "s3-read-demo-bucket",
                "accessStartAt": str(now - 3600),
                "accessEndAt": str(now - 60),
            }
        }

        result = app.handler({"requestId": "req-123"}, None)

        self.assertEqual(result["status"], "expired")
        self.iam.put_role_policy.assert_not_called()

    def test_valid_window_grants_catalog_policy(self):
        import time

        now = int(time.time())
        end = now + 1800
        self.table.get_item.return_value = {
            "Item": {
                "requestId": "req-123",
                "status": "scheduled",
                "permission": "s3-read-demo-bucket",
                "accessStartAt": str(now - 60),
                "accessEndAt": str(end),
            }
        }

        result = app.handler({"requestId": "req-123"}, None)

        self.assertEqual(result["status"], "active")
        self.iam.put_role_policy.assert_called_once()

        kwargs = self.iam.put_role_policy.call_args.kwargs
        self.assertEqual(kwargs["RoleName"], "ci-test-target-role")
        self.assertEqual(kwargs["PolicyName"], "jit-grant-req-123")

        policy = json.loads(kwargs["PolicyDocument"])
        self.assertEqual(
            policy["Statement"][0]["Action"],
            ["s3:GetObject"],
        )

        self.table.update_item.assert_called_once()
        values = self.table.update_item.call_args.kwargs[
            "ExpressionAttributeValues"
        ]
        self.assertEqual(values[":status"], "active")
        self.sns.publish.assert_called_once()


if __name__ == "__main__":
    unittest.main()
