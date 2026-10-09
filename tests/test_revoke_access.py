import importlib.util
import json
import os
import unittest
from unittest.mock import Mock

from botocore.exceptions import ClientError


# Set environment variables before importing the Lambda.
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
os.environ["REQUESTS_TABLE_NAME"] = "ci-test-table"
os.environ["NOTIFICATIONS_TOPIC_ARN"] = (
    "arn:aws:sns:us-east-1:000000000000:ci-test-topic"
)
os.environ["TARGET_ROLE_NAME"] = "ci-test-target-role"

# Load this Lambda's app.py explicitly.
app_path = os.path.join(
    os.path.dirname(__file__),
    "..",
    "lambda",
    "revoke_access",
    "app.py",
)
spec = importlib.util.spec_from_file_location(
    "revoke_access_app", app_path
)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class RevokeAccessTests(unittest.TestCase):
    def setUp(self):
        self.table = Mock()
        self.iam = Mock()
        self.iam.exceptions.NoSuchEntityException = type(
            "NoSuchEntityException", (Exception,), {}
        )
        self.scheduler_sns = Mock()

        self.original_table = app.table
        self.original_iam = app.iam
        self.original_sns = app.sns

        app.table = self.table
        app.iam = self.iam
        app.sns = self.scheduler_sns

    def tearDown(self):
        app.table = self.original_table
        app.iam = self.original_iam
        app.sns = self.original_sns

    def make_active_item(self, **overrides):
        item = {
            "requestId": "req-123",
            "requesterId": "employee-123",
            "status": "active",
            "policyName": "jit-grant-req-123",
        }
        item.update(overrides)
        return item

    def test_missing_request_id_raises_error(self):
        with self.assertRaises(ValueError):
            app.handler({"reason": "scheduled_expiry"}, None)

    def test_missing_request_is_noop(self):
        self.table.get_item.return_value = {}

        result = app.handler(
            {"requestId": "req-123"}, None
        )

        self.assertEqual(result["status"], "not_found")
        self.iam.delete_role_policy.assert_not_called()
        self.table.update_item.assert_not_called()

    def test_already_revoked_request_is_noop(self):
        self.table.get_item.return_value = {
            "Item": self.make_active_item(status="revoked")
        }

        result = app.handler(
            {"requestId": "req-123"}, None
        )

        self.assertEqual(result["status"], "revoked")
        self.iam.delete_role_policy.assert_not_called()
        self.table.update_item.assert_not_called()

    def test_scheduled_expiry_removes_policy_and_marks_expired(self):
        self.table.get_item.return_value = {
            "Item": self.make_active_item()
        }

        result = app.handler(
            {
                "requestId": "req-123",
                "reason": "scheduled_expiry",
            },
            None,
        )

        self.assertEqual(result["status"], "expired")
        self.iam.delete_role_policy.assert_called_once_with(
            RoleName="ci-test-target-role",
            PolicyName="jit-grant-req-123",
        )
        self.table.update_item.assert_called_once()

        update_values = (
            self.table.update_item.call_args.kwargs[
                "ExpressionAttributeValues"
            ]
        )
        self.assertEqual(update_values[":status"], "expired")
        self.scheduler_sns.publish.assert_called_once()

    def test_manual_revoke_marks_request_revoked_early(self):
        self.table.get_item.return_value = {
            "Item": self.make_active_item()
        }

        event = {
            "requestContext": {
                "http": {"method": "DELETE"},
                "authorizer": {
                    "jwt": {
                        "claims": {
                            "sub": "employee-123",
                            "email": "employee@example.com",
                            "cognito:groups": "[]",
                        }
                    }
                },
            },
            "pathParameters": {"requestId": "req-123"},
        }

        response = app.handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(
            json.loads(response["body"])["status"],
            "revoked_early",
        )
        self.iam.delete_role_policy.assert_called_once()
        self.scheduler_sns.publish.assert_called_once()

    def test_iam_failure_is_recorded_alerted_and_reraised(self):
        self.table.get_item.return_value = {
            "Item": self.make_active_item()
        }

        self.iam.delete_role_policy.side_effect = ClientError(
            {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": "Simulated IAM permission error",
                }
            },
            "DeleteRolePolicy",
        )

        with self.assertRaises(ClientError):
            app.handler(
                {"requestId": "req-123"}, None
            )

        self.table.update_item.assert_called_once()
        update_values = (
            self.table.update_item.call_args.kwargs[
                "ExpressionAttributeValues"
            ]
        )
        self.assertEqual(
            update_values[":status"], "revoke_failed"
        )
        self.scheduler_sns.publish.assert_called_once()

    def test_sns_failure_does_not_fail_successful_revoke(self):
        self.table.get_item.return_value = {
            "Item": self.make_active_item()
        }
        self.scheduler_sns.publish.side_effect = ClientError(
            {
                "Error": {
                    "Code": "InternalError",
                    "Message": "Simulated SNS failure",
                }
            },
            "Publish",
        )

        result = app.handler(
            {
                "requestId": "req-123",
                "reason": "scheduled_expiry",
            },
            None,
        )

        self.assertEqual(result["status"], "expired")
        self.iam.delete_role_policy.assert_called_once()
        self.table.update_item.assert_called_once()

    def test_non_owner_non_approver_returns_403(self):
        self.table.get_item.return_value = {
            "Item": {
                "requestId": "req-123",
                "requesterId": "another-user",
                "status": "active",
            }
        }

        event = {
            "requestContext": {
                "http": {"method": "DELETE"},
                "authorizer": {
                    "jwt": {
                        "claims": {
                            "sub": "user-123",
                            "email": "user@example.com",
                            "cognito:groups": "employees",
                        }
                    }
                },
            },
            "pathParameters": {"requestId": "req-123"},
        }

        response = app.handler(event, None)

        self.assertEqual(response["statusCode"], 403)

    def test_api_request_not_found_returns_404(self):
        self.table.get_item.return_value = {}

        event = {
            "requestContext": {
                "http": {"method": "DELETE"},
                "authorizer": {
                    "jwt": {
                        "claims": {"sub": "user-123"}
                    }
                },
            },
            "pathParameters": {"requestId": "req-123"},
        }

        response = app.handler(event, None)

        self.assertEqual(response["statusCode"], 404)

    def test_api_missing_request_id_returns_400(self):
        event = {
            "requestContext": {
                "http": {"method": "DELETE"},
                "authorizer": {
                    "jwt": {
                        "claims": {"sub": "user-123"}
                    }
                },
            },
            "pathParameters": {},
        }

        response = app.handler(event, None)

        self.assertEqual(response["statusCode"], 400)

    def test_api_missing_authorization_returns_401(self):
        event = {
            "requestContext": {
                "http": {"method": "DELETE"},
            },
            "pathParameters": {"requestId": "req-123"},
        }

        response = app.handler(event, None)

        self.assertEqual(response["statusCode"], 401)

    def test_missing_policy_is_treated_as_success(self):
        self.table.get_item.return_value = {
            "Item": {
                "requestId": "req-123",
                "status": "active",
                "policyName": "jit-grant-req-123",
            }
        }

        self.iam.delete_role_policy.side_effect = (
            self.iam.exceptions.NoSuchEntityException()
        )

        result = app._revoke(
            "req-123",
            reason="scheduled_expiry",
            actor=None,
        )

        self.assertEqual(result["status"], "expired")
        self.table.update_item.assert_called_once()
