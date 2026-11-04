
import importlib.util
import json
import os
import unittest
from unittest.mock import Mock

from botocore.exceptions import ClientError


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
        self.table.get_item.assert_called_once_with(
            Key={"requestId": "req-123"}, ConsistentRead=True
        )
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

        self.assertEqual(self.table.update_item.call_count, 2)
        claim_kwargs = self.table.update_item.call_args_list[0].kwargs
        self.assertEqual(
            claim_kwargs["ExpressionAttributeValues"][":activating"],
            "activating",
        )
        completion_kwargs = self.table.update_item.call_args_list[1].kwargs
        self.assertEqual(
            completion_kwargs["ConditionExpression"], "#s = :activating"
        )
        self.assertEqual(
            completion_kwargs["ExpressionAttributeValues"][":active"], "active"
        )
        self.sns.publish.assert_called_once()

    def test_early_revoke_during_activation_removes_granted_policy(self):
        import time

        now = int(time.time())
        end = now + 1800
        from botocore.exceptions import ClientError

        conditional_failure = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException"}},
            "UpdateItem",
        )
        self.table.update_item.side_effect = [{}, conditional_failure]
        self.table.get_item.side_effect = [
            {"Item": {
                "requestId": "req-123",
                "status": "scheduled",
                "permission": "s3-read-demo-bucket",
                "accessStartAt": str(now - 60),
                "accessEndAt": str(end),
            }},
            {"Item": {
                "requestId": "req-123",
                "status": "revoked_early",
                "permission": "s3-read-demo-bucket",
                "accessStartAt": str(now - 60),
                "accessEndAt": str(end),
            }},
        ]

        result = app.handler({"requestId": "req-123"}, None)

        # This exposes whether activation overwrites the revoke decision.
        self.assertEqual(result["status"], "revoked_early")
        self.iam.delete_role_policy.assert_called_once_with(
            RoleName="ci-test-target-role",
            PolicyName="jit-grant-req-123",
        )
        self.assertEqual(self.table.update_item.call_count, 2)

    def test_expiry_during_activation_does_not_leave_policy_attached(self):
        import time

        now = int(time.time())
        end = now + 1800
        from botocore.exceptions import ClientError

        conditional_failure = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException"}},
            "UpdateItem",
        )
        self.table.update_item.side_effect = [{}, conditional_failure]
        self.table.get_item.side_effect = [
            {"Item": {
                "requestId": "req-123",
                "status": "scheduled",
                "permission": "s3-read-demo-bucket",
                "accessStartAt": str(now - 60),
                "accessEndAt": str(end),
            }},
            {"Item": {
                "requestId": "req-123",
                "status": "expired",
                "permission": "s3-read-demo-bucket",
                "accessStartAt": str(now - 60),
                "accessEndAt": str(end),
            }},
        ]

        result = app.handler({"requestId": "req-123"}, None)

        self.assertEqual(result["status"], "expired")
        self.iam.delete_role_policy.assert_called_once_with(
            RoleName="ci-test-target-role",
            PolicyName="jit-grant-req-123",
        )

    def test_missing_access_window_raises_value_error(self):
        self.table.get_item.return_value = {
            "Item": {
                "requestId": "req-123",
                "status": "scheduled",
                "permission": "s3-read-demo-bucket",
            }
        }

        with self.assertRaisesRegex(ValueError, "invalid access window"):
            app.handler({"requestId": "req-123"}, None)

        self.iam.put_role_policy.assert_not_called()

    def test_malformed_access_start_raises_value_error(self):
        self.table.get_item.return_value = {
            "Item": {
                "requestId": "req-123",
                "status": "scheduled",
                "permission": "s3-read-demo-bucket",
                "accessStartAt": "not-a-timestamp",
                "accessEndAt": "9999999999",
            }
        }

        with self.assertRaisesRegex(ValueError, "invalid access window"):
            app.handler({"requestId": "req-123"}, None)

        self.iam.put_role_policy.assert_not_called()

    def test_unknown_permission_does_not_grant_access(self):
        import time

        now = int(time.time())
        self.table.get_item.return_value = {
            "Item": {
                "requestId": "req-123",
                "status": "scheduled",
                "permission": "unknown-permission",
                "accessStartAt": str(now - 60),
                "accessEndAt": str(now + 1800),
            }
        }

        with self.assertRaisesRegex(ValueError, "No policy template"):
            app.handler({"requestId": "req-123"}, None)

        self.iam.put_role_policy.assert_not_called()
        self.table.update_item.assert_not_called()

    def test_conditional_claim_failure_returns_current_status(self):
        error = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException"}},
            "UpdateItem",
        )
        self.table.get_item.side_effect = [
            {
                "Item": {
                    "requestId": "req-123",
                    "status": "scheduled",
                    "permission": "s3-read-demo-bucket",
                    "accessStartAt": "1",
                    "accessEndAt": "9999999999",
                }
            },
            {
                "Item": {
                    "requestId": "req-123",
                    "status": "revoked_early",
                }
            },
        ]
        self.table.update_item.side_effect = error

        result = app.handler({"requestId": "req-123"}, None)

        self.assertEqual(result["status"], "revoked_early")
        self.iam.put_role_policy.assert_not_called()

    def test_conditional_expiry_failure_returns_current_status(self):
        error = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException"}},
            "UpdateItem",
        )
        self.table.get_item.side_effect = [
            {
                "Item": {
                    "requestId": "req-123",
                    "status": "scheduled",
                    "permission": "s3-read-demo-bucket",
                    "accessStartAt": "1",
                    "accessEndAt": "2",
                }
            },
            {
                "Item": {
                    "requestId": "req-123",
                    "status": "expired",
                }
            },
        ]
        self.table.update_item.side_effect = error

        result = app.handler({"requestId": "req-123"}, None)

        self.assertEqual(result["status"], "expired")
        self.iam.put_role_policy.assert_not_called()

    def test_unexpected_dynamodb_error_propagates(self):
        error = ClientError(
            {"Error": {"Code": "ProvisionedThroughputExceededException"}},
            "UpdateItem",
        )
        self.table.get_item.return_value = {
            "Item": {
                "requestId": "req-123",
                "status": "scheduled",
                "permission": "s3-read-demo-bucket",
                "accessStartAt": "1",
                "accessEndAt": "9999999999",
            }
        }
        self.table.update_item.side_effect = error

        with self.assertRaises(ClientError) as raised:
            app.handler({"requestId": "req-123"}, None)

        self.assertIs(raised.exception, error)
        self.iam.put_role_policy.assert_not_called()

    def test_unexpected_iam_cleanup_error_is_raised(self):
        conditional_failure = ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException"}},
            "UpdateItem",
        )
        cleanup_error = ClientError(
            {"Error": {"Code": "AccessDenied"}},
            "DeleteRolePolicy",
        )
        self.table.get_item.side_effect = [
            {
                "Item": {
                    "requestId": "req-123",
                    "status": "scheduled",
                    "permission": "s3-read-demo-bucket",
                    "accessStartAt": "1",
                    "accessEndAt": "9999999999",
                }
            },
            {
                "Item": {
                    "requestId": "req-123",
                    "status": "revoked_early",
                }
            },
        ]
        self.table.update_item.side_effect = [{}, conditional_failure]
        self.iam.delete_role_policy.side_effect = cleanup_error

        with self.assertRaises(ClientError) as raised:
            app.handler({"requestId": "req-123"}, None)

        self.assertIs(raised.exception, cleanup_error)
        self.iam.delete_role_policy.assert_called_once_with(
            RoleName="ci-test-target-role",
            PolicyName="jit-grant-req-123",
        )

    def _window_item(self, now, end):
        return {
            "Item": {
                "requestId": "req-123",
                "status": "scheduled",
                "permission": "s3-read-demo-bucket",
                "accessStartAt": str(now - 60),
                "accessEndAt": str(end),
            }
        }

    def test_granted_policy_expires_at_approved_end_time(self):
        import time

        now = int(time.time())
        end = now + 1800
        self.table.get_item.return_value = self._window_item(now, end)
        catalog_before = json.dumps(app.PERMISSION_CATALOG, sort_keys=True)

        result = app.handler({"requestId": "req-123"}, None)

        self.assertEqual(result["status"], "active")
        kwargs = self.iam.put_role_policy.call_args.kwargs
        statement = json.loads(kwargs["PolicyDocument"])["Statement"][0]
        expected_end = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end))
        self.assertEqual(
            statement["Condition"],
            {"DateLessThan": {"aws:CurrentTime": expected_end}},
        )
        self.assertEqual(statement["Action"], ["s3:GetObject"])
        self.assertEqual(statement["Resource"], "arn:aws:s3:::demo-bucket/*")
        # The shared catalog must never be modified by a grant.
        self.assertEqual(
            json.dumps(app.PERMISSION_CATALOG, sort_keys=True),
            catalog_before,
        )

    def test_catalog_condition_is_preserved_when_adding_time_limit(self):
        import time

        now = int(time.time())
        end = now + 1800
        self.table.get_item.return_value = self._window_item(now, end)
        original = app.PERMISSION_CATALOG
        app.PERMISSION_CATALOG = {
            "s3-read-demo-bucket": {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::demo-bucket/*",
                "Condition": {"Bool": {"aws:SecureTransport": "true"}},
            }
        }
        try:
            app.handler({"requestId": "req-123"}, None)
        finally:
            app.PERMISSION_CATALOG = original

        kwargs = self.iam.put_role_policy.call_args.kwargs
        statement = json.loads(kwargs["PolicyDocument"])["Statement"][0]
        self.assertEqual(
            statement["Condition"]["Bool"], {"aws:SecureTransport": "true"}
        )
        self.assertIn("DateLessThan", statement["Condition"])

    def test_claim_records_activation_deadline(self):
        import time

        now = int(time.time())
        self.table.get_item.return_value = self._window_item(now, now + 1800)
        context = Mock()
        context.get_remaining_time_in_millis.return_value = 15000

        app.handler({"requestId": "req-123"}, context)

        claim_kwargs = self.table.update_item.call_args_list[0].kwargs
        values = claim_kwargs["ExpressionAttributeValues"]
        claimed = int(values[":claimed"])
        deadline = int(values[":deadline"])
        self.assertGreaterEqual(claimed, now)
        self.assertEqual(
            deadline - claimed,
            15 + app.ACTIVATION_SAFETY_MARGIN_SECONDS,
        )

    def test_catalog_entry_with_own_time_limit_is_refused(self):
        import time

        now = int(time.time())
        self.table.get_item.return_value = self._window_item(now, now + 1800)
        original = app.PERMISSION_CATALOG
        app.PERMISSION_CATALOG = {
            "s3-read-demo-bucket": {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::demo-bucket/*",
                "Condition": {
                    "DateLessThan": {"aws:CurrentTime": "2030-01-01T00:00:00Z"}
                },
            }
        }
        try:
            with self.assertRaisesRegex(ValueError, "already limits"):
                app.handler({"requestId": "req-123"}, None)
        finally:
            app.PERMISSION_CATALOG = original

        # Fails closed before claiming: nothing is written and nothing granted.
        self.iam.put_role_policy.assert_not_called()
        self.table.update_item.assert_not_called()

    def test_unexpected_active_state_write_error_preserves_policy_and_propagates(
        self,
    ):
        import time

        now = int(time.time())
        self.table.get_item.return_value = self._window_item(now, now + 1800)
        state_error = ClientError(
            {"Error": {"Code": "ProvisionedThroughputExceededException"}},
            "UpdateItem",
        )
        # The first update claims activation; the second fails when saving
        # the active status after IAM has attached the policy.
        self.table.update_item.side_effect = [{}, state_error]

        with self.assertRaises(ClientError) as raised:
            app.handler({"requestId": "req-123"}, None)

        self.assertIs(raised.exception, state_error)
        self.iam.put_role_policy.assert_called_once()
        self.iam.delete_role_policy.assert_not_called()

    def test_failed_put_leaves_request_activating_for_cleanup(self):
        import time

        now = int(time.time())
        self.table.get_item.return_value = self._window_item(now, now + 1800)
        put_error = ClientError(
            {"Error": {"Code": "AccessDenied"}},
            "PutRolePolicy",
        )
        self.iam.put_role_policy.side_effect = put_error

        with self.assertRaises(ClientError) as raised:
            app.handler({"requestId": "req-123"}, None)

        self.assertIs(raised.exception, put_error)
        # Only the claim was written; no terminal state was invented, so the
        # reconciler can resolve the stale "activating" request later.
        self.assertEqual(self.table.update_item.call_count, 1)
        self.iam.delete_role_policy.assert_not_called()


if __name__ == "__main__":
    unittest.main()
