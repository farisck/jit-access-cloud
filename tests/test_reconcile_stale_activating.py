import importlib.util
import os
import time
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

app_path = os.path.join(
    os.path.dirname(__file__),
    "..",
    "lambda",
    "reconcile_cleanup",
    "app.py",
)
spec = importlib.util.spec_from_file_location(
    "reconcile_cleanup_stale_app", app_path
)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


def conditional_failure():
    return ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException"}},
        "UpdateItem",
    )


class StaleActivatingRecoveryTests(unittest.TestCase):
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

    def activating_item(self, drop=(), **overrides):
        now = int(time.time())
        item = {
            "requestId": "req-123",
            "status": "activating",
            "activationClaimedAt": str(now - 900),
            "activationDeadline": str(now - 600),
            "revocationIntentTarget": "revoked_early",
            "policyName": "jit-grant-req-123",
        }
        item.update(overrides)
        for key in drop:
            item.pop(key, None)
        return item

    def reconcile(self, item):
        self.table.get_item.return_value = {"Item": item}
        return app._reconcile_one("req-123", int(time.time()))

    def test_recovers_saved_manual_revocation_intent(self):
        item = self.activating_item(revocationIntentTarget="revoked_early")

        outcome = self.reconcile(item)

        self.assertEqual(outcome, "recovered")
        self.table.get_item.assert_called_once_with(
            Key={"requestId": "req-123"}, ConsistentRead=True
        )
        self.table.update_item.assert_called_once()
        kwargs = self.table.update_item.call_args.kwargs
        values = kwargs["ExpressionAttributeValues"]
        self.assertEqual(values[":target"], "revoked_early")
        self.assertEqual(values[":pending"], "cleanup_pending")
        self.assertEqual(values[":activating"], "activating")
        self.assertEqual(values[":not_before"], item["activationDeadline"])
        # The condition must pin the saved intent, not just the status.
        self.assertIn(
            "revocationIntentTarget",
            kwargs["ExpressionAttributeNames"].values(),
        )
        # Recovery only changes state; cleanup stays on the normal protocol.
        self.iam.delete_role_policy.assert_not_called()

    def test_recovers_saved_scheduled_expiry_intent(self):
        item = self.activating_item(revocationIntentTarget="expired")

        outcome = self.reconcile(item)

        self.assertEqual(outcome, "recovered")
        values = self.table.update_item.call_args.kwargs[
            "ExpressionAttributeValues"
        ]
        self.assertEqual(values[":target"], "expired")

    def test_missing_intent_is_not_guessed(self):
        item = self.activating_item(drop=("revocationIntentTarget",))

        outcome = self.reconcile(item)

        self.assertEqual(outcome, "unrecoverable")
        self.table.update_item.assert_not_called()
        self.iam.delete_role_policy.assert_not_called()

    def test_invalid_intent_is_not_guessed(self):
        for bad in ("approved", "", None, "active", 5):
            with self.subTest(intent=bad):
                self.table.update_item.reset_mock()
                item = self.activating_item(revocationIntentTarget=bad)

                outcome = self.reconcile(item)

                self.assertEqual(outcome, "unrecoverable")
                self.table.update_item.assert_not_called()

    def test_deadline_not_passed_is_not_recovered(self):
        future = str(int(time.time()) + 300)
        item = self.activating_item(activationDeadline=future)

        outcome = self.reconcile(item)

        self.assertEqual(outcome, "waiting")
        self.table.update_item.assert_not_called()

    def test_missing_or_invalid_deadline_is_not_recovered(self):
        for bad in (None, "", "soon"):
            with self.subTest(deadline=bad):
                self.table.update_item.reset_mock()
                item = self.activating_item(activationDeadline=bad)

                outcome = self.reconcile(item)

                self.assertEqual(outcome, "unrecoverable")
                self.table.update_item.assert_not_called()

        item = self.activating_item(drop=("activationDeadline",))
        self.assertEqual(self.reconcile(item), "unrecoverable")
        self.table.update_item.assert_not_called()

    def test_concurrent_state_change_is_not_overwritten(self):
        self.table.update_item.side_effect = conditional_failure()
        item = self.activating_item()

        outcome = self.reconcile(item)

        self.assertEqual(outcome, "skipped")
        self.table.update_item.assert_called_once()
        self.iam.delete_role_policy.assert_not_called()

    def test_stale_index_result_that_is_now_active_is_skipped(self):
        item = self.activating_item(status="active")

        outcome = self.reconcile(item)

        self.assertEqual(outcome, "skipped")
        self.table.update_item.assert_not_called()


if __name__ == "__main__":
    unittest.main()