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
    "reconcile_cleanup_alert_app", app_path
)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


def conditional_failure():
    return ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException"}},
        "UpdateItem",
    )


def throttled():
    return ClientError(
        {"Error": {"Code": "ProvisionedThroughputExceededException"}},
        "UpdateItem",
    )


class UnrecoverableAlertTests(unittest.TestCase):
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

    def stuck_item(self, drop=(), **overrides):
        """Activating, past its deadline, NO saved intent, window long over."""
        now = int(time.time())
        item = {
            "requestId": "req-123",
            "status": "activating",
            "activationDeadline": str(now - 600),
            "accessEndAt": str(now - 3600),
            "policyName": "jit-grant-req-123",
        }
        item.update(overrides)
        for key in drop:
            item.pop(key, None)
        return item

    def reconcile(self, item):
        self.table.get_item.return_value = {"Item": item}
        return app._reconcile_one("req-123", int(time.time()))

    def test_overdue_request_with_no_intent_alerts_once(self):
        outcome = self.reconcile(self.stuck_item())

        self.assertEqual(outcome, "unrecoverable")
        self.table.update_item.assert_called_once()
        kwargs = self.table.update_item.call_args.kwargs
        # One-time marker: only written if it is not already there, and
        # only while the request is still activating.
        self.assertIn("attribute_not_exists", kwargs["ConditionExpression"])
        self.assertIn("#s = :activating", kwargs["ConditionExpression"])
        # The alert write must never change the request's status.
        self.assertNotIn("#s", kwargs["UpdateExpression"])
        values = kwargs["ExpressionAttributeValues"]
        self.assertEqual(values[":activating"], "activating")
        self.assertNotIn(":pending", values)
        self.sns.publish.assert_called_once()
        self.iam.delete_role_policy.assert_not_called()

    def test_failed_sns_publish_attempts_to_clear_alert_marker(self):
        self.sns.publish.side_effect = ClientError(
            {"Error": {"Code": "InternalError", "Message": "SNS unavailable"}},
            "Publish",
        )

        outcome = self.reconcile(self.stuck_item())

        self.assertEqual(outcome, "unrecoverable")
        self.sns.publish.assert_called_once()
        # First update writes the marker; second conditionally removes it.
        self.assertEqual(self.table.update_item.call_count, 2)
        marker_write = self.table.update_item.call_args_list[0].kwargs
        cleanup_call = self.table.update_item.call_args_list[1]
        self.assertEqual(
            cleanup_call.kwargs["UpdateExpression"],
            "REMOVE unrecoverableAlertedAt",
        )
        self.assertIn(
            "unrecoverableAlertedAt = :marker",
            cleanup_call.kwargs["ConditionExpression"],
        )
        self.assertEqual(
            cleanup_call.kwargs["ExpressionAttributeValues"][":marker"],
            marker_write["ExpressionAttributeValues"][":now"],
        )

    def test_later_runs_stay_silent_after_the_first_alert(self):
        # The marker already exists, so the conditional write is refused.
        self.table.update_item.side_effect = conditional_failure()

        outcome = self.reconcile(self.stuck_item())

        self.assertEqual(outcome, "unrecoverable")
        self.sns.publish.assert_not_called()

    def test_failed_alert_write_sends_no_alert_and_does_not_crash(self):
        self.table.update_item.side_effect = throttled()

        outcome = self.reconcile(self.stuck_item())

        self.assertEqual(outcome, "unrecoverable")
        self.sns.publish.assert_not_called()

    def test_not_overdue_yet_is_logged_but_never_alerted(self):
        now = int(time.time())
        # Window ended a minute ago: still inside the 300 second grace
        # period, so the scheduled revoke may simply not have fired yet.
        for end in (now + 3600, now - 60):
            with self.subTest(access_end_at=end):
                self.table.update_item.reset_mock()
                self.sns.publish.reset_mock()
                item = self.stuck_item(accessEndAt=str(end))

                outcome = self.reconcile(item)

                self.assertEqual(outcome, "unrecoverable")
                self.table.update_item.assert_not_called()
                self.sns.publish.assert_not_called()

    def test_unknown_window_end_is_never_alerted(self):
        for bad in (None, "", "soon"):
            with self.subTest(access_end_at=bad):
                self.table.update_item.reset_mock()
                self.sns.publish.reset_mock()
                item = self.stuck_item(accessEndAt=bad)

                outcome = self.reconcile(item)

                self.assertEqual(outcome, "unrecoverable")
                self.table.update_item.assert_not_called()
                self.sns.publish.assert_not_called()

        outcome = self.reconcile(self.stuck_item(drop=("accessEndAt",)))
        self.assertEqual(outcome, "unrecoverable")
        self.table.update_item.assert_not_called()

    def test_invalid_deadline_that_is_overdue_also_alerts_once(self):
        outcome = self.reconcile(self.stuck_item(activationDeadline="soon"))

        self.assertEqual(outcome, "unrecoverable")
        self.table.update_item.assert_called_once()
        self.sns.publish.assert_called_once()

    def test_a_valid_saved_intent_is_recovered_not_alerted(self):
        item = self.stuck_item(revocationIntentTarget="expired")

        outcome = self.reconcile(item)

        self.assertEqual(outcome, "recovered")
        self.table.update_item.assert_called_once()
        values = self.table.update_item.call_args.kwargs[
            "ExpressionAttributeValues"
        ]
        self.assertEqual(values[":pending"], "cleanup_pending")
        # The only message is the existing "recovered" notice, not an alert.
        self.sns.publish.assert_called_once()
        subject = self.sns.publish.call_args.kwargs["Subject"]
        self.assertIn("recovered", subject.lower())


if __name__ == "__main__":
    unittest.main()