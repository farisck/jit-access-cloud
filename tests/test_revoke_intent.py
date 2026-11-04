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
os.environ["SCHEDULE_GROUP_NAME"] = "ci-test-schedule-group"

app_path = os.path.join(
    os.path.dirname(__file__),
    "..",
    "lambda",
    "revoke_access",
    "app.py",
)
spec = importlib.util.spec_from_file_location(
    "revoke_access_intent_app", app_path
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


def intent_saved(target):
    """What DynamoDB returns for the intent write (ReturnValues=ALL_NEW)."""
    return {"Attributes": {"revocationIntentTarget": target}}


class RevocationIntentTests(unittest.TestCase):
    def setUp(self):
        self.table = Mock()
        self.iam = Mock()
        self.iam.exceptions.NoSuchEntityException = type(
            "NoSuchEntityException", (Exception,), {}
        )
        self.sns = Mock()
        self.scheduler = Mock()

        self.original_table = app.table
        self.original_iam = app.iam
        self.original_sns = app.sns
        self.original_scheduler = app.scheduler
        self.original_cancel = app._cancel_schedules

        app.table = self.table
        app.iam = self.iam
        app.sns = self.sns
        app.scheduler = self.scheduler
        # Schedule cancelling is not what these tests are about.
        app._cancel_schedules = Mock()

    def tearDown(self):
        app.table = self.original_table
        app.iam = self.original_iam
        app.sns = self.original_sns
        app.scheduler = self.original_scheduler
        app._cancel_schedules = self.original_cancel

    def item(self, status, **overrides):
        item = {
            "requestId": "req-123",
            "status": status,
            "activationDeadline": str(int(time.time()) + 60),
            "policyName": "jit-grant-req-123",
        }
        item.update(overrides)
        return item

    def test_manual_revoke_saves_intent_before_changing_status(self):
        self.table.get_item.return_value = {"Item": self.item("activating")}
        self.table.update_item.side_effect = [intent_saved("revoked_early"), {}]

        result = app._revoke("req-123", "manual_revoke", "boss@example.com")

        self.assertEqual(result["status"], "cleanup_pending")
        self.assertEqual(self.table.update_item.call_count, 2)
        intent = self.table.update_item.call_args_list[0].kwargs
        transition = self.table.update_item.call_args_list[1].kwargs

        # Write 1: intent only, first writer wins, only while activating.
        self.assertEqual(intent["ConditionExpression"], "#s = :activating")
        self.assertIn("if_not_exists", intent["UpdateExpression"])
        self.assertEqual(intent["ReturnValues"], "ALL_NEW")
        self.assertEqual(
            intent["ExpressionAttributeValues"][":target"], "revoked_early"
        )
        self.assertEqual(
            intent["ExpressionAttributeValues"][":activating"], "activating"
        )
        self.assertEqual(
            intent["ExpressionAttributeValues"][":by"], "boss@example.com"
        )
        self.assertNotIn(":pending", intent["ExpressionAttributeValues"])

        # Write 2: the existing status transition.
        self.assertEqual(
            transition["ExpressionAttributeValues"][":pending"],
            "cleanup_pending",
        )
        self.assertEqual(
            transition["ExpressionAttributeValues"][":target"],
            "revoked_early",
        )

    def test_scheduled_expiry_saves_expired_intent(self):
        self.table.get_item.return_value = {"Item": self.item("activating")}
        self.table.update_item.side_effect = [intent_saved("expired"), {}]

        app._revoke("req-123", "scheduled_expiry", None)

        intent = self.table.update_item.call_args_list[0].kwargs
        transition = self.table.update_item.call_args_list[1].kwargs
        self.assertEqual(
            intent["ExpressionAttributeValues"][":target"], "expired"
        )
        self.assertEqual(
            transition["ExpressionAttributeValues"][":target"], "expired"
        )

    def test_an_earlier_saved_intent_wins_over_this_call(self):
        # An earlier attempt already saved "expired"; this call is manual.
        self.table.get_item.return_value = {"Item": self.item("activating")}
        self.table.update_item.side_effect = [intent_saved("expired"), {}]

        app._revoke("req-123", "manual_revoke", "boss@example.com")

        transition = self.table.update_item.call_args_list[1].kwargs
        self.assertEqual(
            transition["ExpressionAttributeValues"][":target"], "expired"
        )

    def test_losing_the_intent_race_rereads_and_takes_the_new_branch(self):
        # Activation finished between our read and our write.
        self.table.get_item.side_effect = [
            {"Item": self.item("activating")},
            {"Item": self.item("active")},
        ]
        self.table.update_item.side_effect = [conditional_failure(), {}, {}]

        result = app._revoke("req-123", "scheduled_expiry", None)

        self.assertEqual(result["status"], "expired")
        self.assertEqual(self.table.update_item.call_count, 3)
        second = self.table.update_item.call_args_list[1].kwargs
        self.assertEqual(
            second["ExpressionAttributeValues"][":from_status"], "active"
        )

    def test_failed_intent_write_changes_nothing_and_is_loud(self):
        self.table.get_item.return_value = {"Item": self.item("activating")}
        self.table.update_item.side_effect = throttled()

        with self.assertRaises(ClientError):
            app._revoke("req-123", "manual_revoke", "boss@example.com")

        self.table.update_item.assert_called_once()
        self.iam.delete_role_policy.assert_not_called()

    def test_an_invalid_saved_intent_is_never_used(self):
        self.table.get_item.return_value = {"Item": self.item("activating")}
        self.table.update_item.side_effect = [intent_saved("approved")]

        with self.assertRaises(RuntimeError):
            app._revoke("req-123", "manual_revoke", "boss@example.com")

        self.table.update_item.assert_called_once()
        self.iam.delete_role_policy.assert_not_called()


if __name__ == "__main__":
    unittest.main()