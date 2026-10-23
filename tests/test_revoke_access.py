import importlib.util
import json
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


def conditional_failure():
    return ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException"}},
        "UpdateItem",
    )


def intent_saved(target):
    """What DynamoDB returns for the intent write (ReturnValues=ALL_NEW)."""
    return {"Attributes": {"revocationIntentTarget": target}}


class RevokeAccessTests(unittest.TestCase):
    def setUp(self):
        self.table = Mock()
        self.iam = Mock()
        self.iam.exceptions.NoSuchEntityException = type(
            "NoSuchEntityException", (Exception,), {}
        )
        self.scheduler_sns = Mock()
        self.scheduler = Mock()
        self.scheduler.exceptions.ResourceNotFoundException = type(
            "ResourceNotFoundException", (Exception,), {}
        )

        self.original_table = app.table
        self.original_iam = app.iam
        self.original_sns = app.sns
        self.original_scheduler = app.scheduler

        app.table = self.table
        app.iam = self.iam
        app.sns = self.scheduler_sns
        app.scheduler = self.scheduler

    def tearDown(self):
        app.table = self.original_table
        app.iam = self.original_iam
        app.sns = self.original_sns
        app.scheduler = self.original_scheduler

    def make_active_item(self, **overrides):
        item = {
            "requestId": "req-123",
            "requesterId": "employee-123",
            "status": "active",
            "policyName": "jit-grant-req-123",
        }
        item.update(overrides)
        return item

    def manual_revoke_event(self):
        return {
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

    def update_values(self, call_index):
        return self.table.update_item.call_args_list[call_index].kwargs[
            "ExpressionAttributeValues"
        ]

    # ------------------------------------------------------------------
    # Input validation, authorization, and no-ops (unchanged behaviour)
    # ------------------------------------------------------------------

    def test_missing_request_id_raises_error(self):
        with self.assertRaises(ValueError):
            app.handler({"reason": "scheduled_expiry"}, None)

    def test_missing_request_is_noop(self):
        self.table.get_item.return_value = {}

        result = app.handler(
            {"requestId": "req-123"}, None
        )

        self.assertEqual(result["status"], "not_found")
        self.table.get_item.assert_called_once_with(
            Key={"requestId": "req-123"}, ConsistentRead=True
        )
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

    def test_terminal_statuses_are_never_touched_again(self):
        for status in ("expired", "revoked_early", "denied"):
            with self.subTest(status=status):
                self.table.reset_mock()
                self.iam.reset_mock()
                self.table.get_item.return_value = {
                    "Item": self.make_active_item(status=status)
                }

                result = app._revoke(
                    "req-123", reason="manual_revoke", actor="someone"
                )

                self.assertEqual(result["status"], status)
                self.table.update_item.assert_not_called()
                self.iam.delete_role_policy.assert_not_called()

    def test_cleanup_pending_is_left_to_the_reconciler(self):
        self.table.get_item.return_value = {
            "Item": self.make_active_item(status="cleanup_pending")
        }

        result = app._revoke(
            "req-123", reason="scheduled_expiry", actor=None
        )

        self.assertEqual(result["status"], "cleanup_pending")
        self.table.update_item.assert_not_called()
        self.iam.delete_role_policy.assert_not_called()

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

    # ------------------------------------------------------------------
    # active: nothing can be in flight, so one verified delete finishes it
    # ------------------------------------------------------------------

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

        # Two durable writes: cleanup_pending first, terminal status last.
        self.assertEqual(self.table.update_item.call_count, 2)
        first = self.update_values(0)
        self.assertEqual(first[":pending"], "cleanup_pending")
        self.assertEqual(first[":from_status"], "active")
        self.assertEqual(first[":target"], "expired")

        second_kwargs = self.table.update_item.call_args_list[1].kwargs
        self.assertEqual(second_kwargs["ConditionExpression"], "#s = :pending")
        self.assertEqual(
            second_kwargs["ExpressionAttributeValues"][":status"], "expired"
        )
        self.scheduler_sns.publish.assert_called_once()

    def test_manual_revoke_marks_request_revoked_early(self):
        self.table.get_item.return_value = {
            "Item": self.make_active_item()
        }

        response = app.handler(self.manual_revoke_event(), None)

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(
            json.loads(response["body"])["status"],
            "revoked_early",
        )
        self.iam.delete_role_policy.assert_called_once()
        self.assertEqual(self.table.update_item.call_count, 2)
        self.scheduler_sns.publish.assert_called_once()

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

        # For an active request nothing can still attach the policy, so a
        # missing policy is a safe, idempotent finish.
        self.assertEqual(result["status"], "expired")
        self.assertEqual(self.table.update_item.call_count, 2)

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
        self.assertEqual(self.table.update_item.call_count, 2)

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

        # Write 1: cleanup_pending.  Write 2: the failure record.  The
        # status is never changed to a terminal or "failed" value, so the
        # request stays visible and retryable.
        self.assertEqual(self.table.update_item.call_count, 2)
        self.assertEqual(self.update_values(0)[":pending"], "cleanup_pending")

        failure_kwargs = self.table.update_item.call_args_list[1].kwargs
        self.assertIn("revokeFailureReason", failure_kwargs["UpdateExpression"])
        self.assertIn("cleanupAttempts", failure_kwargs["UpdateExpression"])
        self.assertEqual(failure_kwargs["ConditionExpression"], "#s = :pending")
        self.assertEqual(
            failure_kwargs["ExpressionAttributeNames"], {"#s": "status"}
        )
        self.assertEqual(
            failure_kwargs["ExpressionAttributeValues"][":pending"],
            "cleanup_pending",
        )
        self.assertNotIn(":status", failure_kwargs["ExpressionAttributeValues"])
        self.assertNotIn(
            "revoke_failed",
            json.dumps(self.table.update_item.call_args_list[0].kwargs),
        )
        self.scheduler_sns.publish.assert_called_once()

    def test_failure_bookkeeping_error_does_not_hide_the_iam_error(self):
        self.table.get_item.return_value = {
            "Item": self.make_active_item()
        }
        self.table.update_item.side_effect = [
            {},
            ClientError(
                {"Error": {"Code": "ProvisionedThroughputExceededException"}},
                "UpdateItem",
            ),
        ]
        self.iam.delete_role_policy.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}},
            "DeleteRolePolicy",
        )

        with self.assertRaises(ClientError) as raised:
            app._revoke("req-123", reason="scheduled_expiry", actor=None)

        self.assertEqual(
            raised.exception.response["Error"]["Code"], "AccessDenied"
        )
        self.scheduler_sns.publish.assert_called_once()

    def test_finalize_loses_race_and_reports_current_status(self):
        self.table.get_item.side_effect = [
            {"Item": self.make_active_item()},
            {"Item": self.make_active_item(status="revoked_early")},
        ]
        self.table.update_item.side_effect = [{}, conditional_failure()]

        result = app._revoke(
            "req-123", reason="manual_revoke", actor="employee@example.com"
        )

        self.assertEqual(result["status"], "revoked_early")

    # ------------------------------------------------------------------
    # scheduled: nothing was ever granted, so no IAM call and no cleanup
    # ------------------------------------------------------------------

    def test_manual_revoke_of_scheduled_request_cancels_future_access(self):
        self.table.get_item.return_value = {
            "Item": self.make_active_item(
                status="scheduled",
                activationScheduleName="jit-activate-req-123",
                scheduleName="jit-revoke-req-123",
            )
        }

        response = app.handler(self.manual_revoke_event(), None)

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(
            json.loads(response["body"])["status"],
            "revoked_early",
        )
        self.assertEqual(self.scheduler.delete_schedule.call_count, 2)
        self.assertEqual(
            {
                call.kwargs["Name"]
                for call in self.scheduler.delete_schedule.call_args_list
            },
            {"jit-activate-req-123", "jit-revoke-req-123"},
        )

        # No policy can exist for a request that never activated.
        self.iam.delete_role_policy.assert_not_called()

        self.assertEqual(self.table.update_item.call_count, 1)
        update_kwargs = self.table.update_item.call_args_list[0].kwargs
        self.assertEqual(update_kwargs["ConditionExpression"], "#s = :scheduled")
        self.assertEqual(
            update_kwargs["ExpressionAttributeValues"][":status"],
            "revoked_early",
        )

    def test_scheduled_expiry_claims_scheduled_request_before_activation(self):
        self.table.get_item.return_value = {
            "Item": self.make_active_item(status="scheduled")
        }

        result = app._revoke(
            "req-123", reason="scheduled_expiry", actor=None
        )

        self.assertEqual(result["status"], "expired")
        update_kwargs = self.table.update_item.call_args_list[0].kwargs
        self.assertEqual(update_kwargs["ConditionExpression"], "#s = :scheduled")
        self.scheduler.delete_schedule.assert_not_called()
        self.iam.delete_role_policy.assert_not_called()

    def test_schedule_cancellation_failure_does_not_block_revoke(self):
        self.table.get_item.return_value = {
            "Item": self.make_active_item(
                status="scheduled",
                activationScheduleName="jit-activate-req-123",
                scheduleName="jit-revoke-req-123",
            )
        }
        self.scheduler.delete_schedule.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}},
            "DeleteSchedule",
        )

        result = app._revoke(
            "req-123", reason="manual_revoke", actor="employee@example.com"
        )

        # The status write already blocks any late activation.
        self.assertEqual(result["status"], "revoked_early")

    def test_revoke_loses_race_to_activation_claim_then_waits_for_cleanup(self):
        self.table.get_item.side_effect = [
            {"Item": self.make_active_item(status="scheduled")},
            {"Item": self.make_active_item(status="activating")},
        ]
        # Write 1 (scheduled -> terminal) loses to the activation claim.
        # Then the intent is saved, then the cleanup_pending transition.
        self.table.update_item.side_effect = [
            conditional_failure(),
            intent_saved("revoked_early"),
            {},
        ]
        self.iam.delete_role_policy.side_effect = (
            self.iam.exceptions.NoSuchEntityException()
        )

        result = app._revoke(
            "req-123", reason="manual_revoke", actor="employee@example.com"
        )

        self.assertEqual(result["status"], "cleanup_pending")
        self.assertEqual(self.table.update_item.call_count, 3)
        self.assertEqual(self.update_values(2)[":from_status"], "activating")

    # ------------------------------------------------------------------
    # activating: an activation may still be in flight, so only the
    # reconciler may finalize, and only after the activation deadline
    # ------------------------------------------------------------------

    def test_revoke_of_activating_request_stays_pending_for_reconciler(self):
        deadline = int(time.time()) + 150
        self.table.get_item.return_value = {
            "Item": self.make_active_item(
                status="activating",
                activationDeadline=str(deadline),
            )
        }
        self.iam.delete_role_policy.side_effect = (
            self.iam.exceptions.NoSuchEntityException()
        )
        self.table.update_item.side_effect = [intent_saved("revoked_early"), {}]

        result = app._revoke(
            "req-123", reason="manual_revoke", actor="employee@example.com"
        )

        # An absent policy is NOT proof that an activation has stopped.
        self.assertEqual(result["status"], "cleanup_pending")
        self.iam.delete_role_policy.assert_called_once()
        # Write 1 saves the intent; write 2 is the cleanup_pending transition.
        self.assertEqual(self.table.update_item.call_count, 2)

        update_kwargs = self.table.update_item.call_args_list[1].kwargs
        self.assertEqual(update_kwargs["ConditionExpression"], "#s = :from_status")
        values = update_kwargs["ExpressionAttributeValues"]
        self.assertEqual(values[":from_status"], "activating")
        self.assertEqual(values[":pending"], "cleanup_pending")
        self.assertEqual(values[":target"], "revoked_early")
        self.assertEqual(values[":not_before"], str(deadline))
        self.assertNotIn(":status", values)

    def test_activating_request_without_deadline_gets_a_safe_default(self):
        before = int(time.time())
        self.table.get_item.return_value = {
            "Item": self.make_active_item(status="activating")
        }
        self.table.update_item.side_effect = [intent_saved("expired"), {}]

        app._revoke("req-123", reason="scheduled_expiry", actor=None)

        not_before = int(self.update_values(1)[":not_before"])
        self.assertGreaterEqual(
            not_before, before + app.FALLBACK_ACTIVATION_DEADLINE_SECONDS
        )

    def test_activating_revoke_iam_failure_keeps_request_pending(self):
        self.table.get_item.return_value = {
            "Item": self.make_active_item(status="activating")
        }
        self.iam.delete_role_policy.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied"}},
            "DeleteRolePolicy",
        )
        # Intent write, cleanup_pending transition, then the failure record.
        self.table.update_item.side_effect = [intent_saved("expired"), {}, {}]

        with self.assertRaises(ClientError):
            app._revoke("req-123", reason="scheduled_expiry", actor=None)

        self.assertEqual(self.table.update_item.call_count, 3)
        self.assertEqual(self.update_values(1)[":pending"], "cleanup_pending")
        failure_values = self.update_values(2)
        self.assertNotIn(":status", failure_values)
        self.assertNotIn(":target", failure_values)

    def test_revoke_retries_when_activation_becomes_active_first(self):
        self.table.get_item.side_effect = [
            {"Item": self.make_active_item(status="activating")},
            {"Item": self.make_active_item(status="active")},
        ]
        # 1) activating -> pending loses to the activation's final write,
        # 2) active -> pending wins, 3) pending -> terminal wins.
        self.table.update_item.side_effect = [conditional_failure(), {}, {}]

        result = app._revoke(
            "req-123", reason="manual_revoke", actor="employee@example.com"
        )

        self.assertEqual(result["status"], "revoked_early")
        self.iam.delete_role_policy.assert_called_once()
        self.assertEqual(self.table.update_item.call_count, 3)
        self.assertEqual(self.update_values(1)[":from_status"], "active")
        self.assertEqual(self.update_values(2)[":status"], "revoked_early")

    def test_revoke_gives_up_loudly_if_the_request_keeps_changing(self):
        self.table.get_item.return_value = {
            "Item": self.make_active_item()
        }
        self.table.update_item.side_effect = conditional_failure()

        with self.assertRaises(RuntimeError):
            app._revoke("req-123", reason="scheduled_expiry", actor=None)

        self.assertEqual(
            self.table.update_item.call_count, app.MAX_STATE_RETRIES
        )
        self.iam.delete_role_policy.assert_not_called()


if __name__ == "__main__":
    unittest.main()