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
    "reconcile_cleanup_app", app_path
)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


def conditional_failure():
    return ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException"}},
        "UpdateItem",
    )


def access_denied():
    return ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Simulated"}},
        "DeleteRolePolicy",
    )


class ReconcileCleanupTests(unittest.TestCase):
    def setUp(self):
        self.table = Mock()
        self.iam = Mock()
        self.iam.exceptions.NoSuchEntityException = type(
            "NoSuchEntityException", (Exception,), {}
        )
        self.sns = Mock()

        self.original_table = app.table
        self.original_iam = app.iam
        self.original_sns = app.sns

        app.table = self.table
        app.iam = self.iam
        app.sns = self.sns

        # By default the index reports exactly one pending request.
        self.table.query.return_value = {"Items": [{"requestId": "req-123"}]}

    def tearDown(self):
        app.table = self.original_table
        app.iam = self.original_iam
        app.sns = self.original_sns

    def pending_item(self, **overrides):
        now = int(time.time())
        item = {
            "requestId": "req-123",
            "status": "cleanup_pending",
            "cleanupTargetStatus": "expired",
            "cleanupNotBefore": str(now - 600),
            "policyName": "jit-grant-req-123",
        }
        item.update(overrides)
        return item

    def policy_absent(self):
        self.iam.delete_role_policy.side_effect = (
            self.iam.exceptions.NoSuchEntityException()
        )

    def values(self, call_index=0):
        return self.table.update_item.call_args_list[call_index].kwargs[
            "ExpressionAttributeValues"
        ]

    def kwargs(self, call_index=0):
        return self.table.update_item.call_args_list[call_index].kwargs

    # ------------------------------------------------------------------
    # Finding work
    # ------------------------------------------------------------------

    def test_nothing_pending_does_nothing(self):
        self.table.query.return_value = {"Items": []}

        summary = app.handler({}, None)

        self.assertEqual(summary["finalized"], 0)
        self.iam.delete_role_policy.assert_not_called()
        self.table.update_item.assert_not_called()

    def test_queries_status_index_and_follows_pagination(self):
        self.table.query.side_effect = [
            {
                "Items": [{"requestId": "req-1"}],
                "LastEvaluatedKey": {"requestId": "req-1"},
            },
            {"Items": [{"requestId": "req-2"}]},
            # Third query: the activating status has nothing to report.
            {"Items": []},
        ]
        self.table.get_item.return_value = {}

        app.handler({}, None)

        # Two pages for cleanup_pending, then one empty query for activating.
        self.assertEqual(self.table.query.call_count, 3)
        first = self.table.query.call_args_list[0].kwargs
        second = self.table.query.call_args_list[1].kwargs
        self.assertEqual(first["IndexName"], "status-index")
        self.assertNotIn("ExclusiveStartKey", first)
        self.assertEqual(second["ExclusiveStartKey"], {"requestId": "req-1"})
        self.assertEqual(self.table.get_item.call_count, 2)

    def test_stale_index_result_is_rechecked_with_a_consistent_read(self):
        # The GSI still lists it, but the real item already moved on.
        self.table.get_item.return_value = {
            "Item": self.pending_item(status="expired")
        }

        summary = app.handler({}, None)

        self.assertEqual(summary["skipped"], 1)
        self.assertTrue(
            self.table.get_item.call_args.kwargs["ConsistentRead"]
        )
        self.iam.delete_role_policy.assert_not_called()
        self.table.update_item.assert_not_called()

    def test_request_deleted_since_the_index_read_is_skipped(self):
        self.table.get_item.return_value = {}

        summary = app.handler({}, None)

        self.assertEqual(summary["skipped"], 1)
        self.iam.delete_role_policy.assert_not_called()

    # ------------------------------------------------------------------
    # The clean-pass protocol
    # ------------------------------------------------------------------

    def test_before_the_deadline_it_deletes_but_never_finalizes(self):
        now = int(time.time())
        self.table.get_item.return_value = {
            "Item": self.pending_item(cleanupNotBefore=str(now + 300))
        }
        self.policy_absent()

        summary = app.handler({}, None)

        # Not proof yet: an activation may still be in flight.
        self.assertEqual(summary["waiting"], 1)
        self.iam.delete_role_policy.assert_called_once_with(
            RoleName="ci-test-target-role",
            PolicyName="jit-grant-req-123",
        )
        self.table.update_item.assert_not_called()

    def test_first_clean_pass_after_the_deadline_is_recorded_not_finalized(self):
        self.table.get_item.return_value = {"Item": self.pending_item()}
        self.policy_absent()

        summary = app.handler({}, None)

        self.assertEqual(summary["pass_recorded"], 1)
        self.assertEqual(self.table.update_item.call_count, 1)
        values = self.values()
        self.assertEqual(values[":one"], 1)
        self.assertEqual(values[":pending"], "cleanup_pending")
        self.assertNotIn(":target", values)
        self.assertEqual(
            self.kwargs()["ConditionExpression"],
            "#s = :pending AND attribute_not_exists(#passes) "
            "AND attribute_not_exists(#last_pass)",
        )
        self.assertEqual(
            self.kwargs()["ExpressionAttributeNames"],
            {
                "#s": "status",
                "#passes": "cleanCleanupPasses",
                "#last_pass": "lastCleanPassAt",
            },
        )

    def test_first_clean_pass_guards_the_observed_pass_count(self):
        self.table.get_item.return_value = {
            "Item": self.pending_item(cleanCleanupPasses=0)
        }
        self.policy_absent()

        summary = app.handler({}, None)

        self.assertEqual(summary["pass_recorded"], 1)
        kwargs = self.kwargs()
        self.assertEqual(
            kwargs["ConditionExpression"],
            "#s = :pending AND #passes = :observed_passes "
            "AND attribute_not_exists(#last_pass)",
        )
        self.assertEqual(
            kwargs["ExpressionAttributeValues"][":observed_passes"],
            0,
        )
        self.assertEqual(
            kwargs["ExpressionAttributeNames"]["#passes"],
            "cleanCleanupPasses",
        )

    def test_second_clean_pass_finalizes_to_the_target_status(self):
        now = int(time.time())
        self.table.get_item.return_value = {
            "Item": self.pending_item(
                cleanCleanupPasses=1,
                lastCleanPassAt=str(now - 90),
                cleanupTargetStatus="revoked_early",
            )
        }
        self.policy_absent()

        summary = app.handler({}, None)

        self.assertEqual(summary["finalized"], 1)
        self.assertEqual(self.table.update_item.call_count, 1)
        kwargs = self.kwargs()
        values = kwargs["ExpressionAttributeValues"]
        self.assertEqual(values[":target"], "revoked_early")
        self.assertEqual(values[":observed_passes"], 1)
        self.assertEqual(
            values[":observed_last_pass"],
            str(now - 90),
        )
        self.assertEqual(
            kwargs["ConditionExpression"],
            "#s = :pending AND #passes = :observed_passes "
            "AND #last_pass = :observed_last_pass",
        )
        self.assertEqual(
            kwargs["ExpressionAttributeNames"],
            {
                "#s": "status",
                "#passes": "cleanCleanupPasses",
                "#last_pass": "lastCleanPassAt",
            },
        )
        self.sns.publish.assert_called_once()

    def test_finalization_guards_missing_last_clean_pass_timestamp(self):
        self.table.get_item.return_value = {
            "Item": self.pending_item(cleanCleanupPasses=1)
        }
        self.policy_absent()

        summary = app.handler({}, None)

        self.assertEqual(summary["finalized"], 1)
        kwargs = self.kwargs()
        self.assertEqual(
            kwargs["ConditionExpression"],
            "#s = :pending AND #passes = :observed_passes "
            "AND attribute_not_exists(#last_pass)",
        )
        self.assertEqual(
            kwargs["ExpressionAttributeValues"][":observed_passes"],
            1,
        )
        self.assertNotIn(
            ":observed_last_pass",
            kwargs["ExpressionAttributeValues"],
        )
        self.sns.publish.assert_called_once()

    def test_second_pass_too_soon_does_not_count_as_a_separate_run(self):
        now = int(time.time())
        self.table.get_item.return_value = {
            "Item": self.pending_item(
                cleanCleanupPasses=1,
                lastCleanPassAt=str(now - 2),
            )
        }
        self.policy_absent()

        summary = app.handler({}, None)

        self.assertEqual(summary["waiting"], 1)
        self.table.update_item.assert_not_called()

    def test_late_policy_is_deleted_and_the_clean_count_restarts(self):
        now = int(time.time())
        self.table.get_item.return_value = {
            "Item": self.pending_item(
                cleanCleanupPasses=1,
                lastCleanPassAt=str(now - 90),
            )
        }
        # delete_role_policy succeeds: a policy really was attached.

        summary = app.handler({}, None)

        self.assertEqual(summary["reset"], 1)
        self.assertEqual(summary["finalized"], 0)
        self.assertEqual(self.values()[":zero"], 0)
        self.assertNotIn(":target", self.values())
        # Past its deadline, a surviving policy is worth an alert.
        self.sns.publish.assert_called_once()

    def test_policy_deleted_before_the_deadline_resets_quietly(self):
        now = int(time.time())
        self.table.get_item.return_value = {
            "Item": self.pending_item(cleanupNotBefore=str(now + 300))
        }

        summary = app.handler({}, None)

        self.assertEqual(summary["reset"], 1)
        self.sns.publish.assert_not_called()

    def test_whole_protocol_across_three_runs(self):
        now = int(time.time())
        state = self.pending_item()
        self.policy_absent()

        def get_item(**kwargs):
            return {"Item": dict(state)}

        self.table.get_item.side_effect = get_item

        # Run 1: first clean pass.
        self.assertEqual(app.handler({}, None)["pass_recorded"], 1)
        state.update(cleanCleanupPasses=1, lastCleanPassAt=str(now))

        # Run 2 only seconds later: does not count.
        self.assertEqual(app.handler({}, None)["waiting"], 1)

        # Run 3 well after the minimum gap: finalizes.
        state["lastCleanPassAt"] = str(now - 120)
        self.assertEqual(app.handler({}, None)["finalized"], 1)

        self.assertEqual(self.table.update_item.call_count, 2)

    # ------------------------------------------------------------------
    # Failures stay visible and retryable
    # ------------------------------------------------------------------

    def test_iam_failure_keeps_request_pending_and_alerts_on_first_failure(self):
        self.table.get_item.return_value = {"Item": self.pending_item()}
        self.iam.delete_role_policy.side_effect = access_denied()

        with self.assertRaises(RuntimeError):
            app.handler({}, None)

        self.assertEqual(self.table.update_item.call_count, 1)
        kwargs = self.kwargs()
        self.assertIn("revokeFailureReason", kwargs["UpdateExpression"])
        self.assertIn("cleanupAttempts", kwargs["UpdateExpression"])
        self.assertEqual(kwargs["ConditionExpression"], "#s = :pending")
        self.assertEqual(kwargs["ExpressionAttributeNames"], {"#s": "status"})
        values = kwargs["ExpressionAttributeValues"]
        self.assertEqual(values[":zero"], 0)
        self.assertEqual(values[":pending"], app.PENDING_STATUS)
        self.assertNotIn(":target", values)
        self.assertNotIn(":status", values)
        self.sns.publish.assert_called_once()

    def test_repeated_failures_do_not_alert_every_single_run(self):
        self.table.get_item.return_value = {
            "Item": self.pending_item(cleanupAttempts=3)
        }
        self.iam.delete_role_policy.side_effect = access_denied()

        with self.assertRaises(RuntimeError):
            app.handler({}, None)

        self.assertEqual(self.table.update_item.call_count, 1)
        self.sns.publish.assert_not_called()

    def test_a_reminder_alert_is_sent_every_tenth_failure(self):
        self.table.get_item.return_value = {
            "Item": self.pending_item(cleanupAttempts=10)
        }
        self.iam.delete_role_policy.side_effect = access_denied()

        with self.assertRaises(RuntimeError):
            app.handler({}, None)

        self.sns.publish.assert_called_once()

    def test_one_failing_request_does_not_block_the_others(self):
        self.table.query.return_value = {
            "Items": [{"requestId": "req-bad"}, {"requestId": "req-good"}]
        }
        now = int(time.time())

        def get_item(Key, ConsistentRead):
            request_id = Key["requestId"]
            return {
                "Item": self.pending_item(
                    requestId=request_id,
                    policyName=f"jit-grant-{request_id}",
                    cleanCleanupPasses=1,
                    lastCleanPassAt=str(now - 120),
                )
            }

        self.table.get_item.side_effect = get_item

        def delete(RoleName, PolicyName):
            if PolicyName == "jit-grant-req-bad":
                raise access_denied()
            raise self.iam.exceptions.NoSuchEntityException()

        self.iam.delete_role_policy.side_effect = delete

        with self.assertRaises(RuntimeError) as raised:
            app.handler({}, None)

        self.assertIn("1 cleanup(s) failed", str(raised.exception))
        deleted = [
            call.kwargs["PolicyName"]
            for call in self.iam.delete_role_policy.call_args_list
        ]
        self.assertEqual(
            deleted, ["jit-grant-req-bad", "jit-grant-req-good"]
        )
        # The good request was still finalized.
        finalized = [
            c.kwargs["ExpressionAttributeValues"].get(":target")
            for c in self.table.update_item.call_args_list
        ]
        self.assertIn("expired", finalized)

    def test_unexpected_request_error_does_not_block_the_others(self):
        self.table.query.return_value = {
            "Items": [{"requestId": "req-bad"}, {"requestId": "req-good"}]
        }
        now = int(time.time())

        def get_item(Key, ConsistentRead):
            request_id = Key["requestId"]
            if request_id == "req-bad":
                raise RuntimeError("simulated read failure")
            return {
                "Item": self.pending_item(
                    requestId=request_id,
                    policyName=f"jit-grant-{request_id}",
                    cleanCleanupPasses=1,
                    lastCleanPassAt=str(now - 120),
                )
            }

        self.table.get_item.side_effect = get_item
        self.iam.delete_role_policy.side_effect = (
            self.iam.exceptions.NoSuchEntityException()
        )

        with self.assertRaises(RuntimeError) as raised:
            app.handler({}, None)

        self.assertIn("1 cleanup(s) failed", str(raised.exception))
        self.assertEqual(self.table.get_item.call_count, 2)
        finalized = [
            call.kwargs["ExpressionAttributeValues"].get(":target")
            for call in self.table.update_item.call_args_list
        ]
        self.assertIn("expired", finalized)

    def test_failure_bookkeeping_update_requires_pending_status(self):
        self.table.get_item.return_value = {"Item": self.pending_item()}
        self.iam.delete_role_policy.side_effect = access_denied()

        with self.assertRaises(RuntimeError):
            app.handler({}, None)

        # The failure-bookkeeping write must only affect a request
        # that remains in cleanup_pending status.
        failure_write = self.table.update_item.call_args.kwargs
        self.assertEqual(
            failure_write["ConditionExpression"], "#s = :pending"
        )
        self.assertEqual(
            failure_write["ExpressionAttributeNames"], {"#s": "status"}
        )
        self.assertEqual(
            failure_write["ExpressionAttributeValues"][":pending"],
            "cleanup_pending",
        )

    def test_failure_bookkeeping_error_does_not_hide_the_problem(self):
        self.table.get_item.return_value = {"Item": self.pending_item()}
        self.iam.delete_role_policy.side_effect = access_denied()
        self.table.update_item.side_effect = ClientError(
            {"Error": {"Code": "ProvisionedThroughputExceededException"}},
            "UpdateItem",
        )

        with self.assertRaises(RuntimeError):
            app.handler({}, None)

        self.sns.publish.assert_called_once()

    def test_invalid_target_status_is_never_finalized(self):
        self.table.get_item.return_value = {
            "Item": self.pending_item(
                cleanupTargetStatus="active",
                cleanCleanupPasses=1,
                lastCleanPassAt="1",
            )
        }
        self.policy_absent()

        with self.assertRaises(RuntimeError):
            app.handler({}, None)

        self.iam.delete_role_policy.assert_not_called()
        for call in self.table.update_item.call_args_list:
            self.assertNotIn(
                ":target", call.kwargs["ExpressionAttributeValues"]
            )

    def test_missing_deadline_is_never_finalized(self):
        item = self.pending_item(cleanCleanupPasses=1, lastCleanPassAt="1")
        del item["cleanupNotBefore"]
        self.table.get_item.return_value = {"Item": item}
        self.policy_absent()

        with self.assertRaises(RuntimeError):
            app.handler({}, None)

        self.iam.delete_role_policy.assert_not_called()

    # ------------------------------------------------------------------
    # Races, idempotency, and limits
    # ------------------------------------------------------------------

    def test_finalize_losing_a_race_is_not_an_error(self):
        now = int(time.time())
        self.table.get_item.return_value = {
            "Item": self.pending_item(
                cleanCleanupPasses=1,
                lastCleanPassAt=str(now - 120),
            )
        }
        self.policy_absent()
        self.table.update_item.side_effect = conditional_failure()

        summary = app.handler({}, None)

        self.assertEqual(summary["skipped"], 1)
        self.assertEqual(summary["finalized"], 0)
        self.sns.publish.assert_not_called()
        kwargs = self.kwargs()
        self.assertIn(
            "#passes = :observed_passes",
            kwargs["ConditionExpression"],
        )

    def test_terminal_requests_are_never_modified(self):
        for status in ("expired", "revoked_early", "active", "scheduled"):
            with self.subTest(status=status):
                self.table.reset_mock()
                self.iam.reset_mock()
                self.table.query.return_value = {
                    "Items": [{"requestId": "req-123"}]
                }
                self.table.get_item.return_value = {
                    "Item": self.pending_item(status=status)
                }

                app.handler({}, None)

                self.table.update_item.assert_not_called()
                self.iam.delete_role_policy.assert_not_called()

    def test_only_the_requests_own_policy_is_ever_deleted(self):
        self.table.get_item.return_value = {
            "Item": self.pending_item(policyName="jit-grant-req-123")
        }
        self.policy_absent()

        app.handler({}, None)

        self.iam.delete_role_policy.assert_called_once_with(
            RoleName="ci-test-target-role",
            PolicyName="jit-grant-req-123",
        )
        self.iam.put_role_policy.assert_not_called()

    def test_policy_name_falls_back_to_the_standard_name(self):
        item = self.pending_item()
        del item["policyName"]
        self.table.get_item.return_value = {"Item": item}
        self.policy_absent()

        app.handler({}, None)

        self.assertEqual(
            self.iam.delete_role_policy.call_args.kwargs["PolicyName"],
            "jit-grant-req-123",
        )

    def test_stops_early_when_the_invocation_is_almost_out_of_time(self):
        context = Mock()
        context.get_remaining_time_in_millis.return_value = 1000
        self.table.get_item.return_value = {"Item": self.pending_item()}

        summary = app.handler({}, context)

        self.assertTrue(summary["stopped_early"])
        self.iam.delete_role_policy.assert_not_called()

    def test_query_errors_are_raised(self):
        self.table.query.side_effect = ClientError(
            {"Error": {"Code": "ProvisionedThroughputExceededException"}},
            "Query",
        )

        with self.assertRaises(ClientError):
            app.handler({}, None)


if __name__ == "__main__":
    unittest.main()