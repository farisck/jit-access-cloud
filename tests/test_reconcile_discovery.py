import importlib.util
import os
import time
import unittest
from unittest.mock import Mock


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
    "reconcile_cleanup_discovery_app", app_path
)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.table = Mock()
        self.iam = Mock()
        self.iam.exceptions.NoSuchEntityException = type(
            "NoSuchEntityException", (Exception,), {}
        )
        self.iam.delete_role_policy.side_effect = (
            self.iam.exceptions.NoSuchEntityException()
        )
        self.sns = Mock()

        self.original_table = app.table
        self.original_iam = app.iam
        self.original_sns = app.sns

        app.table = self.table
        app.iam = self.iam
        app.sns = self.sns

        self.queried = []
        self.items = {}

    def tearDown(self):
        app.table = self.original_table
        app.iam = self.original_iam
        app.sns = self.original_sns

    def stale_activating(self, request_id, **overrides):
        now = int(time.time())
        item = {
            "requestId": request_id,
            "status": "activating",
            "activationDeadline": str(now - 600),
            "revocationIntentTarget": "expired",
        }
        item.update(overrides)
        return item

    def waiting_pending(self, request_id):
        return {
            "requestId": request_id,
            "status": "cleanup_pending",
            "cleanupTargetStatus": "expired",
            "cleanupNotBefore": str(int(time.time()) + 600),
        }

    def serve(self, pages_by_status, items):
        """Fake the index: each status returns its pages in order."""
        remaining = {s: list(p) for s, p in pages_by_status.items()}
        self.items = items

        def fake_query(**kwargs):
            condition = kwargs["KeyConditionExpression"].get_expression()
            status = condition["values"][1]
            self.queried.append(
                (status, kwargs["IndexName"], kwargs.get("ExclusiveStartKey"))
            )
            return remaining.get(status, [{"Items": []}]).pop(0)

        self.table.query.side_effect = fake_query
        self.table.get_item.side_effect = lambda **kw: {
            "Item": self.items.get(kw["Key"]["requestId"])
        }

    def test_queries_both_statuses_on_the_status_index(self):
        self.serve({}, {})

        app.handler({}, None)

        statuses = sorted(status for status, _, _ in self.queried)
        self.assertEqual(statuses, ["activating", "cleanup_pending"])
        for _, index_name, _ in self.queried:
            self.assertEqual(index_name, "status-index")

    def test_pagination_is_followed_for_both_statuses(self):
        self.serve(
            {
                "activating": [
                    {"Items": [{"requestId": "a1"}], "LastEvaluatedKey": {"k": 1}},
                    {"Items": [{"requestId": "a2"}]},
                ],
                "cleanup_pending": [
                    {"Items": [{"requestId": "p1"}], "LastEvaluatedKey": {"k": 2}},
                    {"Items": [{"requestId": "p2"}]},
                ],
            },
            {
                "a1": self.stale_activating("a1"),
                "a2": self.stale_activating("a2"),
                "p1": self.waiting_pending("p1"),
                "p2": self.waiting_pending("p2"),
            },
        )

        app.handler({}, None)

        read_ids = sorted(
            call.kwargs["Key"]["requestId"]
            for call in self.table.get_item.call_args_list
        )
        self.assertEqual(read_ids, ["a1", "a2", "p1", "p2"])
        continued = sorted(
            status for status, _, start in self.queried if start is not None
        )
        self.assertEqual(continued, ["activating", "cleanup_pending"])

    def test_a_request_in_both_results_is_processed_once(self):
        self.serve(
            {
                "activating": [{"Items": [{"requestId": "req-1"}]}],
                "cleanup_pending": [{"Items": [{"requestId": "req-1"}]}],
            },
            {"req-1": self.waiting_pending("req-1")},
        )

        summary = app.handler({}, None)

        self.assertEqual(self.table.get_item.call_count, 1)
        self.assertEqual(summary["waiting"], 1)

    def test_summary_counts_recovered_and_unrecoverable(self):
        self.serve(
            {
                "activating": [
                    {"Items": [{"requestId": "good"}, {"requestId": "no-intent"}]}
                ],
            },
            {
                "good": self.stale_activating("good"),
                "no-intent": self.stale_activating(
                    "no-intent", revocationIntentTarget=None
                ),
            },
        )

        summary = app.handler({}, None)

        self.assertEqual(summary["recovered"], 1)
        self.assertEqual(summary["unrecoverable"], 1)
        # Only the good one is written; the other stays untouched.
        self.table.update_item.assert_called_once()
        self.assertEqual(
            self.table.update_item.call_args.kwargs["Key"],
            {"requestId": "good"},
        )


if __name__ == "__main__":
    unittest.main()