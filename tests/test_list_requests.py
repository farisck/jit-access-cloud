import json
import importlib.util
import os
import unittest
from unittest.mock import Mock, patch


os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
os.environ["REQUESTS_TABLE_NAME"] = "ci-test-table"

app_path = os.path.join(
    os.path.dirname(__file__),
    "..",
    "lambda",
    "list_requests",
    "app.py"
)

spec = importlib.util.spec_from_file_location(
    "list_requests_app",
    app_path
)

app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class ListRequestsTests(unittest.TestCase):

    def setUp(self):
        self.table = Mock()
        self.original_table = app.table
        app.table = self.table

    def tearDown(self):
        app.table = self.original_table

    def make_event(self, claims=None, query=None):
        if claims is None:
            claims = {
                "sub": "user-123",
                "email": "faris@example.com",
            }

        return {
            "requestContext": {
                "authorizer": {
                    "jwt": {
                        "claims": claims
                    }
                }
            },
            "queryStringParameters": query,
        }

    def test_missing_authorization_returns_401(self):
        event = {
            "requestContext": {}
        }

        response = app.handler(event, None)

        self.assertEqual(response["statusCode"], 401)

    def test_lists_requesters_own_requests(self):
        self.table.query.return_value = {
            "Items": [
                {
                    "requestId": "req-123",
                    "requesterEmail": "faris@example.com",
                    "permission": "s3-read-demo-bucket",
                    "reason": "Need S3 access",
                    "durationMinutes": 60,
                    "status": "pending",
                    "requestedAt": "1000",
                }
            ]
        }

        event = self.make_event()

        response = app.handler(event, None)

        self.assertEqual(response["statusCode"], 200)

        body = json.loads(response["body"])

        self.assertEqual(body["mode"], "mine")
        self.assertEqual(len(body["requests"]), 1)
        self.assertEqual(body["requests"][0]["requestId"], "req-123")

        self.table.query.assert_called_once()

        query_kwargs = self.table.query.call_args.kwargs

        self.assertEqual(query_kwargs["IndexName"], "requester-index")

    def test_status_filter_uses_status_index(self):
        self.table.query.return_value = {
            "Items": [
                {
                    "requestId": "req-456",
                    "status": "pending",
                    "permission": "s3-read-demo-bucket",
                }
            ]
        }

        event = self.make_event(
            query={"status": "pending"}
        )

        response = app.handler(event, None)

        self.assertEqual(response["statusCode"], 200)

        body = json.loads(response["body"])

        self.assertEqual(body["mode"], "status:pending")
        self.assertEqual(len(body["requests"]), 1)

        query_kwargs = self.table.query.call_args.kwargs

        self.assertEqual(query_kwargs["IndexName"], "status-index")

    def test_limit_is_capped_at_50(self):
        self.table.query.return_value = {
            "Items": []
        }

        event = self.make_event(
            query={"limit": "100"}
        )

        response = app.handler(event, None)

        self.assertEqual(response["statusCode"], 200)

        query_kwargs = self.table.query.call_args.kwargs

        self.assertEqual(query_kwargs["Limit"], 50)

    def test_invalid_limit_uses_default(self):
        self.table.query.return_value = {
            "Items": []
        }

        event = self.make_event(
            query={"limit": "abc"}
        )

        response = app.handler(event, None)

        self.assertEqual(response["statusCode"], 200)

        query_kwargs = self.table.query.call_args.kwargs

        self.assertEqual(query_kwargs["Limit"], 20)

    def test_database_failure_returns_500(self):
        self.table.query.side_effect = Exception("DynamoDB unavailable")

        event = self.make_event()

        response = app.handler(event, None)

        self.assertEqual(response["statusCode"], 500)

        body = json.loads(response["body"])

        self.assertEqual(
            body["message"],
            "Could not list requests"
        )


if __name__ == "__main__":
    unittest.main()