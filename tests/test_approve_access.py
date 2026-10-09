import importlib.util
import json
import os
import unittest
from unittest.mock import Mock


# Environment variables required when app.py is imported
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
os.environ["REQUESTS_TABLE_NAME"] = "ci-test-table"
os.environ["NOTIFICATIONS_TOPIC_ARN"] = (
    "arn:aws:sns:us-east-1:000000000000:ci-test-topic"
)
os.environ["TARGET_ROLE_NAME"] = "ci-test-target-role"
os.environ["REVOKE_FUNCTION_ARN"] = (
    "arn:aws:lambda:us-east-1:000000000000:function:ci-test-revoke"
)
os.environ["SCHEDULER_ROLE_ARN"] = (
    "arn:aws:iam::000000000000:role/ci-test-scheduler-role"
)
os.environ["SCHEDULE_GROUP_NAME"] = "ci-test-schedule-group"
os.environ["PERMISSION_CATALOG"] = json.dumps({
    "s3-read-demo-bucket": {
        "Effect": "Allow",
        "Action": ["s3:GetObject"],
        "Resource": "arn:aws:s3:::demo-bucket/*"
    }
})


app_path = os.path.join(
    os.path.dirname(__file__),
    "..",
    "lambda",
    "approve_access",
    "app.py"
)

spec = importlib.util.spec_from_file_location(
    "approve_access_app",
    app_path
)

app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class ApproveAccessTests(unittest.TestCase):

    def setUp(self):
        self.table = Mock()
        self.iam = Mock()
        self.scheduler = Mock()
        self.sns = Mock()

        self.original_table = app.table
        self.original_iam = app.iam
        self.original_scheduler = app.scheduler
        self.original_sns = app.sns

        app.table = self.table
        app.iam = self.iam
        app.scheduler = self.scheduler
        app.sns = self.sns

    def tearDown(self):
        app.table = self.original_table
        app.iam = self.original_iam
        app.scheduler = self.original_scheduler
        app.sns = self.original_sns

    def make_event(
        self,
        claims=None,
        request_id="req-123",
        body=None
    ):
        if claims is None:
            claims = {
                "sub": "approver-123",
                "email": "manager@example.com",
                "cognito:groups": "[approvers]"
            }

        if body is None:
            body = {
                "decision": "approve"
            }

        return {
            "requestContext": {
                "authorizer": {
                    "jwt": {
                        "claims": claims
                    }
                }
            },
            "pathParameters": {
                "requestId": request_id
            },
            "body": json.dumps(body)
        }

    def test_missing_authorization_returns_401(self):
        event = {
            "requestContext": {}
        }

        response = app.handler(event, None)

        self.assertEqual(response["statusCode"], 401)

    def test_non_approver_returns_403(self):
        event = self.make_event(
            claims={
                "sub": "employee-123",
                "email": "employee@example.com",
                "cognito:groups": "[employees]"
            }
        )

        response = app.handler(event, None)

        self.assertEqual(response["statusCode"], 403)

    def test_missing_request_id_returns_400(self):
        event = self.make_event(request_id=None)

        event["pathParameters"] = {}

        response = app.handler(event, None)

        self.assertEqual(response["statusCode"], 400)

    def test_invalid_json_returns_400(self):
        event = self.make_event()
        event["body"] = "{invalid json"

        response = app.handler(event, None)

        self.assertEqual(response["statusCode"], 400)

    def test_invalid_decision_returns_400(self):
        event = self.make_event(
            body={
                "decision": "maybe"
            }
        )

        response = app.handler(event, None)

        self.assertEqual(response["statusCode"], 400)

    def test_request_not_found_returns_404(self):
        self.table.get_item.return_value = {}

        event = self.make_event()

        response = app.handler(event, None)

        self.assertEqual(response["statusCode"], 404)
        self.assertEqual(self.iam.put_role_policy.call_count, 0)
        self.assertEqual(self.scheduler.create_schedule.call_count, 0)

    def test_non_pending_request_returns_409(self):
        self.table.get_item.return_value = {
            "Item": {
                "requestId": "req-123",
                "status": "active",
                "permission": "s3-read-demo-bucket",
                "durationMinutes": 60,
            }
        }

        event = self.make_event()

        response = app.handler(event, None)

        self.assertEqual(response["statusCode"], 409)
        self.assertEqual(self.iam.put_role_policy.call_count, 0)
        self.assertEqual(self.scheduler.create_schedule.call_count, 0)

    def test_deny_request_updates_status_and_notifies(self):
        self.table.get_item.return_value = {
            "Item": {
                "requestId": "req-123",
                "permission": "s3-read-demo-bucket",
                "status": "pending",
                "durationMinutes": 60,
            }
        }

        event = self.make_event(
            body={"decision": "deny"}
        )

        response = app.handler(event, None)

        self.assertEqual(response["statusCode"], 200)

        body = json.loads(response["body"])
        self.assertEqual(body["status"], "denied")
        self.assertEqual(body["requestId"], "req-123")

        self.table.update_item.assert_called_once()
        update_kwargs = self.table.update_item.call_args.kwargs
        self.assertEqual(
            update_kwargs["ExpressionAttributeValues"][":status"],
            "denied",
        )
        self.assertEqual(
            update_kwargs["ExpressionAttributeValues"][":by"],
            "manager@example.com",
        )

        self.sns.publish.assert_called_once()
        self.iam.put_role_policy.assert_not_called()
        self.scheduler.create_schedule.assert_not_called()

    def test_approve_request_grants_access_and_schedules_revocation(self):
        self.table.get_item.return_value = {
            "Item": {
                "requestId": "req-123",
                "permission": "s3-read-demo-bucket",
                "status": "pending",
                "durationMinutes": 60,
            }
        }

        event = self.make_event(
            body={"decision": "approve"}
        )

        response = app.handler(event, None)

        self.assertEqual(response["statusCode"], 200)

        body = json.loads(response["body"])
        self.assertEqual(body["requestId"], "req-123")
        self.assertEqual(body["status"], "active")
        self.assertIn("expiresAt", body)

        # Verify the IAM policy was attached to the target role.
        self.iam.put_role_policy.assert_called_once()
        iam_kwargs = self.iam.put_role_policy.call_args.kwargs
        self.assertEqual(
            iam_kwargs["RoleName"],
            "ci-test-target-role",
        )
        self.assertEqual(
            iam_kwargs["PolicyName"],
            "jit-grant-req-123",
        )

        policy = json.loads(iam_kwargs["PolicyDocument"])
        self.assertEqual(
            policy["Statement"][0]["Action"],
            ["s3:GetObject"],
        )

        # Verify automatic revocation was scheduled.
        self.scheduler.create_schedule.assert_called_once()
        schedule_kwargs = self.scheduler.create_schedule.call_args.kwargs
        self.assertEqual(
            schedule_kwargs["Name"],
            "jit-revoke-req-123",
        )
        self.assertEqual(
            schedule_kwargs["GroupName"],
            "ci-test-schedule-group",
        )
        self.assertTrue(
            schedule_kwargs["ScheduleExpression"].startswith("at(")
        )
        self.assertEqual(
            schedule_kwargs["Target"]["Arn"],
            "arn:aws:lambda:us-east-1:000000000000:function:ci-test-revoke",
        )

        # Verify DynamoDB was updated to active.
        self.table.update_item.assert_called_once()
        update_kwargs = self.table.update_item.call_args.kwargs
        values = update_kwargs["ExpressionAttributeValues"]

        self.assertEqual(values[":status"], "active")
        self.assertEqual(values[":sched"], "jit-revoke-req-123")
        self.assertEqual(values[":pol"], "jit-grant-req-123")
        self.assertIn(":exp", values)

        # Verify the lifecycle notification was sent.
        self.sns.publish.assert_called_once()

    def test_scheduler_failure_rolls_back_iam_policy(self):
        from botocore.exceptions import ClientError

        self.table.get_item.return_value = {
            "Item": {
                "requestId": "req-123",
                "permission": "s3-read-demo-bucket",
                "status": "pending",
                "durationMinutes": 60,
            }
        }

        self.scheduler.create_schedule.side_effect = ClientError(
            {
                "Error": {
                    "Code": "InternalServerError",
                    "Message": "Simulated scheduler failure",
                }
            },
            "CreateSchedule",
        )

        event = self.make_event(
            body={"decision": "approve"}
        )

        response = app.handler(event, None)

        self.assertEqual(response["statusCode"], 500)

        body = json.loads(response["body"])
        self.assertIn(
            "Could not schedule the automatic revocation",
            body["message"],
        )

        # IAM grant was attempted first.
        self.iam.put_role_policy.assert_called_once_with(
            RoleName="ci-test-target-role",
            PolicyName="jit-grant-req-123",
            PolicyDocument=unittest.mock.ANY,
        )

        # The newly granted policy must be removed.
        self.iam.delete_role_policy.assert_called_once_with(
            RoleName="ci-test-target-role",
            PolicyName="jit-grant-req-123",
        )

        # The request must not be marked active.
        self.table.update_item.assert_not_called()

    def test_iam_grant_failure_returns_500(self):
        from botocore.exceptions import ClientError

        self.table.get_item.return_value = {
            "Item": {
                "requestId": "req-123",
                "permission": "s3-read-demo-bucket",
                "status": "pending",
                "durationMinutes": 60,
            }
        }

        # Simulate AWS IAM refusing to create the policy.
        self.iam.put_role_policy.side_effect = ClientError(
            {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": "Simulated IAM permission error",
                }
            },
            "PutRolePolicy",
        )

        event = self.make_event(body={"decision": "approve"})
        response = app.handler(event, None)

        # The handler should report an internal error.
        self.assertEqual(response["statusCode"], 500)

        # No revocation schedule should be created.
        self.scheduler.create_schedule.assert_not_called()

        # The request should not be marked active.
        self.table.update_item.assert_not_called()


if __name__ == "__main__":
    unittest.main()