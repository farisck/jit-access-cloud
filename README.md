# JIT Access Manager

A just-in-time privileged access platform on AWS — Cloud Computing capstone project.

An employee requests a specific, time-boxed elevated permission. A manager
approves or denies it. If approved, the permission is granted immediately
and **automatically revoked at the exact requested expiry**, with no manual
cleanup step anyone could forget. Every request, grant, and revocation is
logged twice — once in the app's own audit trail, once independently in
CloudTrail — so the two can be cross-checked.

📄 Full proposal: [`docs/JIT_Access_Manager_Proposal.docx`](docs/JIT_Access_Manager_Proposal.docx)

## Why this design is safe to run in a real AWS account

Rather than accepting arbitrary IAM policy JSON from a requester (one typo
away from granting real admin), the system only ever grants from a small,
fixed **permission catalog** defined in the CloudFormation template:

- `s3-read-demo-bucket` — read-only access to one demo S3 bucket
- `dynamodb-read-requests` — read-only access to the requests table itself

Grants attach to a single, dedicated `TargetRole` that starts with **zero**
permissions. `approve_access` adds exactly one inline policy per grant;
`revoke_access` removes exactly that one policy. Nothing in this system can
ever touch any other role, user, or resource in the account.

## Architecture

![Architecture diagram](docs/architecture.png)

```
Employee → Cognito → API Gateway → request_access → DynamoDB (pending) → SNS (notify approver)
Manager  → Cognito → API Gateway → approve_access  → IAM (grant) + EventBridge Scheduler (schedule revoke)
                                                    ↓ (at expiry, automatically)
                                        EventBridge Scheduler → revoke_access → IAM (revoke) → DynamoDB (expired)
                                                                              ↓
                                                    CloudWatch · CloudTrail · SNS · Budgets
```

## Status

| Phase | What it builds | Status |
|---|---|---|
| 1 — Foundation | Cognito (+ approvers group), requests table, demo bucket, target IAM role, SNS | 🔜 Ready to deploy |
| 2 — Compute | 4 Lambdas, HTTP API, Cognito authorizer, EventBridge Scheduler wiring | 🔜 Ready to deploy |
| 3 — Monitoring | CloudWatch alarms (especially on failed revocations), CloudTrail, Budgets | ✅ Failed-revocation alarm complete; CloudTrail and Budgets planned |

## Repo layout

```
jit-access-cloud/
├── infra/cloudformation/
│   ├── 01-foundation.yaml    # Cognito, DynamoDB, demo bucket, target role, SNS
│   └── 02-compute-api.yaml   # 4 Lambdas + HTTP API + Cognito authorizer + Scheduler
├── lambda/
│   ├── request_access/       # POST /requests
│   ├── approve_access/       # POST /requests/{id}/approve — the core grant logic
│   ├── revoke_access/        # DELETE /requests/{id} (manual) + EventBridge target (automatic)
│   └── list_requests/        # GET /requests[?status=pending]
├── docs/
│   ├── JIT_Access_Manager_Proposal.docx
│   └── architecture.png
```

## Prerequisites

- AWS CLI v2, configured (`aws configure`)
- Region: `us-east-1` (used throughout the commands below)

## Deploying

```bash
# Phase 1 — Foundation
aws cloudformation deploy \
  --template-file infra/cloudformation/01-foundation.yaml \
  --stack-name jit-access-dev-foundation \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1

# One-time: create a bucket to hold packaged Lambda artifacts
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
aws s3 mb "s3://jit-access-dev-lambda-artifacts-${ACCOUNT_ID}" --region us-east-1

# Phase 2 — Compute: package (zips each Lambda folder, uploads to S3),
# then deploy the PACKAGED template (not the original)
aws cloudformation package \
  --template-file infra/cloudformation/02-compute-api.yaml \
  --s3-bucket "jit-access-dev-lambda-artifacts-${ACCOUNT_ID}" \
  --output-template-file infra/cloudformation/02-compute-api.packaged.yaml

aws cloudformation deploy \
  --template-file infra/cloudformation/02-compute-api.packaged.yaml \
  --stack-name jit-access-dev-compute \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1

# Get the API endpoint
aws cloudformation describe-stacks --stack-name jit-access-dev-compute \
  --query "Stacks[0].Outputs" --region us-east-1
```

## Setting up a demo requester and approver

```bash
POOL_ID=$(aws cloudformation describe-stacks --stack-name jit-access-dev-foundation \
  --query "Stacks[0].Outputs[?OutputKey=='UserPoolId'].OutputValue" --output text --region us-east-1)
CLIENT_ID=$(aws cloudformation describe-stacks --stack-name jit-access-dev-foundation \
  --query "Stacks[0].Outputs[?OutputKey=='UserPoolClientId'].OutputValue" --output text --region us-east-1)

# Requester
aws cognito-idp admin-create-user --user-pool-id $POOL_ID --username employee@example.com \
  --temporary-password 'TempPass123!' --message-action SUPPRESS --region us-east-1
aws cognito-idp admin-set-user-password --user-pool-id $POOL_ID --username employee@example.com \
  --password 'RealPass123!' --permanent --region us-east-1

# Approver — same steps, then add to the approvers group
aws cognito-idp admin-create-user --user-pool-id $POOL_ID --username manager@example.com \
  --temporary-password 'TempPass123!' --message-action SUPPRESS --region us-east-1
aws cognito-idp admin-set-user-password --user-pool-id $POOL_ID --username manager@example.com \
  --password 'RealPass123!' --permanent --region us-east-1
aws cognito-idp admin-add-user-to-group --user-pool-id $POOL_ID --username manager@example.com \
  --group-name approvers --region us-east-1
```

## Demo flow

1. Sign in as the employee, `POST /requests` with `{"permission": "s3-read-demo-bucket", "reason": "debugging", "durationMinutes": 5}`
2. Sign in as the manager, `POST /requests/{requestId}/approve` with `{"decision": "approve"}`
3. Immediately after: `aws iam list-role-policies --role-name jit-access-dev-target-role` — the grant is there
4. Wait 5+ minutes (or whatever duration you used)
5. `aws iam list-role-policies --role-name jit-access-dev-target-role` again — the grant is gone, with no manual step taken
6. Check DynamoDB — the request's status moved from `pending` → `active` → `expired`, each with a timestamp
7. Check CloudTrail for the same two IAM events, independently confirming the grant and revocation

## Tearing down

```bash
aws cloudformation delete-stack --stack-name jit-access-dev-compute --region us-east-1
aws cloudformation wait stack-delete-complete --stack-name jit-access-dev-compute --region us-east-1
aws cloudformation delete-stack --stack-name jit-access-dev-foundation --region us-east-1
```

The Lambda artifacts bucket isn't managed by any stack — delete it manually:
`aws s3 rb s3://jit-access-dev-lambda-artifacts-<account-id> --force`

## Cost notes

Designed to run inside AWS Free Tier — everything here (Lambda, DynamoDB,
API Gateway, EventBridge Scheduler, SNS, Cognito) has a generous always-free
or 12-month-free allowance. No CloudFront, no NAT Gateway, no customer-
managed KMS key by default.
