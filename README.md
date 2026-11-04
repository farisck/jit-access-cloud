[![JIT Access CI](https://github.com/farisck/jit-access-cloud/actions/workflows/hello.yml/badge.svg)](https://github.com/farisck/jit-access-cloud/actions/workflows/hello.yml)

[![codecov](https://codecov.io/github/farisck/jit-access-cloud/graph/badge.svg)](https://codecov.io/github/farisck/jit-access-cloud)

# JIT Access Manager

A just-in-time privileged access platform on AWS — Cloud Computing capstone project.

An employee requests a specific, time-boxed elevated permission for a chosen
access window (a start and an end time). A manager approves or denies it. If
approved, the permission is granted automatically at the start time and
**automatically revoked at the end time**, with no manual cleanup step anyone
could forget. Every request, grant, and revocation is logged in DynamoDB, and
independently visible in the account's CloudTrail history (see note below).

**Live demo:** https://jit.barfs.shop

![Manager view: active grants](docs/screenshots/manager-active-grants.png)

> **Note on CloudTrail and Budgets:** this project doesn't deploy its own
> trail or budget. Both services operate at the AWS account level, not
> per-project, and this account already has a multi-region CloudTrail and
> a monthly Budget (originally set up for a separate project). Since they
> already capture every API call and every dollar spent account-wide, a
> second, JIT-specific trail and budget would be redundant. Confirmed by
> directly querying CloudTrail for this project's own `PutRolePolicy` and
> `DeleteRolePolicy` events — both show up correctly.

📄 Full proposal: [`docs/JIT_Access_Manager_Proposal.docx`](docs/JIT_Access_Manager_Proposal.docx)
🖥️ Frontend: [`frontend/index.html`](frontend/index.html) — a standalone dashboard, no build step required

## Why this design is safe to run in a real AWS account

Rather than accepting arbitrary IAM policy JSON from a requester (one typo
away from granting real admin), the system only ever grants from a small,
fixed **permission catalog** defined in the CloudFormation template:

- `s3-read-demo-bucket` — read-only access to one demo S3 bucket
- `dynamodb-read-requests` — read-only access to the requests table itself

Grants attach to a single, dedicated `TargetRole` that starts with **zero**
permissions. Each grant is exactly one inline policy named
`jit-grant-<requestId>`. It is added by `activate_access` at the start time
(or by `approve_access` for the older duration-only requests) and removed by
`revoke_access`, with `reconcile_cleanup` as a fallback. Nothing in this
system can ever touch any other role, user, or resource in the account.

## Access windows

A request names a permission, a reason, and an access window. The start and
end must be in the future when the request is made, include a timezone, and
span a whole number of minutes. The window length is capped (8 hours by
default). The older duration-only request (grant now for N minutes) is still
accepted by the API.

| Status | Meaning |
|---|---|
| Pending | Waiting for a manager |
| Scheduled | Approved; nothing is granted until the start time |
| Active | The grant exists on the target role until the window ends |
| Expired | The window ended and the grant was removed |
| Revoked | Ended early by an approver or the requester |
| Denied | Rejected by a manager; nothing was granted |

Behind the scenes there are two short-lived internal states, `activating`
and `cleanup_pending`, used while access is being granted or removed.

Rules worth knowing:

- A request must be approved **before** its start time. After that, approval is rejected.
- Approvers cannot approve their own requests.
- Only an approver or the original requester can revoke a grant.

## How access is kept safe

- **Time-limited policies.** Every granted statement carries an `aws:CurrentTime` condition equal to the approved end time, so a grant that lands late can never authorize requests after the window.
- **Race-safe state changes.** Status changes are conditional writes in DynamoDB, so activation, revocation and approval cannot overwrite each other.
- **Cleanup reconciler.** `reconcile_cleanup` runs every 5 minutes. It deletes only the request's own `jit-grant-<requestId>` policy and finalizes a request only after two clean passes at least 30 seconds apart. It also recovers activations stuck past their deadline when a revocation was requested.
- **Safe to repeat.** Revoking an already-ended request does nothing, and a missing policy counts as already removed.
- **Loud failures.** CloudWatch alarms notify the SNS topic when activation, revocation or the reconciler raise an error.
- **Least privilege per function.** Each Lambda has its own role. `request_access` cannot touch IAM at all.

## Architecture

![Architecture diagram](docs/architecture.png)

```
Employee → Cognito → API Gateway → request_access → DynamoDB (pending) → SNS (notify approver)
Manager  → Cognito → API Gateway → approve_access → DynamoDB (scheduled) + EventBridge Scheduler (activation + revocation)
                                                    ↓ at the start time
                              EventBridge Scheduler → activate_access → IAM (grant) → DynamoDB (active)
                                                    ↓ at the end time, or on manual revoke
                              EventBridge Scheduler → revoke_access → IAM (revoke) → DynamoDB (expired / revoked early)
Every 5 minutes:  EventBridge Scheduler → reconcile_cleanup → finishes any revocation that could not be completed safely
                              CloudWatch alarms on failed activation, revocation and cleanup · account-wide CloudTrail
```

Frontend delivery:

```
Browser → https://jit.barfs.shop → CloudFront (ACM certificate) → private S3 bucket (index.html)
Browser → API Gateway (Cognito-authenticated calls)
```

Both the employee and manager use the same dashboard (`frontend/index.html`)
instead of calling the API directly — see **Frontend** below.

## Status

| Phase | What it builds | Status |
|---|---|---|
| 1 — Foundation | Cognito (+ approvers group), requests table, demo bucket, target IAM role, SNS | ✅ Deployed |
| 2 — Compute | 6 Lambdas, HTTP API, Cognito authorizer, EventBridge Scheduler wiring (scheduled activation and revocation, cleanup reconciler) | ✅ Deployed and tested end-to-end |
| 3 — Monitoring | CloudWatch alarms on failed activation, revocation and cleanup | ✅ Deployed and tested |
| 3 — Monitoring (cont.) | CloudTrail, AWS Budgets | ✅ Covered by an existing account-wide trail and budget (see note above) |
| Frontend | Employee/manager dashboard (light and dark modes) | ✅ Built, tested, and live |
| Hosting | Private S3 bucket + CloudFront + ACM certificate + custom domain | ✅ Live at https://jit.barfs.shop |

## Repo layout

```
jit-access-cloud/
├── infra/cloudformation/
│   ├── 01-foundation.yaml    # Cognito, DynamoDB, demo bucket, target role, SNS
│   ├── 02-compute-api.yaml   # 6 Lambdas + HTTP API + Cognito authorizer + Scheduler
│   └── 03-monitoring.yaml    # CloudWatch alarms: failed activation, revocation, cleanup
├── lambda/
│   ├── request_access/       # POST /requests
│   ├── approve_access/       # POST /requests/{id}/approve — the core grant logic
│   ├── activate_access/      # EventBridge Scheduler target: grants access at the scheduled start time
│   ├── revoke_access/        # DELETE /requests/{id} (manual) + EventBridge target (automatic)
│   ├── list_requests/        # GET /requests[?status=pending]
│   └── reconcile_cleanup/    # Runs every 5 minutes: finishes revocations that could not be completed safely
├── frontend/
│   ├── index.html            # Standalone employee/manager dashboard (no build step)
│   ├── favicon.ico
│   └── favicon.svg
├── tests/                    # Python unit tests
├── docs/
│   ├── JIT_Access_Manager_Proposal.docx
│   ├── DEMO.md               # Full step-by-step demo walkthrough
│   ├── architecture.png
│   └── screenshots/          # Dashboard screenshots used in this README
```

## Prerequisites

- AWS CLI v2, configured (`aws configure`)
- Region: `us-east-1` (used throughout the commands below)

## Deploying the backend

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

# Phase 3 — Monitoring (CloudWatch alarm on failed revocations)
aws cloudformation deploy \
  --template-file infra/cloudformation/03-monitoring.yaml \
  --stack-name jit-access-dev-monitoring \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1
```

## Setting up a demo requester and approver

```bash
POOL_ID=$(aws cloudformation describe-stacks --stack-name jit-access-dev-foundation \
  --query "Stacks[0].Outputs[?OutputKey=='UserPoolId'].OutputValue" --output text --region us-east-1)
CLIENT_ID=$(aws cloudformation describe-stacks --stack-name jit-access-dev-foundation \
  --query "Stacks[0].Outputs[?OutputKey=='UserPoolClientId'].OutputValue" --output text --region us-east-1)

# Requester
aws cognito-idp admin-create-user --user-pool-id $POOL_ID --username employee@example.com \
  --temporary-password '<temporary-password>' --message-action SUPPRESS --region us-east-1
aws cognito-idp admin-set-user-password --user-pool-id $POOL_ID --username employee@example.com \
  --password '<your-password>' --permanent --region us-east-1

# Approver — same steps, then add to the approvers group
aws cognito-idp admin-create-user --user-pool-id $POOL_ID --username manager@example.com \
  --temporary-password '<temporary-password>' --message-action SUPPRESS --region us-east-1
aws cognito-idp admin-set-user-password --user-pool-id $POOL_ID --username manager@example.com \
  --password '<your-password>' --permanent --region us-east-1
aws cognito-idp admin-add-user-to-group --user-pool-id $POOL_ID --username manager@example.com \
  --group-name approvers --region us-east-1
```

## Frontend

The dashboard is a single file, `frontend/index.html`, with no build step or
npm install.

It has light and dark modes (toggle in the sidebar) and a responsive layout
that also works on phone-sized screens.

What each user sees:

- **Employee** — **My access** (active grants with a live countdown and pending requests), **Request access** (permission, reason, and an access window with start and end times), and **History** (every request, with its access window and a **Details** timeline)
- **Manager** (must be in the `approvers` Cognito group) — **Approvals** (pending queue with approve/deny), **Active grants** (with a revoke action), and **Access history** (expired, denied and revoked requests)

| Manager: active grants | Manager: access history |
|---|---|
| ![Active grants](docs/screenshots/manager-active-grants.png) | ![Access history](docs/screenshots/manager-access-history.png) |

| Employee: mobile view |
|---|
| ![Mobile view](docs/screenshots/employee-mobile.png) |

### Local testing

From the repo root, serve the `frontend` folder with Python:

```powershell
# Windows (using the project's virtual environment)
.\.venv\Scripts\python.exe -m http.server 5500 -d frontend

# macOS / Linux
python3 -m http.server 5500 -d frontend
```

Then open `http://localhost:5500`.

## Deploying the frontend (S3 + CloudFront)

The frontend is hosted in a **private** S3 bucket (no public access) and
served through CloudFront over HTTPS at **https://jit.barfs.shop**. An ACM
certificate in `us-east-1` provides TLS for the custom domain, and a CNAME
record at the DNS provider (GoDaddy) points `jit` at the CloudFront domain.

> **Two ways to deploy.** A push to `main` that changes anything under
> `frontend/` runs the **Deploy Frontend** GitHub Actions workflow
> (`.github/workflows/deploy-frontend.yml`). It uploads `index.html`,
> `favicon.ico` and `favicon.svg` to S3 and invalidates CloudFront using
> GitHub OIDC, with no stored AWS keys. Pushes to other branches do **not**
> deploy anything, so changes made on a feature branch go live either when
> the branch is merged to `main` or when you upload manually (below).
> The frontend bucket is in `ap-south-1`.

Replace the placeholders with your own values:

```powershell
# 1. Confirm you are in the right AWS account
aws sts get-caller-identity

# 2. Upload the page (no-cache so updates show up quickly)
aws s3 cp frontend\index.html s3://<frontend-bucket>/index.html `
  --content-type "text/html" --cache-control "no-cache" --region ap-south-1

# 3. Upload the favicons
aws s3 cp frontend\favicon.ico s3://<frontend-bucket>/favicon.ico `
  --content-type "image/vnd.microsoft.icon" --cache-control "max-age=86400" --region ap-south-1
aws s3 cp frontend\favicon.svg s3://<frontend-bucket>/favicon.svg `
  --content-type "image/svg+xml" --cache-control "max-age=86400" --region ap-south-1

# 4. Clear CloudFront's cached copies
aws cloudfront create-invalidation --distribution-id <distribution-id> `
  --paths "/index.html" "/favicon.ico" "/favicon.svg"

# 5. Wait for the invalidation to finish (use the Id printed by step 4)
aws cloudfront wait invalidation-completed --distribution-id <distribution-id> --id <invalidation-id>
```

Verify the deployment:

```powershell
curl.exe -I https://jit.barfs.shop/favicon.ico        # expect HTTP 200
curl.exe -s https://jit.barfs.shop/index.html | Measure-Object -Character   # should match the new file's size
```

**DNS troubleshooting tip:** if the custom domain doesn't resolve, compare the
CNAME value at the DNS provider character by character with the CloudFront
domain shown in the console. A single swapped letter produces a hostname that
doesn't exist, and resolvers cache that failure for a while, so a fix can take
up to an hour to show up on some networks.

## Testing and CI

Backend logic is covered by Python unit tests in `tests/` (153 tests at the
last full run), run automatically by GitHub Actions on every push. Coverage
is reported to Codecov (badge at the top), and the CI run fails if coverage
drops below 90%. The tests use mocked AWS clients, so they check the logic
and the exact DynamoDB and IAM calls but not IAM permissions. Permissions
are reviewed in the CloudFormation templates and checked on the live site.

Run the tests locally from the repo root:

```bash
python -m coverage run --include="lambda/*/app.py" -m unittest discover -s tests -v
```

On Windows, with the project's virtual environment:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests
```

Manual end-to-end checks on the live site (employee and manager accounts):

| Check | Expected result |
|---|---|
| Employee submits a request | Appears as **Pending** for the manager |
| Manager approves a request before its start time | Status becomes **Scheduled**, then **Active** at the start time |
| Manager approves after the start time has passed | Rejected (the start must still be in the future) |
| Manager denies | Status becomes **Denied**, no IAM grant created |
| Manager revokes an active grant | Status becomes **Revoked** and the grant leaves Active grants |
| End time passes | Status becomes **Expired** automatically, and the policy is gone from the target role |
| `aws iam list-role-policies --role-name jit-access-dev-target-role` after revoke/expiry | `"PolicyNames": []` |
| Browser console (F12) | No errors |

## Demo flow

For the full 9-step walkthrough (including IAM verification commands and
the automatic-expiry check), see [`docs/DEMO.md`](docs/DEMO.md). Quick
version:

1. Sign in as the employee at https://jit.barfs.shop, open **Request access**, and request a window that starts a few minutes from now (for example, start in 5 minutes, end 15 minutes later) with a realistic reason
2. Sign in as the manager and approve it **before** the start time; the request shows as **Scheduled** under **Active grants**
3. Check the role before the start: `aws iam list-role-policies --role-name jit-access-dev-target-role` shows `"PolicyNames": []`
4. After the start time, run the same command: one policy named `jit-grant-<requestId>`, and the request is **Active** with a countdown
5. Either click **Revoke access**, or wait for the end time
6. Run the IAM command again — `"PolicyNames": []`, with no manual cleanup
7. Open **History** and click **Details** on the request: the timeline shows requested, approved, scheduled window, access granted, and revoked or expired
8. Submit one more request and **deny** it as the manager to show the denied path

## Known limitations

- **Activation race cleanup.** If a revocation lands while an activation is
  in flight, `activate_access` tries to remove the policy it just attached.
  `ActivateAccessRole` needs `iam:DeleteRolePolicy` (scoped to the target
  role) for that. The template includes it, but the deployed stack only has it
  after the compute stack is redeployed from the current files. Until then the
  call is denied, the `activate-failed` alarm fires, and the reconciler removes
  the policy within a few minutes.
- **Stuck activations with no revocation on record.** If a request stays in
  `activating` past its window and no revocation was ever requested, the
  reconciler raises a one-time alert instead of guessing what to do.

## Tearing down

```bash
aws cloudformation delete-stack --stack-name jit-access-dev-monitoring --region us-east-1
aws cloudformation wait stack-delete-complete --stack-name jit-access-dev-monitoring --region us-east-1

aws cloudformation delete-stack --stack-name jit-access-dev-compute --region us-east-1
aws cloudformation wait stack-delete-complete --stack-name jit-access-dev-compute --region us-east-1

aws cloudformation delete-stack --stack-name jit-access-dev-foundation --region us-east-1
```

Resources not managed by these stacks must be removed manually:

- Lambda artifacts bucket: `aws s3 rb s3://jit-access-dev-lambda-artifacts-<account-id> --force`
- Frontend: the S3 bucket, the CloudFront distribution (disable, then delete), the ACM certificate, and the `jit` CNAME record at the DNS provider

## Cost notes

Designed to run inside AWS Free Tier — everything here (Lambda, DynamoDB,
API Gateway, EventBridge Scheduler, SNS, Cognito, CloudWatch) has a generous
always-free or 12-month-free allowance. The public frontend uses S3 and
CloudFront, which are low-cost at demo traffic, and ACM public certificates
are free. No NAT Gateway or customer-managed KMS key is used — the DynamoDB
table uses its default AWS-owned encryption key, which carries no additional
charge.
