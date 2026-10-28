# JIT Access Manager: Demo Script

A walkthrough of the full request, schedule, activate, expire and revoke lifecycle. All commands are PowerShell, run from the repo root.

## Setup

```powershell
$API    = "https://nae7gvq1k2.execute-api.us-east-1.amazonaws.com"
$CLIENT = "7sjnp6kopq95l824inp74pdl8a"

function Get-IdToken($user, $pass) {
  aws cognito-idp initiate-auth `
    --auth-flow USER_PASSWORD_AUTH --client-id $CLIENT `
    --auth-parameters USERNAME=$user,PASSWORD=$pass `
    --region us-east-1 --query "AuthenticationResult.IdToken" --output text
}

$EMP   = Get-IdToken "employee@example.com" "<employee-password>"
$TOKEN = Get-IdToken "manager@example.com"  "<manager-password>"
```

Test users live in the dev Cognito pool only. Do not commit their passwords.

Request submission, approval or denial, and successful manual or scheduled revocation each publish a notification to the SNS topic. Email delivery requires a confirmed email subscription to that topic.

## Public Frontend Deployment

The JIT Access Manager frontend is publicly hosted using Amazon S3 and Amazon CloudFront.

The frontend `index.html` is stored in a private S3 bucket:

`jit-access-dev-frontend-921049725652`

Amazon CloudFront is configured to use the S3 bucket as its origin and serves the frontend over HTTPS.

CloudFront distribution:

- Distribution ID: `EWMBBAFBT5WS4`
- CloudFront domain: `dhdhrgszajmez.cloudfront.net`
- Default root object: `index.html`

A custom domain was configured for public access:

`https://jit.barfs.shop`

AWS Certificate Manager (ACM) provides the SSL/TLS certificate for `jit.barfs.shop`. The certificate was created in the `us-east-1` region, as required for CloudFront.

The custom domain is configured in GoDaddy DNS using the following CNAME record:

```text
jit.barfs.shop → dhdhrgszajmez.cloudfront.net
```

The deployment was verified by accessing the application through the custom HTTPS domain. Employee and manager login functionality were tested successfully, confirming that the public frontend can communicate with the existing API Gateway and backend AWS services without requiring localhost.

The final public frontend URL is:

`https://jit.barfs.shop`

## 1. Baseline: the target role has no permissions

```powershell
aws iam list-role-policies --role-name jit-access-dev-target-role
```

Expected: `"PolicyNames": []`

## 2. Employee requests a time-boxed permission

Access requests name a start and end time. Both must be in the future,
include a timezone, and span a whole number of minutes. This builds a window
that starts 5 minutes from now and lasts 15 minutes:

```powershell
$start = (Get-Date).ToUniversalTime().AddMinutes(5)
$end   = $start.AddMinutes(15)
$body  = @{
  permission    = "s3-read-demo-bucket"
  reason        = "demo walkthrough"
  accessStartAt = $start.ToString("yyyy-MM-ddTHH:mm:ssZ")
  accessEndAt   = $end.ToString("yyyy-MM-ddTHH:mm:ssZ")
} | ConvertTo-Json

$new = Invoke-RestMethod -Method Post -Uri "$API/requests" `
  -Headers @{ Authorization = "Bearer $EMP" } -ContentType "application/json" `
  -Body $body
$new
```

Expected: a `requestId` with `status: pending`. The catalog has two permissions: `s3-read-demo-bucket` and `dynamodb-read-requests`.

## 3. Negative test: employees cannot approve

```powershell
try {
  Invoke-RestMethod -Method Post -Uri "$API/requests/$($new.requestId)/approve" `
    -Headers @{ Authorization = "Bearer $EMP" } -ContentType "application/json" `
    -Body '{"decision":"approve"}'
} catch { $_.Exception.Response.StatusCode.value__; $_.ErrorDetails.Message }
```

Expected: `403` and "Only members of the approvers group may approve or deny requests".

## 4. Manager reviews the queue and approves

```powershell
Invoke-RestMethod -Uri "$API/requests?status=pending" -Headers @{ Authorization = "Bearer $TOKEN" }

Invoke-RestMethod -Method Post -Uri "$API/requests/$($new.requestId)/approve" `
  -Headers @{ Authorization = "Bearer $TOKEN" } -ContentType "application/json" `
  -Body '{"decision":"approve"}'
```

Expected: `status: scheduled`, with `accessStartAt` and `accessEndAt`. Approve before the start time, because approval is rejected once the start has passed. Nothing is granted yet.

## 5. The grant appears at the start time, not before

Right after approval:

```powershell
aws iam list-role-policies --role-name jit-access-dev-target-role
```

Expected: `"PolicyNames": []`. Approval created two schedules but granted nothing.

Wait until the start time has passed (about 5 minutes), then run it again.
Expected: one policy named `jit-grant-<requestId>`, and the request shows `status: active`.

## 6. Automatic revocation

Wait for the end time to pass, with no manual action, then:

```powershell
aws iam list-role-policies --role-name jit-access-dev-target-role
Invoke-RestMethod -Uri "$API/requests" `
  -Headers @{ Authorization = "Bearer $EMP" } |
  Select-Object -ExpandProperty requests |
  Select-Object requestId, status, expiresAt, revokedAt, revokedBy
```

Expected: `PolicyNames` is empty. The request row shows:

```text
status    : expired
revokedBy : scheduler
```

## 7. Manual early revoke

Create a request that starts in 3 minutes (same `$start`/`$end` pattern as step 2, with `AddMinutes(3)`), approve it as the manager, wait until it is active, then revoke it:

```powershell
$start = (Get-Date).ToUniversalTime().AddMinutes(3)
$end   = $start.AddMinutes(15)
$body  = @{
  permission    = "s3-read-demo-bucket"
  reason        = "early revoke demo"
  accessStartAt = $start.ToString("yyyy-MM-ddTHH:mm:ssZ")
  accessEndAt   = $end.ToString("yyyy-MM-ddTHH:mm:ssZ")
} | ConvertTo-Json

$new = Invoke-RestMethod -Method Post -Uri "$API/requests" `
  -Headers @{ Authorization = "Bearer $EMP" } -ContentType "application/json" `
  -Body $body

Invoke-RestMethod -Method Post -Uri "$API/requests/$($new.requestId)/approve" `
  -Headers @{ Authorization = "Bearer $TOKEN" } -ContentType "application/json" `
  -Body '{"decision":"approve"}'

aws iam list-role-policies --role-name jit-access-dev-target-role

Invoke-RestMethod -Method Delete -Uri "$API/requests/$($new.requestId)" `
  -Headers @{ Authorization = "Bearer $TOKEN" }

aws iam list-role-policies --role-name jit-access-dev-target-role
```

Expected: `status: revoked_early`, the policy disappears immediately, and the row shows the manager in `revokedBy`. Manual revoke also cancels the request's schedules.

If you revoke a request while it's still `scheduled`, nothing was ever granted, so there's no policy to remove, and the status goes straight to `revoked_early`.

## 8. Employee views their own history

```powershell
Invoke-RestMethod -Uri "$API/requests" -Headers @{ Authorization = "Bearer $EMP" } |
  Select-Object -ExpandProperty requests |
  Select-Object requestId, permission, status, expiresAt, revokedAt
```

## 9. Failed-revocation alarm

Force the alarm state to demonstrate the notification path:

```powershell
aws cloudwatch set-alarm-state --alarm-name jit-access-dev-revoke-failed `
  --state-value ALARM --state-reason "demo test" --region us-east-1
```

Expected: an `ALARM: "jit-access-dev-revoke-failed"` email within a minute, provided the SNS topic has a confirmed email subscription. In production, the alarm fires when the `revoke_access` Lambda reports an error, indicating that a privileged grant may still be active.

There are three alarms: `jit-access-dev-revoke-failed`, `jit-access-dev-activate-failed` and `jit-access-dev-reconcile-cleanup-failed`. Each fires when its Lambda reports an error.

## Key design points to mention

- Requests come from a fixed catalog of safe, read-only permissions, never arbitrary IAM JSON.
- Approval schedules activation and revocation; the scoped inline policy exists only between the start and end times, and every grant also carries an `aws:CurrentTime` limit.
- A cleanup reconciler runs every 5 minutes and finishes any revocation that could not be completed safely.
- Every request keeps an audit trail: requester, approver, timestamps, and who revoked it.
- Genuine IAM failures during revocation are re-raised so they surface as Lambda errors and trigger the CloudWatch alarm.
