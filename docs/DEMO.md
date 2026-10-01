# JIT Access Manager: Demo Script

A walkthrough of the full request, approve, expire and revoke lifecycle. All commands are PowerShell, run from the repo root.

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

## 1. Baseline: the target role has no permissions

```powershell
aws iam list-role-policies --role-name jit-access-dev-target-role
```

Expected: `"PolicyNames": []`

## 2. Employee requests a time-boxed permission

```powershell
$new = Invoke-RestMethod -Method Post -Uri "$API/requests" `
  -Headers @{ Authorization = "Bearer $EMP" } -ContentType "application/json" `
  -Body '{"permission":"s3-read-demo-bucket","durationMinutes":2,"reason":"demo walkthrough"}'
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

Expected: `status: active` with an `expiresAt` timestamp.

## 5. The grant is real

```powershell
aws iam list-role-policies --role-name jit-access-dev-target-role
```

Expected: one policy named `jit-grant-<requestId>`.

## 6. Automatic revocation

Wait for the duration to pass (about 2 minutes), with no manual action, then:

```powershell
aws iam list-role-policies --role-name jit-access-dev-target-role
aws dynamodb get-item --table-name jit-access-dev-requests `
  --key ('{\"requestId\":{\"S\":\"' + $new.requestId + '\"}}') --region us-east-1
```

Expected: `PolicyNames` is empty, and the row shows `status: expired` and `revokedBy: scheduler`.

## 7. Manual early revoke

Create a 10-minute request, approve it as the manager, then revoke it:

```powershell
Invoke-RestMethod -Method Delete -Uri "$API/requests/$($new.requestId)" `
  -Headers @{ Authorization = "Bearer $TOKEN" }
```

Expected: `status: revoked_early`, the policy disappears immediately, and the row shows the manager in `revokedBy`. The original schedule still fires later and is a harmless no-op, because `revoke_access` is idempotent.

## 8. Employee views their own history

```powershell
Invoke-RestMethod -Uri "$API/requests" -Headers @{ Authorization = "Bearer $EMP" }
```

## Key design points to mention

- Requests come from a fixed catalog of safe, read-only permissions, never arbitrary IAM JSON.
- Approval attaches one scoped inline policy and creates the EventBridge Scheduler revoke in the same action.
- Every request keeps an audit trail: requester, approver, timestamps, and who revoked it.
- Genuine IAM failures during revocation are re-raised so they surface as Lambda errors (alarm planned in Phase 3).
