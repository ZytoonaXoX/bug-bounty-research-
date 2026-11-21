# Account Enumeration via Password-Reset and Registration Verification-Code Endpoints

**Platform:** example.com
**Reported via:** HackerOne
**Researcher:** zyt00naxox
**Severity:** Low–Medium — CWE-203 (Observable Discrepancy)

## Summary

Two separate endpoints on the target application leak whether a given email address is a registered account, based solely on the HTTP status code and response body returned. No authentication, CAPTCHA, or meaningful rate-limiting prevents an attacker from querying either endpoint repeatedly, making it possible to build a list of valid, registered email addresses on the platform.

This is a classic **Account Enumeration** vulnerability (CWE-203: Observable Discrepancy), present in two independent locations that reinforce each other as cross-validating oracles.

---

## Finding 1 — Account Enumeration via Password-Reset Verification-Code Endpoint

**Endpoint:** `POST https://example.com/api/forgot-password/verification-code/send`

### Description
When an attacker submits an email address to this endpoint (along with any arbitrary password value in the request), the server's response differs depending on whether that email belongs to a registered account.

### Behavior

**If the account exists:**
- The UI shows a message confirming the verification code was sent.
- The raw API response returns:
```json
{"result": true}
```

**If the account does not exist:**
- The UI shows a message stating the email is not registered.
- The raw API response returns:
```json
{
  "error": true,
  "url": "http://www.example.com/api/forgot-password/verification-code/send",
  "statusCode": 400,
  "statusMessage": "Server Error",
  "data": {
    "errorCode": "<NUM>",
    "reqId": "<ID>",
    "i18nMessageKey": "FORGOT_PASSWORD_USER_NOT_FOUND"
  }
}
```

### Steps to Reproduce
1. Send a `POST` request to `/api/forgot-password/verification-code/send` with a candidate email address.
2. Observe the HTTP status code and response body.
3. A `200` response with `{"result":true}` confirms the email is registered.
4. A `400` response with `errorCode` and `i18nMessageKey: "FORGOT_PASSWORD_USER_NOT_FOUND"` confirms the email is **not** registered.
5. Repeat with different email addresses to enumerate valid accounts.

---

## Finding 2 — Account Enumeration via Registration Verification-Code Endpoint

**Endpoint:** `POST https://example.com/mainsite/api/v1/register/verification-code/send`

### Description
The same root-cause flaw exists on the registration flow's verification-code endpoint, acting as a second, independent oracle for the same class of information.

### Behavior

**If the account does not exist (unregistered email — free to register):**
```
HTTP/2 200 OK
(empty body)
```

**If the account already exists (registered email):**
```
HTTP/2 400 Bad Request
```
```json
{
  "error": true,
  "url": "http://www.example.com/api/register/verification-code/send",
  "statusCode": 400,
  "statusMessage": "Server Error",
  "message": "",
  "data": {
    "errorCode": "<NUM>",
    "reqId": "<ID>",
    "i18nMessageKey": "REGISTER_ACCOUNT_EXISTS_EMAIL"
  }
}
```

### Steps to Reproduce
1. Send a `POST` request to `/mainsite/api/v1/register/verification-code/send` with a candidate email address.
2. A `200` response with an empty body confirms the email is **not** registered.
3. A `400` response with `errorCode` and `i18nMessageKey: "REGISTER_ACCOUNT_EXISTS_EMAIL"` confirms the email **is already registered**.
4. Repeat with different email addresses to enumerate valid accounts.

---

## Impact

Combining both endpoints gives an attacker two independent, mutually-confirming oracles to:
- Build a list of valid, registered email addresses tied to the platform.
- Support targeted phishing campaigns against confirmed users.
- Prioritize targets for credential-stuffing attacks (only testing passwords against emails known to be registered).
- Confirm whether a specific individual or organization uses the service — a privacy exposure in itself.

Neither endpoint requires authentication, and no CAPTCHA or per-IP rate limiting blocks automated, bulk querying — only a short per-address resend cooldown exists, which does not meaningfully prevent large-scale enumeration.

---
