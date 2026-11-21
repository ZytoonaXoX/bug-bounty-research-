# IDOR in `/app-api/enduserapp/profile/{userId}` — Cross-Account PII Disclosure

**Platform:** sub.example.com
**Reported via:** HackerOne
**Researcher:** zyt00naxox
**Severity:** High — CWE-639 (Authorization Bypass Through User-Controlled Key)

---

## Summary

The endpoint `GET /app-api/enduserapp/profile/{userId}` allows any authenticated user to retrieve another user's full profile — including name, email/login, job title, company, address, phone number, website, and avatar URL — simply by supplying that user's numeric `userId`. No ownership, sharing relationship, or enterprise membership is enforced before returning the data.

The vulnerability was independently confirmed in both directions using two unrelated test accounts.

---

## Technical Details

- The endpoint accepts a numeric `userId` as a path parameter and returns the corresponding profile object with no authorization check against the requesting session's own identity or collaboration graph.
- A direct object reference (the raw user ID) is trusted entirely from the client request, with the server performing authentication (is this a valid session?) but not authorization (does this session have any relationship to the requested user?).
- The response behavior itself also creates a secondary issue: valid user IDs return `200 OK`, while non-existent ones return `404 userNotFound` — enabling straightforward user enumeration by iterating sequential or guessed numeric IDs.

---

## Test Accounts Used

| Account | Email | User ID |
|---|---|---|
| A | `Account_A@gmail.com` | `<ID>` |
| B | `Account_B@gmail.com` | `<ID>` |

No sharing, collaboration, or enterprise relationship existed between the two accounts prior to testing — confirmed by requesting Account B's folder contents while authenticated as Account A, which returned an empty result (`{"items":[]}`).

---

## Steps to Reproduce

1. Create and authenticate two separate, unrelated accounts on sub.example.com (Account A and Account B).
2. While authenticated as **Account A**, confirm no sharing relationship exists with Account B (e.g., a request for B's folder contents returns `{"items":[]}`).
3. Still authenticated as Account A, send:
   ```
   GET /app-api/enduserapp/profile/<ID> HTTP/2
   Host: sub.example.com
   Accept: application/json
   ```
4. Observe the server responds `200 OK` with Account B's full profile — including email/login.
5. Reverse the test: authenticated as **Account B**, request:
   ```
   GET /app-api/enduserapp/profile/<ID> HTTP/2
   ```
   Observe `200 OK` with Account A's profile data.
6. Control tests confirming the behavior is ID-driven, not a general auth bypass:
   - A non-existent numeric `userId` → `404 userNotFound`.
   - No authentication/session → `401 sessionExpired`.
   - Requesting one's own `userId` → `200 OK` (expected, legitimate access).

---

## Impact

An attacker with **any** authenticated account on sub.example.com — with no sharing relationship, no shared enterprise, no prior interaction of any kind with the target — can harvest another user's:

- Full name
- Email address / login identifier
- Job title
- Company name
- Physical address
- Phone number
- Website
- Avatar URL

This enables:

- **Mass PII harvesting** by iterating sequential numeric user IDs across the platform.
- **User enumeration**, independent of the PII leak, via the `200`/`404` status-code difference.
- **Targeted phishing and social engineering**, since the disclosed data (name, job title, company, direct phone/email) is exactly what's needed to craft convincing spear-phishing or pretexting attacks against specific employees or organizations using the platform.
- **Privacy/compliance exposure** for organizations relying on the platform, since employee contact and role data can be pulled without their knowledge or any audit trail tied to a legitimate business reason.

---
