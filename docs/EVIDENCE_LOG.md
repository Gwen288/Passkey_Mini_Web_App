# Evidence Log — Tests T1–T8

**IS451 Assignment 2 — University Student Records Portal**
Test run: **18 October 2026** · Environment: macOS 26.0.1 (Apple Silicon), Node 24.22.0,
Microsoft Edge at `http://localhost:3000`.

> **Redactions.** No enrolment codes, session cookie values, live challenges or unsalted
> credential IDs are reproduced in this document, because this repository is public and the
> brief forbids publishing enrolment codes and session tokens. Enrolment codes are generated
> by `npm run setup` and printed once. Credential IDs are shown truncated.

---

## T1 — Register a genuine passkey for S1, then sign in

**Action.** `npm run setup`, then in the browser: User ID `S1` + the enrolment code printed by
the setup script 
*Create passkey* : macOS Touch ID prompt appeared and *"Passkey registered
successfully. You can now log in." is the expected response.
Then *Continue with passkey* press your Touch ID which shows the dashboard.

**Result: PASS.** The macOS system authenticator prompt is the evidence that this is a real
WebAuthn ceremony rather than a simulated PIN or fingerprint dialog.

**Server-side evidence** — only a public key is stored, never a private key:

```
$ sqlite3 portal.db "SELECT credential_id, user_id, length(public_key), counter FROM credentials;"
E3VV27cB…   | S1 | 77 | 0
```

| Observation | Meaning |
|---|---|
| `public_key` is 77 bytes | COSE-encoded EC P-256 **public** key only |
| No private-key column exists | The private key never left the authenticator |
| `counter = 0` | Signature counter stored for clone detection |
| `enrolment_code_hash` is now `NULL` | The one-time code was consumed |

```
$ sqlite3 portal.db "SELECT id, name, role, enrolment_code_hash IS NULL FROM users;"
S1 | Ama Mensah (Student 1) | student | 1
```

**Enrolment code storage** — only a hash is persisted, and no plaintext code exists in the
database file:

```
$ sqlite3 portal.db "SELECT id, substr(enrolment_code_hash,1,24) FROM users;"
S1 | 657683a316239f91ff0c2b9a…
S2 | f0807b41d9a33e8f4aa40f4c…
L1 | a94132810fecef35b4f09f27…

$ strings portal.db | grep -c "ENROL-"
0
```

---

## T2 — Sign in as S1 and view S1's grades

**Action.** In the browser console while authenticated as S1:

```js
fetch('/api/grades').then(r => r.json()).then(console.log)
```

**Observed:**

```json
{"grades":[{"student_id":"S1","name":"Ama Mensah (Student 1)","course_code":"IS451","grade":"A"}]}
```

**Result: PASS — allowed, and only S1's own record is returned.**

---

## T3 — As S1, request S2's grade record directly by ID

**Action.** Same session (S1), direct API request by ID:

```js
fetch('/api/students/S2/grades').then(async r => console.log(r.status, await r.json()))
```

**Observed:**

```
GET http://localhost:3000/api/students/S2/grades 403 (Forbidden)
403 {error: 'You may only view your own grades.'}
```

**Result: PASS — denied on the server, and no part of S2's record appears in the response.**

Control experiment — requesting S1's own record is still allowed:

```
fetch('/api/students/S1/grades')  →  200 {grades:[{student_id:"S1", … , grade:"A"}]}
```

Client-supplied identity is ignored. Adding `?studentId=S2` to the list endpoint still returns
only S1's row, because the query filters on the **session** user ID:

```js
fetch('/api/grades?studentId=S2').then(r => r.json()).then(console.log)
// {"grades":[{"student_id":"S1", …}]}   ← still only S1
```

**Lecturer scope.** As L1, S2's record is readable (S2 is in L1's course), but a student outside
L1's course is refused — least privilege:

```
fetch('/api/students/S2/grades')  →  200 {grades:[{student_id:"S2", …}]}
fetch('/api/students/S9/grades')  →  403 {error: 'This student is not in your assigned course.'}
```

---

## T4 — As S1, attempt to edit a grade

**Action.** The "Update a grade" form is never rendered for a student, so this test bypasses the
interface entirely and hand-crafts the request from S1's own authenticated session:

```js
fetch('/api/grades', {
  method: 'PATCH',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({studentId: 'S2', grade: 'A'})
}).then(async r => console.log(r.status, await r.json()))
```

**Observed:**

```
PATCH http://localhost:3000/api/grades 403 (Forbidden)
403 {error: 'Lecturer access required.'}
```

**Result: PASS — denied by the `requireLecturer` server middleware.**
This is the test that shows a hidden button is not a security control.

---

## T5 — As L1, update a grade in the assigned course

**Action.** Logged in as L1, the *Update a grade* form is rendered. S2 — Kofi Owusu, grade set to
**B**, *Save grade* → *"Grade updated successfully."* The roster refreshed automatically.

**Observed in the database after the change:**

```
$ sqlite3 portal.db "SELECT student_id, course_code, lecturer_id, grade FROM grades;"
S1 | IS451 | L1 | A
S2 | IS451 | L1 | B      ← was B+ before the update
```

**Result: PASS — allowed, and the change persists across requests.**
The update statement is scoped with `WHERE student_id = ? AND course_code = 'IS451' AND
lecturer_id = ?`, so L1 cannot edit any course they are not assigned to.

---

## T6 — Access a protected resource without signing in, and again after logout

**Action (a) — never signed in:**

```
$ curl -i http://localhost:3000/api/grades
HTTP/1.1 401 Unauthorized
Content-Type: application/json; charset=utf-8
Content-Length: 32
```

**Action (b) — after pressing Log out, from the same browser:**

```js
fetch('/api/grades').then(async r => console.log(r.status, await r.json()))
```

**Observed:**

```
GET http://localhost:3000/api/grades 401 (Unauthorized)
401 {error: 'Please log in first.'}
```

**Result: PASS — denied in both cases.** Logout destroys the server-side session and clears the
cookie, so no protected data is reachable afterwards.

---

## T7 — Attempt sign-in with an unavailable / unregistered passkey

**Action (a) — an account with no registered passkey:**

```
$ curl -s -X POST http://localhost:3000/api/login/options \
    -H 'Content-Type: application/json' -d '{"userId":"S9"}'
{"error":"Account or registered passkey not found."}
```

**Action (b) — a forged assertion carrying an unregistered credential ID**, submitted against a
genuine freshly issued challenge:

```
$ curl -i -X POST http://localhost:3000/api/login/verify \
    -H 'Content-Type: application/json' \
    -d '{"userId":"S1","response":{"id":"totally-fake-credential-id", …}}'
HTTP/1.1 401 Unauthorized
{"error":"Passkey not recognized."}
```

**Action (c) — confirm no session was created:**

```
$ curl -o /dev/null -w "%{http_code}\n" http://localhost:3000/api/me
401
```

**Result: PASS — authentication denied and no session created.**
The challenge was still issued and consumed normally; the rejection came from the
credential lookup and signature verification.

---

## T8 — AES-256-GCM encrypt / decrypt / tamper rejection

**Action:**

```
$ npm run crypto-demo
```

**Observed:**

```
Original Plaintext: Student consultation note – demonstration data only

Encrypted Ciphertext: 666e468ce8644520cee6f7904a335fb8aa0e4981e36f8a1f41984862f8d2d9ac16506f69b3a09a797c31e8020da5a4a0d874da0f4f
Authentication Tag:   0887591cd9676dfbf69fe012ffa8aa45

Original decryption successful: Student consultation note – demonstration data only

Tampered Ciphertext:  676e468ce8644520cee6f7904a335fb8aa0e4981e36f8a1f41984862f8d2d9ac16506f69b3a09a797c31e8020da5a4a0d874da0f4f
Tampering detected: decryption rejected because authentication failed.
```

**Result: PASS.** Only the **first byte** differs
(`66 6e` → `67 6e`). The GCM authentication tag no longer verifies, so the library throws
instead of returning corrupted plaintext. Plaintext is recovered only when the ciphertext is
unchanged.

---

## Summary

| Test | Scenario | Expected | Observed | Status |
|---|---|---|---|---|
| T1 | Register genuine passkey for S1, then sign in | Succeeds | Touch ID prompt; public key only stored | **PASS** |
| T2 | S1 views own grades | Allowed | `200`, own record only | **PASS** |
| T3 | S1 requests S2's record by ID | Denied | `403`, no S2 data | **PASS** |
| T4 | S1 attempts a grade edit | Denied server-side | `403` "Lecturer access required." | **PASS** |
| T5 | L1 updates a grade in assigned course | Allowed, persists | `B+` → `B` in database | **PASS** |
| T6 | Protected resource with no session, then after logout | Denied both times | `401` both times | **PASS** |
| T7 | Sign-in with an unregistered passkey | Denied, no session | `401`, `/api/me` → `401` | **PASS** |
| T8 | AES-GCM encrypt/decrypt, then tamper | Tamper rejected | Auth-tag failure on 1 changed byte | **PASS** |

