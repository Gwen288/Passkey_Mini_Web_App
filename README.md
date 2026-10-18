# University Student Records Portal — WebAuthn Passkeys and Role-Based Access Control

**IS451 Assignment 2.** A small local web application in which Student and Lecturer accounts
sign in with a **genuine WebAuthn/FIDO2 passkey** instead of a password, and in which every
access decision is enforced on the **server**.

One mock course (IS451) is taught by Lecturer **L1** and taken by students **S1** and **S2**.
All names, user IDs, courses and grades are fictional demonstration data.

---

## 1. Tools and versions

| Component | Version |
|---|---|
| Node.js | 24.22.0 (LTS) — minimum 20.17.0 |
| npm | 11.19.1 |
| Express | 5.3.0 |
| express-session | 1.19.0 |
| sqlite3 (SQLite 3.52.0) | 6.0.1 |
| @simplewebauthn/server | 14.0.3 |
| @simplewebauthn/browser | 14.0.0 |
| Browser tested | Safari / Chrome / Edge on macOS 26 (Apple Silicon) |

`npm install` reports **153 packages audited, 0 vulnerabilities**. Exact transitive versions are
frozen in `package-lock.json`.

## 2. Install, seed and run

Requires Node.js ≥ 20.17 and a modern browser on the **same machine** as the server.

```bash
npm install       # restore pinned dependencies from package-lock.json
npm run setup     # create portal.db and issue one-time enrolment codes
npm start         # serve http://localhost:3000
```

`npm run setup` creates the SQLite database, inserts the three accounts and the IS451 grades,
then **prints the one-time enrolment codes** for each account. Only a SHA-256 hash of each code
is stored, so **the codes are shown once and cannot be recovered** — write them down. Re-running
`npm run setup` fully resets the database and issues new codes.

Independent of the portal, the cryptography demonstration can be run on its own:

```bash
npm run crypto-demo   # AES-256-GCM encrypt / decrypt / tamper-rejection (test T8)
```

> **Open the site at `http://localhost:3000` exactly.** The server pins the WebAuthn
> relying-party ID to `localhost` and the expected origin to `http://localhost:3000`.
> `127.0.0.1`, a LAN address or an HTTPS proxy will be rejected by design.

## 3. Test accounts

| User ID | Name | Role | Permitted operations |
|---|---|---|---|
| **S1** | Ama Mensah | student | View **own** profile and grades only |
| **S2** | Kofi Owusu | student | View **own** profile and grades only |
| **L1** | Dr. Boateng | lecturer | View the IS451 roster; edit grades **in IS451 only** |

Neither role may assign or change user roles — no such endpoint exists.

Enrolment codes are **not** stored in this repository or in the database in plaintext.
Run `npm run setup` to generate them.

## 4. Safe passkey enrolment procedure

1. Run `npm run setup` and record the printed enrolment codes.
2. Open `http://localhost:3000`.
3. Under **Register a passkey**, select the **User ID** (`S1`, `S2` or `L1`) and type that
   account's **one-time enrolment code**.
4. Click **Create passkey** and approve the operating-system prompt
   (Touch ID / Windows Hello / external FIDO2 key).

The role is **never chosen by the user** — it is read from the database row for the claimed
User ID, so a student cannot request the Lecturer role. A successful registration consumes the
enrolment code and closes enrolment for that account, and a second passkey for the same account
is refused.

## 5. Enrolling on a different device (for an examiner)

A passkey is bound to the authenticator that created it, so the passkey registered on our
machines **cannot** be used from yours. To enrol on your own device:

1. Run `npm run setup`. This clears any previously registered credentials and issues fresh
   one-time enrolment codes.
2. Open `http://localhost:3000` **on your own machine**.
3. Choose a User ID, enter the code printed in step 1, and approve your own
   Touch ID / Windows Hello prompt.

Your authenticator generates a new key pair; the server stores only your new public key.

## 6. Repeating the tests T1–T8

Full commands and observed outputs are recorded in the accompanying evidence log. Summary:

| Test | How to repeat it | Expected |
|---|---|---|
| T1 | Register a passkey for S1, then log in with it | Registration and login succeed |
| T2 | Log in as S1; the dashboard shows IS451 grade | Allowed |
| T3 | Console: `fetch('/api/students/S2/grades')` while signed in as S1 | `403`, no S2 data |
| T4 | Console: `PATCH /api/grades` with `{studentId:'S2',grade:'A'}` as S1 | `403` on the server |
| T5 | Log in as L1, change S2's IS451 grade, reload | Allowed; change persists |
| T6 | `curl http://localhost:3000/api/grades` with no session; then repeat after logging out | `401` both times |
| T7 | `POST /api/login/verify` with an unregistered credential ID | `401`, no session created |
| T8 | `npm run crypto-demo` | Plaintext recovered; tampered ciphertext rejected |

## 7. Dependencies

Declared in `package.json`, locked in `package-lock.json`. There are no globally installed
tools and no other runtime dependencies. The WebAuthn browser bundle is served locally from
`node_modules/@simplewebauthn/browser/dist/bundle` at `/webauthn/index.umd.min.js`, so the page
makes no third-party network requests.

## 8. Known limitations

Notable limitations, discussed fully in the accompanying security report:

- Account provisioning uses one-time codes with **no identity proofing**.
- Each account holds a **single** passkey; there is no account-recovery route.
- `SESSION_SECRET` is randomised at each server start, so **restarting the server logs everyone
  out**. Setting a `SESSION_SECRET` in the environment keeps sessions across restarts during a demo.
- The session cookie is `httpOnly` and `SameSite=Lax` but not `Secure`, because localhost is
  HTTP-only. Production requires HTTPS with `Secure` cookies.
- There is no rate limiting, auditing or logging of access decisions.
