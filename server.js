
const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');

const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require('@simplewebauthn/server');

const app = express();
const PORT = 3000;
const rpName = 'University Passkey Portal';
const rpID = 'localhost';
const origin = `http://localhost:${PORT}`;

const db = new sqlite3.Database(path.join(__dirname, 'portal.db'));

app.use(express.json({ limit: '100kb' }));

app.use(session({
    name: 'portal.sid',
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: false,
        maxAge: 15 * 60 * 1000
    }
}));

// Serve the browser's SimpleWebAuthn bundle locally.
app.use('/webauthn', express.static(
    path.join(__dirname, 'node_modules', '@simplewebauthn',
        'browser', 'dist', 'bundle')
));

// Serve the portal interface.
app.use(express.static(path.join(__dirname, 'public')));

// Reject cross-origin browser requests that change data.
app.use((req, res, next) => {
    const changesData = ['POST', 'PATCH', 'PUT', 'DELETE'].includes(req.method);

    if (
        changesData &&
        req.path.startsWith('/api/') &&
        req.get('origin') &&
        req.get('origin') !== origin
    ) {
        return res.status(403).json({ error: 'Request origin rejected.' });
    }

    next();
});

// SQLite promise helpers.
function dbGet(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function dbAll(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

function dbRun(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) reject(err);
            else resolve({ changes: this.changes, lastID: this.lastID });
        });
    });
}

// Enrolment codes are stored only as SHA-256 hashes (see setup.js), so the
// server hashes the submitted code and compares it to the stored hash in
// constant time. This avoids leaking the stored value through timing.
function hashCode(code) {
    return crypto.createHash('sha256').update(code, 'utf8').digest('hex');
}

function codeMatches(submittedCode, storedHash) {
    const submitted = Buffer.from(hashCode(submittedCode), 'hex');
    const stored = Buffer.from(storedHash, 'hex');

    if (submitted.length !== stored.length) return false;

    return crypto.timingSafeEqual(submitted, stored);
}

function requireLogin(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Please log in first.' });
    }
    next();
}

function requireLecturer(req, res, next) {
    if (!req.session.user || req.session.user.role !== 'lecturer') {
        return res.status(403).json({ error: 'Lecturer access required.' });
    }
    next();
}

// Store the challenge with a timestamp so it expires.
async function saveChallenge(userId, challenge) {
    const value = JSON.stringify({
        challenge,
        createdAt: Date.now()
    });

    await dbRun(
        'UPDATE users SET current_challenge = ? WHERE id = ?',
        [value, userId]
    );
}

// Read and consume a challenge exactly once.
async function consumeChallenge(userId) {
    const user = await dbGet(
        'SELECT current_challenge FROM users WHERE id = ?',
        [userId]
    );

    if (!user || !user.current_challenge) {
        throw new Error('Challenge missing or already used.');
    }

    const storedValue = user.current_challenge;

    // Conditional update prevents two requests from consuming the same challenge.
    const result = await dbRun(
        `UPDATE users SET current_challenge = NULL
         WHERE id = ? AND current_challenge = ?`,
        [userId, storedValue]
    );

    if (result.changes !== 1) {
        throw new Error('Challenge has already been used.');
    }

    const data = JSON.parse(storedValue);

    if (Date.now() - data.createdAt > 120000) {
        throw new Error('Challenge expired. Please try again.');
    }

    return data.challenge;
}

function asyncRoute(handler) {
    return (req, res, next) => {
        Promise.resolve(handler(req, res, next)).catch(next);
    };
}

function regenerateSession(req, user) {
    return new Promise((resolve, reject) => {
        req.session.regenerate(err => {
            if (err) return reject(err);

            req.session.user = user;

            req.session.save(saveErr => {
                if (saveErr) reject(saveErr);
                else resolve();
            });
        });
    });
}

// Health check.
app.get('/health', asyncRoute(async (req, res) => {
    const row = await dbGet('SELECT COUNT(*) AS total FROM users');

    res.json({
        status: 'running',
        database: 'connected',
        fictionalUsers: row.total
    });
}));

// REGISTRATION: generate passkey options.
// The ID and enrolment code must match a pre-provisioned account.
app.post('/api/register/options', asyncRoute(async (req, res) => {
    const { userId, enrolmentCode } = req.body;

    if (
        typeof userId !== 'string' ||
        typeof enrolmentCode !== 'string'
    ) {
        return res.status(400).json({ error: 'Enter your user ID and enrolment code.' });
    }

    const user = await dbGet(
        `SELECT id, name, role, enrolment_code_hash FROM users
         WHERE id = ?`,
        [userId]
    );

    // One generic message for both cases: an unknown user ID and a wrong code
    // are indistinguishable, so the endpoint cannot be used to enumerate accounts.
    if (
        !user ||
        !user.enrolment_code_hash ||
        !codeMatches(enrolmentCode, user.enrolment_code_hash)
    ) {
        return res.status(400).json({
            error: 'Invalid user ID or enrolment code.'
        });
    }

    const existing = await dbGet(
        'SELECT COUNT(*) AS total FROM credentials WHERE user_id = ?',
        [user.id]
    );

    if (existing.total > 0) {
        return res.status(409).json({
            error: 'A passkey is already registered for this account.'
        });
    }

    const options = await generateRegistrationOptions({
        rpName,
        rpID,
        userID: new TextEncoder().encode(user.id),
        userName: user.id,
        userDisplayName: user.name,
        attestationType: 'none',
        timeout: 120000,
        authenticatorSelection: {
            residentKey: 'required',
            userVerification: 'preferred'
        }
    });

    await saveChallenge(user.id, options.challenge);

    res.json(options);
}));

// REGISTRATION: verify the authenticator response and save the public key.
app.post('/api/register/verify', asyncRoute(async (req, res) => {
    const { userId, response } = req.body;

    const user = await dbGet(
        `SELECT id, name, role, enrolment_code_hash
         FROM users WHERE id = ?`,
        [userId]
    );

    // A missing hash means the code was already consumed at an earlier
    // registration, so this account is no longer open for enrolment.
    if (!user || !user.enrolment_code_hash) {
        return res.status(400).json({
            error: 'Registration is unavailable for this account.'
        });
    }

    const challenge = await consumeChallenge(user.id);

    const verification = await verifyRegistrationResponse({
        response,
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: false
    });

    if (!verification.verified || !verification.registrationInfo) {
        return res.status(400).json({
            error: 'Passkey registration could not be verified.'
        });
    }

    const credential = verification.registrationInfo.credential;

    // Prevent an already-used credential ID from being registered again.
    await dbRun(
        `INSERT INTO credentials
         (credential_id, user_id, public_key, counter)
         VALUES (?, ?, ?, ?)`,
        [
            credential.id,
            user.id,
            Buffer.from(credential.publicKey),
            credential.counter
        ]
    );

    // The enrolment code is single-use: clearing the hash closes enrolment.
    await dbRun(
        'UPDATE users SET enrolment_code_hash = NULL WHERE id = ?',
        [user.id]
    );

    res.json({
        verified: true,
        message: 'Passkey registered successfully. You can now log in.'
    });
}));

// LOGIN: generate authentication options for the requested account.
app.post('/api/login/options', asyncRoute(async (req, res) => {
    const { userId } = req.body;

    if (typeof userId !== 'string') {
        return res.status(400).json({ error: 'Enter your user ID.' });
    }

    const user = await dbGet(
        'SELECT id FROM users WHERE id = ?',
        [userId]
    );

    const credentials = user
        ? await dbAll(
            'SELECT credential_id FROM credentials WHERE user_id = ?',
            [user.id]
        )
        : [];

    if (!user || credentials.length === 0) {
        return res.status(400).json({
            error: 'Account or registered passkey not found.'
        });
    }

    const options = await generateAuthenticationOptions({
        rpID,
        timeout: 120000,
        userVerification: 'preferred',
        allowCredentials: credentials.map(item => ({
            id: item.credential_id
        }))
    });

    await saveChallenge(user.id, options.challenge);

    res.json(options);
}));

// LOGIN: verify the signed response before creating a session.
app.post('/api/login/verify', asyncRoute(async (req, res) => {
    const { userId, response } = req.body;

    const user = await dbGet(
        'SELECT id, name, role FROM users WHERE id = ?',
        [userId]
    );

    if (!user || !response || typeof response.id !== 'string') {
        return res.status(400).json({ error: 'Invalid login request.' });
    }

    const challenge = await consumeChallenge(user.id);

    const credential = await dbGet(
        `SELECT credential_id, public_key, counter
         FROM credentials
         WHERE credential_id = ? AND user_id = ?`,
        [response.id, user.id]
    );

    if (!credential) {
        return res.status(401).json({ error: 'Passkey not recognized.' });
    }

    const verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: false,
        credential: {
            id: credential.credential_id,
            publicKey: new Uint8Array(credential.public_key),
            counter: credential.counter
        }
    });

    if (!verification.verified) {
        return res.status(401).json({ error: 'Passkey verification failed.' });
    }

    await dbRun(
        'UPDATE credentials SET counter = ? WHERE credential_id = ?',
        [verification.authenticationInfo.newCounter, credential.credential_id]
    );

    await regenerateSession(req, {
        id: user.id,
        name: user.name,
        role: user.role
    });

    res.json({ success: true, user });
}));

// Return the authenticated user's identity and role.
app.get('/api/me', requireLogin, (req, res) => {
    res.json({ user: req.session.user });
});

// Students receive only their own grade.
// Lecturer receives the IS451 roster for their assigned course.
app.get('/api/grades', requireLogin, asyncRoute(async (req, res) => {
    const user = req.session.user;

    let grades;

    if (user.role === 'student') {
        grades = await dbAll(
            `SELECT g.student_id, u.name, g.course_code, g.grade
             FROM grades g
             JOIN users u ON u.id = g.student_id
             WHERE g.student_id = ?`,
            [user.id]
        );
    } else if (user.role === 'lecturer') {
        grades = await dbAll(
            `SELECT g.student_id, u.name, g.course_code, g.grade
             FROM grades g
             JOIN users u ON u.id = g.student_id
             WHERE g.lecturer_id = ? AND g.course_code = 'IS451'`,
            [user.id]
        );
    } else {
        return res.status(403).json({ error: 'Access denied.' });
    }

    res.json({ grades });
}));

// Per-student grade lookup by ID (test T3).
// A student may read only their OWN record: the identity in the URL is
// compared against the authenticated session, never against client input.
// A lecturer may read only records for the course they are assigned to.
app.get('/api/students/:id/grades', requireLogin, asyncRoute(async (req, res) => {
    const targetId = req.params.id;
    const user = req.session.user;

    if (user.role === 'student') {
        // Ownership check. The message reveals nothing about the other student.
        if (user.id !== targetId) {
            return res.status(403).json({
                error: 'You may only view your own grades.'
            });
        }
    } else if (user.role === 'lecturer') {
        // Course-assignment check.
        const assigned = await dbGet(
            `SELECT 1 AS allowed FROM grades
             WHERE student_id = ?
               AND course_code = 'IS451'
               AND lecturer_id = ?`,
            [targetId, user.id]
        );

        if (!assigned) {
            return res.status(403).json({
                error: 'This student is not in your assigned course.'
            });
        }
    } else {
        return res.status(403).json({ error: 'Access denied.' });
    }

    const grades = await dbAll(
        `SELECT g.student_id, u.name, g.course_code, g.grade
         FROM grades g
         JOIN users u ON u.id = g.student_id
         WHERE g.student_id = ?`,
        [targetId]
    );

    res.json({ grades });
}));

// Only the assigned lecturer can update existing IS451 grades.
app.patch('/api/grades', requireLogin, requireLecturer, asyncRoute(async (req, res) => {
    const { studentId, grade } = req.body;
    const allowedGrades = [
        'A', 'A-', 'B+', 'B', 'B-', 'C+', 'C', 'C-', 'D', 'F'
    ];

    if (
        typeof studentId !== 'string' ||
        !allowedGrades.includes(grade)
    ) {
        return res.status(400).json({ error: 'Invalid student or grade.' });
    }

    const result = await dbRun(
        `UPDATE grades SET grade = ?
         WHERE student_id = ?
           AND course_code = 'IS451'
           AND lecturer_id = ?`,
        [grade, studentId, req.session.user.id]
    );

    if (result.changes !== 1) {
        return res.status(403).json({
            error: 'No authorised IS451 grade was updated.'
        });
    }

    res.json({ success: true, message: 'Grade updated successfully.' });
}));

// Destroy the session on logout.
app.post('/api/logout', requireLogin, (req, res, next) => {
    req.session.destroy(err => {
        if (err) return next(err);

        res.clearCookie('portal.sid', {
            httpOnly: true,
            sameSite: 'lax',
            secure: false
        });

        res.json({ success: true, message: 'Logged out successfully.' });
    });
});

// Return generic errors to the browser; log details on the server.
app.use((err, req, res, next) => {
    console.error(err);

    if (res.headersSent) return next(err);

    res.status(400).json({
        error: 'The request could not be completed. Please try again.'
    });
});

const server = app.listen(PORT, () => {
    console.log(`Portal running at ${origin}`);
});

process.on('SIGINT', () => {
    server.close(() => {
        db.close(() => {
            console.log('Server and database connection closed.');
            process.exit(0);
        });
    });
});
