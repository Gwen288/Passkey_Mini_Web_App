const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./portal.db');

// ---------------------------------------------------------------------------
// Enrolment codes
//
// Each account is provisioned with a random, single-use enrolment code that is
// printed ONCE when this script runs. Only a SHA-256 hash of the code is stored
// in the database, exactly like a password reset token: the code itself exists
// in neither the repository nor the database file.
//
// Why: the enrolment code is the only thing gating account claim. If it were
// hard-coded here and this file were published, anyone reading the repository
// could claim the privileged Lecturer account (L1) before its real owner.
// ---------------------------------------------------------------------------

function generateEnrolmentCode(userId) {
    return `ENROL-${userId}-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
}

function hashCode(code) {
    return crypto.createHash('sha256').update(code, 'utf8').digest('hex');
}

const accounts = [
    { id: 'S1', name: 'Ama Mensah (Student 1)', role: 'student' },
    { id: 'S2', name: 'Kofi Owusu (Student 2)', role: 'student' },
    { id: 'L1', name: 'Dr. Boateng (Lecturer 1)', role: 'lecturer' }
];

db.serialize(() => {
    // Recreate the schema from scratch so this script is safely re-runnable and
    // always produces a clean demonstration dataset.
    db.run(`DROP TABLE IF EXISTS credentials`);
    db.run(`DROP TABLE IF EXISTS grades`);
    db.run(`DROP TABLE IF EXISTS users`);

    // 1. Users table.
    //    enrolment_code_hash holds a SHA-256 hash, never the code itself.
    db.run(`
        CREATE TABLE users (
            id TEXT PRIMARY KEY,
            name TEXT,
            role TEXT,
            enrolment_code_hash TEXT,
            current_challenge TEXT
        )
    `);

    // 2. Registered passkey public credentials.
    //    Only the PUBLIC key is stored; the private key stays in the
    //    user's authenticator and is never sent to this server.
    db.run(`
        CREATE TABLE credentials (
            credential_id TEXT PRIMARY KEY,
            user_id TEXT,
            public_key BLOB,
            counter INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `);

    // 3. Mock academic records.
    db.run(`
        CREATE TABLE grades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT,
            course_code TEXT,
            lecturer_id TEXT,
            grade TEXT
        )
    `);

    const issuedCodes = [];

    const stmt = db.prepare(`
        INSERT INTO users (id, name, role, enrolment_code_hash)
        VALUES (?, ?, ?, ?)
    `);

    accounts.forEach(account => {
        const code = generateEnrolmentCode(account.id);

        issuedCodes.push({
            userId: account.id,
            role: account.role,
            code
        });

        stmt.run(
            account.id,
            account.name,
            account.role,
            hashCode(code)
        );
    });

    stmt.finalize(() => {
        console.log('\nDatabase (portal.db) initialised with fictional accounts and grades.\n');
        console.log('ONE-TIME ENROLMENT CODES - shown once, never stored in plaintext:');
        console.log('-----------------------------------------------------------------');
        console.log('  USER ID   ROLE       ENROLMENT CODE');
        issuedCodes.forEach(item => {
            console.log(
                `  ${item.userId.padEnd(9)} ${item.role.padEnd(10)} ${item.code}`
            );
        });
        console.log('-----------------------------------------------------------------');
        console.log('Write these down now. Each code is single-use and cannot be');
        console.log('recovered - re-run "npm run setup" to issue new ones.');
        console.log('Do NOT commit these codes or share them with anyone.\n');
    });

    // 4. Mock IS451 grades: one course, one lecturer, two students.
    const gradeStmt = db.prepare(`
        INSERT INTO grades (student_id, course_code, lecturer_id, grade)
        VALUES (?, ?, ?, ?)
    `);

    gradeStmt.run('S1', 'IS451', 'L1', 'A');
    gradeStmt.run('S2', 'IS451', 'L1', 'B+');

    gradeStmt.finalize();
});

db.close();
