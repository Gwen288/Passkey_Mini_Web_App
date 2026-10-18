const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./portal.db');

db.serialize(() => {
    // 1. Create the users table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT,
            role TEXT,
            enrolment_code TEXT,
            current_challenge TEXT
        )
    `);

    // 2. Create the passkey credentials table
    db.run(`
        CREATE TABLE IF NOT EXISTS credentials (
            credential_id TEXT PRIMARY KEY,
            user_id TEXT,
            public_key BLOB,
            counter INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `);

    // 3. Create the grades table
    db.run(`
        CREATE TABLE IF NOT EXISTS grades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT,
            course_code TEXT,
            lecturer_id TEXT,
            grade TEXT
        )
    `);

    // Reset demonstration data
    db.run(`DELETE FROM credentials`);
    db.run(`DELETE FROM grades`);
    db.run(`DELETE FROM users`);

    // 4. Insert two fictional students and one lecturer
    const stmt = db.prepare(`
        INSERT INTO users (id, name, role, enrolment_code)
        VALUES (?, ?, ?, ?)
    `);

    stmt.run('S1', 'Ama Mensah (Student 1)', 'student', 'ENROL-S1-9981');
    stmt.run('S2', 'Kofi Owusu (Student 2)', 'student', 'ENROL-S2-4432');
    stmt.run('L1', 'Dr. Boateng (Lecturer 1)', 'lecturer', 'ENROL-L1-7721');

    stmt.finalize();

    // 5. Insert the mock IS451 grades
    const gradeStmt = db.prepare(`
        INSERT INTO grades (student_id, course_code, lecturer_id, grade)
        VALUES (?, ?, ?, ?)
    `);

    gradeStmt.run('S1', 'IS451', 'L1', 'A');
    gradeStmt.run('S2', 'IS451', 'L1', 'B+');

    gradeStmt.finalize();

    console.log('Database (portal.db) initialized with fictional users and grades!');
});

db.close();
