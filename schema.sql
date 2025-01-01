CREATE TABLE IF NOT EXISTS user(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        );

CREATE TABLE IF NOT EXISTS session(
            id TEXT PRIMARY KEY,
            data TEXT,
            expires_at TIMESTAMP
        );

CREATE TABLE IF NOT EXISTS otp (
    email TEXT PRIMARY KEY,
    otp TEXT NOT NULL,
    expires_at DATETIME NOT NULL
);