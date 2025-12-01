import sqlite3

# Use a different database file for the secure branch
DATABASE = "secure_db.db"

def init_db():
    # Connect to the database
    connectDb = sqlite3.connect(DATABASE)
    c = connectDb.cursor()

    # USERS Table
    # Includes Unique constraints, role, pass_hash, and lockout columns
    c.execute("""
        CREATE TABLE IF NOT EXISTS Users (
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            pass_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            isLocked BOOLEAN NOT NULL DEFAULT 0,
            failed_login_count INTEGER NOT NULL DEFAULT 0
        );
    """)

    # TASKS Table
    # Includes Foreign Key in USERS
    c.execute("""
        CREATE TABLE IF NOT EXISTS Tasks (
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            
            FOREIGN KEY (user_id) REFERENCES Users(ID) ON DELETE CASCADE
        );
    """)

    # SESSIONS Table (Session Management)
    # Includes Foreign Key (FK) and unique token_hash
    c.execute("""
        CREATE TABLE IF NOT EXISTS Sessions (
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            created_at DATETIME NOT NULL,
            expires_at DATETIME NOT NULL,
            isValid BOOLEAN NOT NULL DEFAULT 1,
            
            FOREIGN KEY (user_id) REFERENCES Users(ID) ON DELETE CASCADE
        );
    """)

    # LOGIN_ATTEMPT Table (Brute Force)
    # Includes Foreign Key (FK)
    c.execute("""
        CREATE TABLE IF NOT EXISTS Login_Attempt (
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            timestamp DATETIME NOT NULL,
            IP TEXT NOT NULL,
            successfulLog BOOLEAN NOT NULL,
            
            FOREIGN KEY (user_id) REFERENCES Users(ID) ON DELETE SET NULL
        );
    """)

    connectDb.commit()
    connectDb.close()
    print(f"Secure database initialized successfully at: {DATABASE}")

if __name__ == "__main__":
    init_db()