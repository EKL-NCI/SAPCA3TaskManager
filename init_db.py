import sqlite3

DATABASE = "database.db"

# Plain text passwords (No Hashing), No security columns for password hash or session token or login attempts, XSS Vulnurable due to simple text fields

def init_db():
    connectDb = sqlite3.connect(DATABASE)
    c = connectDb.cursor()

    # Insecure users table
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        );
    """)

    # Insecure tasks table
    c.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            description TEXT
        );
    """)

    connectDb.commit()
    connectDb.close()
    print("Insecure DB initialized!")

if __name__ == "__main__":
    init_db()