import sqlite3

# Connect to SQLite database
conn = sqlite3.connect("attacks.db")

cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    attacker_ip TEXT,
    username TEXT,
    password TEXT,
    event TEXT
)
""")

conn.commit()
conn.close()

print("Database created successfully!")