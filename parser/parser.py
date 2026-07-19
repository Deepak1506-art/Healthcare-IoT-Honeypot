import json
import sqlite3
import os

# Path to the copied Cowrie log
LOG_FILE = "../database/cowrie.json"

# SQLite database
DB_FILE = "../database/attacks.db"

if not os.path.exists(LOG_FILE):
    print("❌ cowrie.json not found!")
    exit()

conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

count = 0

with open(LOG_FILE, "r") as file:
    for line in file:
        try:
            data = json.loads(line)

            timestamp = data.get("timestamp", "")
            attacker_ip = data.get("src_ip", "")
            username = data.get("username", "")
            password = data.get("password", "")
            event = data.get("eventid", "")

            cursor.execute("""
            INSERT INTO attacks(timestamp, attacker_ip, username, password, event)
            VALUES(?,?,?,?,?)
            """, (timestamp, attacker_ip, username, password, event))

            count += 1

        except Exception:
            continue

conn.commit()
conn.close()

print(f"✅ Imported {count} log records into SQLite.")