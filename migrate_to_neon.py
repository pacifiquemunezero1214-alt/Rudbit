import os
import sqlite3
import psycopg

SQLITE_DB = "rudbit.db"
NEON_URL = os.environ.get("NEON_DATABASE_URL")

if not NEON_URL:
    raise RuntimeError("NEON_DATABASE_URL is not set.")

print("Connecting to Neon...")

# Read SQLite data
sqlite_conn = sqlite3.connect(SQLITE_DB)
sqlite_conn.row_factory = sqlite3.Row

users = sqlite_conn.execute("""
    SELECT id, phone, password, balance, status, created_at,
           failed_login_attempts, locked_until, role
    FROM users
    ORDER BY id
""").fetchall()

transactions = sqlite_conn.execute("""
    SELECT id, user_id, transaction_type, amount, created_at,
           destination_phone, status, reference_id
    FROM transactions
    ORDER BY id
""").fetchall()

password_resets = sqlite_conn.execute("""
    SELECT id, user_id, otp_hash, expires_at, attempts, used, created_at
    FROM password_resets
    ORDER BY id
""").fetchall()

print(f"SQLite users: {len(users)}")
print(f"SQLite transactions: {len(transactions)}")
print(f"SQLite password resets: {len(password_resets)}")

print("Connecting to Neon...")

with psycopg.connect(NEON_URL) as conn:

    with conn.cursor() as cur:

        # Create users table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                phone TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                balance DOUBLE PRECISION DEFAULT 0,
                status TEXT DEFAULT 'Pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TEXT,
                role TEXT DEFAULT 'user'
            )
        """)

        # Create transactions table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                transaction_type TEXT NOT NULL,
                amount DOUBLE PRECISION NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                destination_phone TEXT,
                status TEXT DEFAULT 'Completed',
                reference_id TEXT
            )
        """)

        # Create password_resets table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                otp_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                attempts INTEGER DEFAULT 0,
                used INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        print("Neon tables are ready.")

        # Insert users
        for row in users:
            cur.execute("""
                INSERT INTO users (
                    id, phone, password, balance, status, created_at,
                    failed_login_attempts, locked_until, role
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s,
                    %s, %s, %s
                )
                ON CONFLICT (id) DO UPDATE SET
                    phone = EXCLUDED.phone,
                    password = EXCLUDED.password,
                    balance = EXCLUDED.balance,
                    status = EXCLUDED.status,
                    created_at = EXCLUDED.created_at,
                    failed_login_attempts = EXCLUDED.failed_login_attempts,
                    locked_until = EXCLUDED.locked_until,
                    role = EXCLUDED.role
            """, (
                row["id"],
                row["phone"],
                row["password"],
                row["balance"],
                row["status"],
                row["created_at"],
                row["failed_login_attempts"],
                row["locked_until"],
                row["role"]
            ))

        # Insert transactions
        for row in transactions:
            cur.execute("""
                INSERT INTO transactions (
                    id, user_id, transaction_type, amount, created_at,
                    destination_phone, status, reference_id
                )
                VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s
                )
                ON CONFLICT (id) DO UPDATE SET
                    user_id = EXCLUDED.user_id,
                    transaction_type = EXCLUDED.transaction_type,
                    amount = EXCLUDED.amount,
                    created_at = EXCLUDED.created_at,
                    destination_phone = EXCLUDED.destination_phone,
                    status = EXCLUDED.status,
                    reference_id = EXCLUDED.reference_id
            """, (
                row["id"],
                row["user_id"],
                row["transaction_type"],
                row["amount"],
                row["created_at"],
                row["destination_phone"],
                row["status"],
                row["reference_id"]
            ))

        # Insert password reset records
        for row in password_resets:
            cur.execute("""
                INSERT INTO password_resets (
                    id, user_id, otp_hash, expires_at,
                    attempts, used, created_at
                )
                VALUES (
                    %s, %s, %s, %s,
                    %s, %s, %s
                )
                ON CONFLICT (id) DO UPDATE SET
                    user_id = EXCLUDED.user_id,
                    otp_hash = EXCLUDED.otp_hash,
                    expires_at = EXCLUDED.expires_at,
                    attempts = EXCLUDED.attempts,
                    used = EXCLUDED.used,
                    created_at = EXCLUDED.created_at
            """, (
                row["id"],
                row["user_id"],
                row["otp_hash"],
                row["expires_at"],
                row["attempts"],
                row["used"],
                row["created_at"]
            ))

        conn.commit()

        # Verify counts
        cur.execute("SELECT COUNT(*) FROM users")
        neon_users = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM transactions")
        neon_transactions = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM password_resets")
        neon_password_resets = cur.fetchone()[0]

print()
print("========== MIGRATION RESULT ==========")
print(f"Users:            SQLite={len(users)} | Neon={neon_users}")
print(f"Transactions:     SQLite={len(transactions)} | Neon={neon_transactions}")
print(f"Password resets:  SQLite={len(password_resets)} | Neon={neon_password_resets}")
print("======================================")

if (
    len(users) == neon_users
    and len(transactions) == neon_transactions
    and len(password_resets) == neon_password_resets
):
    print("MIGRATION: SUCCESS")
else:
    print("MIGRATION: COUNT MISMATCH - DO NOT DEPLOY")

sqlite_conn.close()