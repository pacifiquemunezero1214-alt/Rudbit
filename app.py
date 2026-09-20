from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import secrets
from datetime import datetime, timedelta, timezone


app = Flask(__name__)

app.secret_key = os.environ.get(
    "RUD_BIT_SECRET_KEY",
    "rudbit-development-secret-key"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False
)

# CSRF PROTECTION
csrf = CSRFProtect(app)

DATABASE = "rudbit.db"

OTP_EXPIRY_MINUTES = 5
MAX_OTP_ATTEMPTS = 5

# LOGIN SECURITY
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCK_MINUTES = 15


def utc_now():
    return datetime.now(timezone.utc)


def parse_datetime(value):
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    # =================================================
    # USERS TABLE
    # =================================================

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            balance REAL DEFAULT 0,
            status TEXT DEFAULT 'Pending',
            role TEXT DEFAULT 'user',
            failed_login_attempts INTEGER DEFAULT 0,
            locked_until TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    user_columns = conn.execute(
        "PRAGMA table_info(users)"
    ).fetchall()

    user_column_names = [
        column["name"]
        for column in user_columns
    ]

    if "role" not in user_column_names:
        conn.execute("""
            ALTER TABLE users
            ADD COLUMN role TEXT DEFAULT 'user'
        """)

        conn.execute("""
            UPDATE users
            SET role = 'user'
            WHERE role IS NULL OR role = ''
        """)

    if "failed_login_attempts" not in user_column_names:
        conn.execute("""
            ALTER TABLE users
            ADD COLUMN failed_login_attempts INTEGER DEFAULT 0
        """)

    if "locked_until" not in user_column_names:
        conn.execute("""
            ALTER TABLE users
            ADD COLUMN locked_until TEXT
        """)

    # =================================================
    # TRANSACTIONS TABLE
    # =================================================

    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            transaction_type TEXT NOT NULL,
            amount REAL NOT NULL,
            destination_phone TEXT,
            status TEXT DEFAULT 'Completed',
            reference_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    transaction_columns = conn.execute(
        "PRAGMA table_info(transactions)"
    ).fetchall()

    transaction_column_names = [
        column["name"]
        for column in transaction_columns
    ]

    if "destination_phone" not in transaction_column_names:
        conn.execute("""
            ALTER TABLE transactions
            ADD COLUMN destination_phone TEXT
        """)

    if "status" not in transaction_column_names:
        conn.execute("""
            ALTER TABLE transactions
            ADD COLUMN status TEXT DEFAULT 'Completed'
        """)

        # Existing withdrawals are treated as pending
        # when the status workflow is first introduced.
        conn.execute("""
            UPDATE transactions
            SET status = 'Pending'
            WHERE transaction_type = 'Withdraw'
        """)

        conn.execute("""
            UPDATE transactions
            SET status = 'Completed'
            WHERE transaction_type = 'Save'
        """)

    if "reference_id" not in transaction_column_names:
        conn.execute("""
            ALTER TABLE transactions
            ADD COLUMN reference_id TEXT
        """)

    # Give old transactions a stable reference ID.
    existing_transactions = conn.execute("""
        SELECT id
        FROM transactions
        WHERE reference_id IS NULL
           OR reference_id = ''
    """).fetchall()

    for transaction in existing_transactions:
        reference_id = f"RUD-{transaction['id']:06d}"

        conn.execute("""
            UPDATE transactions
            SET reference_id = ?
            WHERE id = ?
        """, (
            reference_id,
            transaction["id"]
        ))

    # =================================================
    # PASSWORD RESET TABLE
    # =================================================

    conn.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            otp_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            attempts INTEGER DEFAULT 0,
            used INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()


# =====================================================
# HOME
# =====================================================

@app.route("/")
def home():

    if "user_id" in session:

        if session.get("role") == "admin":
            return redirect(
                url_for("admin_dashboard")
            )

        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


# =====================================================
# REGISTER
# =====================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        country_code = request.form.get(
            "country_code",
            ""
        ).strip()

        phone = request.form.get(
            "phone",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        country_code = country_code.replace(
            " ",
            ""
        )

        phone = phone.replace(
            " ",
            ""
        ).replace(
            "-",
            ""
        )

        if country_code and not country_code.startswith("+"):
            country_code = "+" + country_code

        if phone.startswith("0"):
            phone = phone[1:]

        full_phone = country_code + phone

        if not country_code or not phone:
            flash(
                "Please enter your phone number.",
                "error"
            )

            return redirect(
                url_for("register")
            )

        if len(password) < 6:
            flash(
                "Password must be at least 6 characters.",
                "error"
            )

            return redirect(
                url_for("register")
            )

        if password != confirm_password:
            flash(
                "Passwords do not match.",
                "error"
            )

            return redirect(
                url_for("register")
            )

        conn = get_db()

        existing_user = conn.execute("""
            SELECT id
            FROM users
            WHERE phone = ?
        """, (
            full_phone,
        )).fetchone()

        if existing_user:
            conn.close()

            flash(
                "This phone number is already registered.",
                "error"
            )

            return redirect(
                url_for("register")
            )

        hashed_password = generate_password_hash(
            password
        )

        conn.execute("""
            INSERT INTO users
            (
                phone,
                password,
                balance,
                status,
                role,
                failed_login_attempts,
                locked_until
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            full_phone,
            hashed_password,
            0,
            "Pending",
            "user",
            0,
            None
        ))

        conn.commit()
        conn.close()

        flash(
            "Registration successful. You can now login.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# =====================================================
# LOGIN
# =====================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        country_code = request.form.get(
            "country_code",
            ""
        ).strip()

        phone = request.form.get(
            "phone",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        country_code = country_code.replace(
            " ",
            ""
        )

        phone = phone.replace(
            " ",
            ""
        ).replace(
            "-",
            ""
        )

        if country_code and not country_code.startswith("+"):
            country_code = "+" + country_code

        full_phone = country_code + phone

        conn = get_db()

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE phone = ?
        """, (
            full_phone,
        )).fetchone()

        if not user:
            conn.close()

            flash(
                "Phone number or password is incorrect.",
                "error"
            )

            return redirect(
                url_for("login")
            )

        # =================================================
        # ACCOUNT STATUS CHECK
        # =================================================
        # Admin is always allowed to continue.
        # Normal users must have Active status.
        # Pending means inactive/deactivated.
        # =================================================

        if user["role"] != "admin" and user["status"] != "Active":

            conn.close()

            flash(
                "Your account is currently inactive. "
                "Please contact the administrator.",
                "error"
            )

            return redirect(
                url_for("login")
            )

        locked_until = user["locked_until"]

        if locked_until:

            lock_time = parse_datetime(
                locked_until
            )

            if lock_time and utc_now() < lock_time:

                remaining_seconds = (
                    lock_time - utc_now()
                ).total_seconds()

                remaining_minutes = max(
                    1,
                    int(
                        (remaining_seconds + 59) // 60
                    )
                )

                conn.close()

                flash(
                    f"Account temporarily locked. "
                    f"Please try again in approximately "
                    f"{remaining_minutes} minute(s).",
                    "error"
                )

                return redirect(
                    url_for("login")
                )

            conn.execute("""
                UPDATE users
                SET failed_login_attempts = 0,
                    locked_until = NULL
                WHERE id = ?
            """, (
                user["id"],
            ))

            conn.commit()

            user = conn.execute("""
                SELECT *
                FROM users
                WHERE id = ?
            """, (
                user["id"],
            )).fetchone()

        password_is_correct = check_password_hash(
            user["password"],
            password
        )

        if not password_is_correct:

            new_attempts = (
                (user["failed_login_attempts"] or 0)
                + 1
            )

            if new_attempts >= MAX_LOGIN_ATTEMPTS:

                lock_until = (
                    utc_now()
                    + timedelta(
                        minutes=LOGIN_LOCK_MINUTES
                    )
                )

                conn.execute("""
                    UPDATE users
                    SET failed_login_attempts = ?,
                        locked_until = ?
                    WHERE id = ?
                """, (
                    new_attempts,
                    lock_until.isoformat(),
                    user["id"]
                ))

                conn.commit()
                conn.close()

                flash(
                    "Too many failed login attempts. "
                    "Your account has been temporarily "
                    "locked for 15 minutes.",
                    "error"
                )

                return redirect(
                    url_for("login")
                )

            conn.execute("""
                UPDATE users
                SET failed_login_attempts = ?
                WHERE id = ?
            """, (
                new_attempts,
                user["id"]
            ))

            conn.commit()
            conn.close()

            remaining_attempts = (
                MAX_LOGIN_ATTEMPTS
                - new_attempts
            )

            flash(
                f"Phone number or password is incorrect. "
                f"{remaining_attempts} attempt(s) remaining.",
                "error"
            )

            return redirect(
                url_for("login")
            )

        # =================================================
        # SUCCESSFUL LOGIN
        # =================================================
        # IMPORTANT:
        # Do NOT change status to Active here.
        # Admin controls the account status.
        # =================================================

        conn.execute("""
            UPDATE users
            SET failed_login_attempts = 0,
                locked_until = NULL
            WHERE id = ?
        """, (
            user["id"],
        ))

        conn.commit()
        conn.close()

        session.clear()

        session["user_id"] = user["id"]
        session["phone"] = user["phone"]
        session["role"] = user["role"]

        if user["role"] == "admin":
            return redirect(
                url_for("admin_dashboard")
            )

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "login.html"
    )


# =====================================================
# FORGOT PASSWORD
# =====================================================

@app.route(
    "/forgot-password",
    methods=["GET", "POST"]
)
def forgot_password():

    if request.method == "POST":

        country_code = request.form.get(
            "country_code",
            ""
        ).strip()

        phone = request.form.get(
            "phone",
            ""
        ).strip()

        country_code = country_code.replace(
            " ",
            ""
        )

        phone = phone.replace(
            " ",
            ""
        ).replace(
            "-",
            ""
        )

        if country_code and not country_code.startswith("+"):
            country_code = "+" + country_code

        if phone.startswith("0"):
            phone = phone[1:]

        full_phone = country_code + phone

        if not country_code or not phone:

            flash(
                "Please enter your phone number.",
                "error"
            )

            return redirect(
                url_for("forgot_password")
            )

        conn = get_db()

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE phone = ?
        """, (
            full_phone,
        )).fetchone()

        if not user:
            conn.close()

            flash(
                "No account was found with this phone number.",
                "error"
            )

            return redirect(
                url_for("forgot_password")
            )

        conn.execute("""
            UPDATE password_resets
            SET used = 1
            WHERE user_id = ?
            AND used = 0
        """, (
            user["id"],
        ))

        otp = str(
            secrets.randbelow(1000000)
        ).zfill(6)

        otp_hash = generate_password_hash(
            otp
        )

        expires_at = (
            utc_now()
            + timedelta(
                minutes=OTP_EXPIRY_MINUTES
            )
        )

        conn.execute("""
            INSERT INTO password_resets
            (
                user_id,
                otp_hash,
                expires_at,
                attempts,
                used
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            user["id"],
            otp_hash,
            expires_at.isoformat(),
            0,
            0
        ))

        conn.commit()
        conn.close()

        session["reset_user_id"] = user["id"]
        session["reset_phone"] = user["phone"]

        # DEVELOPMENT / TESTING ONLY
        session["development_otp"] = otp

        flash(
            f"Development OTP: {otp}",
            "success"
        )

        return redirect(
            url_for("verify_reset_otp")
        )

    return render_template(
        "forgot_password.html"
    )


# =====================================================
# VERIFY RESET OTP
# =====================================================

@app.route(
    "/verify-reset-otp",
    methods=["GET", "POST"]
)
def verify_reset_otp():

    if "reset_user_id" not in session:
        return redirect(
            url_for("forgot_password")
        )

    if request.method == "POST":

        entered_otp = request.form.get(
            "otp",
            ""
        ).strip()

        if not entered_otp:

            flash(
                "Please enter the OTP code.",
                "error"
            )

            return redirect(
                url_for("verify_reset_otp")
            )

        conn = get_db()

        reset = conn.execute("""
            SELECT *
            FROM password_resets
            WHERE user_id = ?
            AND used = 0
            ORDER BY id DESC
            LIMIT 1
        """, (
            session["reset_user_id"],
        )).fetchone()

        if not reset:
            conn.close()

            session.pop(
                "development_otp",
                None
            )

            flash(
                "This OTP is no longer valid. "
                "Please request a new one.",
                "error"
            )

            return redirect(
                url_for("forgot_password")
            )

        expires_at = parse_datetime(
            reset["expires_at"]
        )

        if not expires_at or utc_now() > expires_at:

            conn.execute("""
                UPDATE password_resets
                SET used = 1
                WHERE id = ?
            """, (
                reset["id"],
            ))

            conn.commit()
            conn.close()

            session.pop(
                "development_otp",
                None
            )

            flash(
                "This OTP has expired. "
                "Please request a new one.",
                "error"
            )

            return redirect(
                url_for("forgot_password")
            )

        if reset["attempts"] >= MAX_OTP_ATTEMPTS:

            conn.execute("""
                UPDATE password_resets
                SET used = 1
                WHERE id = ?
            """, (
                reset["id"],
            ))

            conn.commit()
            conn.close()

            session.pop(
                "development_otp",
                None
            )

            flash(
                "Too many incorrect attempts. "
                "Please request a new OTP.",
                "error"
            )

            return redirect(
                url_for("forgot_password")
            )

        if not check_password_hash(
            reset["otp_hash"],
            entered_otp
        ):

            conn.execute("""
                UPDATE password_resets
                SET attempts = attempts + 1
                WHERE id = ?
            """, (
                reset["id"],
            ))

            conn.commit()
            conn.close()

            remaining_attempts = (
                MAX_OTP_ATTEMPTS
                - reset["attempts"]
                - 1
            )

            flash(
                f"Incorrect OTP. "
                f"{remaining_attempts} attempts remaining.",
                "error"
            )

            return redirect(
                url_for("verify_reset_otp")
            )

        conn.execute("""
            UPDATE password_resets
            SET used = 1
            WHERE id = ?
        """, (
            reset["id"],
        ))

        conn.commit()
        conn.close()

        session["reset_verified"] = True

        session.pop(
            "development_otp",
            None
        )

        return redirect(
            url_for("reset_password")
        )

    development_otp = session.get(
        "development_otp"
    )

    return render_template(
        "verify_reset_otp.html",
        development_otp=development_otp
    )


# =====================================================
# RESET PASSWORD
# =====================================================

@app.route(
    "/reset-password",
    methods=["GET", "POST"]
)
def reset_password():

    if "reset_user_id" not in session:
        return redirect(
            url_for("forgot_password")
        )

    if not session.get("reset_verified"):
        return redirect(
            url_for("verify_reset_otp")
        )

    if request.method == "POST":

        new_password = request.form.get(
            "new_password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if not new_password:

            flash(
                "Please enter a new password.",
                "error"
            )

            return redirect(
                url_for("reset_password")
            )

        if len(new_password) < 6:

            flash(
                "Password must be at least 6 characters.",
                "error"
            )

            return redirect(
                url_for("reset_password")
            )

        if new_password != confirm_password:

            flash(
                "Passwords do not match.",
                "error"
            )

            return redirect(
                url_for("reset_password")
            )

        conn = get_db()

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE id = ?
        """, (
            session["reset_user_id"],
        )).fetchone()

        if not user:
            conn.close()

            session.pop(
                "reset_user_id",
                None
            )

            session.pop(
                "reset_phone",
                None
            )

            session.pop(
                "reset_verified",
                None
            )

            flash(
                "Account not found.",
                "error"
            )

            return redirect(
                url_for("login")
            )

        if check_password_hash(
            user["password"],
            new_password
        ):
            conn.close()

            flash(
                "New password must be different "
                "from your old password.",
                "error"
            )

            return redirect(
                url_for("reset_password")
            )

        hashed_password = generate_password_hash(
            new_password
        )

        conn.execute("""
            UPDATE users
            SET password = ?,
                failed_login_attempts = 0,
                locked_until = NULL
            WHERE id = ?
        """, (
            hashed_password,
            user["id"]
        ))

        conn.commit()
        conn.close()

        session.pop(
            "reset_user_id",
            None
        )

        session.pop(
            "reset_phone",
            None
        )

        session.pop(
            "reset_verified",
            None
        )

        session.pop(
            "development_otp",
            None
        )

        flash(
            "Password reset successfully. "
            "You can now login.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "reset_password.html"
    )


# =====================================================
# USER DASHBOARD
# =====================================================

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    if session.get("role") == "admin":
        return redirect(
            url_for("admin_dashboard")
        )

    conn = get_db()

    user = conn.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (
        session["user_id"],
    )).fetchone()

    transactions = conn.execute("""
        SELECT *
        FROM transactions
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 5
    """, (
        session["user_id"],
    )).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        user=user,
        transactions=transactions
    )


# =====================================================
# SAVE
# =====================================================

@app.route(
    "/save",
    methods=["GET", "POST"]
)
def save():

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    if session.get("role") == "admin":
        return redirect(
            url_for("admin_dashboard")
        )

    if request.method == "POST":

        amount_text = request.form.get(
            "amount",
            ""
        ).strip()

        try:
            amount = float(amount_text)
        except (ValueError, TypeError):

            flash(
                "Please enter a valid amount.",
                "error"
            )

            return redirect(
                url_for("save")
            )

        if amount <= 0:

            flash(
                "Amount must be greater than 0.",
                "error"
            )

            return redirect(
                url_for("save")
            )

        conn = get_db()

        conn.execute("""
            UPDATE users
            SET balance = balance + ?
            WHERE id = ?
        """, (
            amount,
            session["user_id"]
        ))

        reference_id = (
            f"RUD-{secrets.token_hex(4).upper()}"
        )

        conn.execute("""
            INSERT INTO transactions
            (
                user_id,
                transaction_type,
                amount,
                status,
                reference_id
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            session["user_id"],
            "Save",
            amount,
            "Completed",
            reference_id
        ))

        conn.commit()
        conn.close()

        flash(
            f"{amount:,.2f} added to your balance successfully.",
            "success"
        )

        return redirect(
            url_for("save_payment")
        )

    conn = get_db()

    user = conn.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (
        session["user_id"],
    )).fetchone()

    transactions = conn.execute("""
        SELECT *
        FROM transactions
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 5
    """, (
        session["user_id"],
    )).fetchall()

    conn.close()

    return render_template(
        "save.html",
        user=user,
        transactions=transactions
    )


# =====================================================
# SAVE PAYMENT
# =====================================================

@app.route("/save-payment")
def save_payment():

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    if session.get("role") == "admin":
        return redirect(
            url_for("admin_dashboard")
        )

    return render_template(
        "save_payment.html"
    )


# =====================================================
# WITHDRAW
# =====================================================

@app.route(
    "/withdraw",
    methods=["GET", "POST"]
)
def withdraw():

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    if session.get("role") == "admin":
        return redirect(
            url_for("admin_dashboard")
        )

    if request.method == "POST":

        amount_text = request.form.get(
            "amount",
            ""
        ).strip()

        destination_phone = request.form.get(
            "destination_phone",
            ""
        ).strip()

        try:
            amount = float(amount_text)
        except (ValueError, TypeError):

            flash(
                "Please enter a valid amount.",
                "error"
            )

            return redirect(
                url_for("withdraw")
            )

        if amount <= 0:

            flash(
                "Amount must be greater than 0.",
                "error"
            )

            return redirect(
                url_for("withdraw")
            )

        if not destination_phone:

            flash(
                "Please enter the phone number where "
                "the money should be sent.",
                "error"
            )

            return redirect(
                url_for("withdraw")
            )

        conn = get_db()

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE id = ?
        """, (
            session["user_id"],
        )).fetchone()

        if not user:
            conn.close()

            flash(
                "User account not found.",
                "error"
            )

            return redirect(
                url_for("login")
            )

        if amount > user["balance"]:
            conn.close()

            flash(
                "Insufficient balance for this withdrawal.",
                "error"
            )

            return redirect(
                url_for("withdraw")
            )

        # Reserve the amount immediately.
        # If Admin rejects the withdrawal,
        # the amount is returned.
        conn.execute("""
            UPDATE users
            SET balance = balance - ?
            WHERE id = ?
        """, (
            amount,
            session["user_id"]
        ))

        reference_id = (
            f"RUD-{secrets.token_hex(4).upper()}"
        )

        conn.execute("""
            INSERT INTO transactions
            (
                user_id,
                transaction_type,
                amount,
                destination_phone,
                status,
                reference_id
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            session["user_id"],
            "Withdraw",
            amount,
            destination_phone,
            "Pending",
            reference_id
        ))

        conn.commit()
        conn.close()

        flash(
            f"Withdrawal request for {amount:,.2f} "
            f"submitted successfully.",
            "success"
        )

        return redirect(
            url_for("withdraw")
        )

    conn = get_db()

    user = conn.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (
        session["user_id"],
    )).fetchone()

    transactions = conn.execute("""
        SELECT *
        FROM transactions
        WHERE user_id = ?
        AND transaction_type = 'Withdraw'
        ORDER BY id DESC
        LIMIT 5
    """, (
        session["user_id"],
    )).fetchall()

    conn.close()

    return render_template(
        "withdraw.html",
        user=user,
        transactions=transactions
    )


# =====================================================
# PROFILE
# =====================================================

@app.route("/profile")
def profile():

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    if session.get("role") == "admin":
        return redirect(
            url_for("admin_dashboard")
        )

    conn = get_db()

    user = conn.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (
        session["user_id"],
    )).fetchone()

    conn.close()

    if not user:
        session.clear()

        return redirect(
            url_for("login")
        )

    return render_template(
        "profile.html",
        user=user
    )


# =====================================================
# SETTINGS
# =====================================================

@app.route("/settings")
def settings():

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    if session.get("role") == "admin":
        return redirect(
            url_for("admin_dashboard")
        )

    conn = get_db()

    user = conn.execute("""
        SELECT *
        FROM users
        WHERE id = ?
    """, (
        session["user_id"],
    )).fetchone()

    conn.close()

    if not user:
        session.clear()

        return redirect(
            url_for("login")
        )

    return render_template(
        "settings.html",
        user=user
    )


# =====================================================
# CHANGE PASSWORD
# =====================================================

@app.route(
    "/change-password",
    methods=["GET", "POST"]
)
def change_password():

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    if session.get("role") == "admin":
        return redirect(
            url_for("admin_dashboard")
        )

    if request.method == "POST":

        current_password = request.form.get(
            "current_password",
            ""
        )

        new_password = request.form.get(
            "new_password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if not current_password:

            flash(
                "Please enter your current password.",
                "error"
            )

            return redirect(
                url_for("change_password")
            )

        if not new_password:

            flash(
                "Please enter a new password.",
                "error"
            )

            return redirect(
                url_for("change_password")
            )

        if len(new_password) < 6:

            flash(
                "New password must be at least 6 characters.",
                "error"
            )

            return redirect(
                url_for("change_password")
            )

        if new_password != confirm_password:

            flash(
                "New passwords do not match.",
                "error"
            )

            return redirect(
                url_for("change_password")
            )

        conn = get_db()

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE id = ?
        """, (
            session["user_id"],
        )).fetchone()

        if not user:
            conn.close()

            session.clear()

            return redirect(
                url_for("login")
            )

        if not check_password_hash(
            user["password"],
            current_password
        ):
            conn.close()

            flash(
                "Current password is incorrect.",
                "error"
            )

            return redirect(
                url_for("change_password")
            )

        if check_password_hash(
            user["password"],
            new_password
        ):
            conn.close()

            flash(
                "New password must be different "
                "from your current password.",
                "error"
            )

            return redirect(
                url_for("change_password")
            )

        hashed_password = generate_password_hash(
            new_password
        )

        conn.execute("""
            UPDATE users
            SET password = ?,
                failed_login_attempts = 0,
                locked_until = NULL
            WHERE id = ?
        """, (
            hashed_password,
            session["user_id"]
        ))

        conn.commit()
        conn.close()

        flash(
            "Password changed successfully.",
            "success"
        )

        return redirect(
            url_for("settings")
        )

    return render_template(
        "change_password.html"
    )


# =====================================================
# ADMIN AUTHORIZATION
# =====================================================

def admin_required():

    if "user_id" not in session:
        return False

    if session.get("role") != "admin":
        return False

    return True


# =====================================================
# ADMIN DASHBOARD
# =====================================================

@app.route("/admin")
def admin_dashboard():

    if not admin_required():
        return redirect(
            url_for("login")
        )

    conn = get_db()

    total_users = conn.execute("""
        SELECT COUNT(*)
        FROM users
        WHERE role = 'user'
    """).fetchone()[0]

    active_users = conn.execute("""
        SELECT COUNT(*)
        FROM users
        WHERE role = 'user'
        AND status = 'Active'
    """).fetchone()[0]

    pending_users = conn.execute("""
        SELECT COUNT(*)
        FROM users
        WHERE role = 'user'
        AND status = 'Pending'
    """).fetchone()[0]

    total_balance = conn.execute("""
        SELECT COALESCE(SUM(balance), 0)
        FROM users
        WHERE role = 'user'
    """).fetchone()[0]

    total_saves = conn.execute("""
        SELECT COALESCE(SUM(amount), 0)
        FROM transactions
        WHERE transaction_type = 'Save'
    """).fetchone()[0]

    total_withdrawals = conn.execute("""
        SELECT COALESCE(SUM(amount), 0)
        FROM transactions
        WHERE transaction_type = 'Withdraw'
    """).fetchone()[0]

    withdrawal_count = conn.execute("""
        SELECT COUNT(*)
        FROM transactions
        WHERE transaction_type = 'Withdraw'
    """).fetchone()[0]

    pending_withdrawals = conn.execute("""
        SELECT COUNT(*)
        FROM transactions
        WHERE transaction_type = 'Withdraw'
        AND status = 'Pending'
    """).fetchone()[0]

    recent_transactions = conn.execute("""
        SELECT
            transactions.id,
            transactions.transaction_type,
            transactions.amount,
            transactions.destination_phone,
            transactions.status,
            transactions.reference_id,
            transactions.created_at,
            users.phone
        FROM transactions
        INNER JOIN users
            ON transactions.user_id = users.id
        ORDER BY transactions.id DESC
        LIMIT 10
    """).fetchall()

    conn.close()

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        active_users=active_users,
        pending_users=pending_users,
        total_balance=total_balance,
        total_saves=total_saves,
        total_withdrawals=total_withdrawals,
        withdrawal_count=withdrawal_count,
        pending_withdrawals=pending_withdrawals,
        recent_transactions=recent_transactions
    )


# =====================================================
# ADMIN USERS
# =====================================================

@app.route("/admin/users")
def admin_users():

    if not admin_required():
        return redirect(
            url_for("login")
        )

    search = request.args.get(
        "search",
        ""
    ).strip()

    conn = get_db()

    if search:

        users = conn.execute("""
            SELECT *
            FROM users
            WHERE role = 'user'
            AND phone LIKE ?
            ORDER BY id DESC
        """, (
            f"%{search}%",
        )).fetchall()

    else:

        users = conn.execute("""
            SELECT *
            FROM users
            WHERE role = 'user'
            ORDER BY id DESC
        """).fetchall()

    conn.close()

    return render_template(
        "admin_users.html",
        users=users,
        search=search
    )


# =====================================================
# ADMIN UPDATE USER STATUS
# =====================================================

@app.route(
    "/admin/users/<int:user_id>/status",
    methods=["POST"]
)
def admin_update_user_status(user_id):

    if not admin_required():
        return redirect(
            url_for("login")
        )

    new_status = request.form.get(
        "status",
        ""
    ).strip()

    if new_status not in [
        "Active",
        "Pending"
    ]:

        flash(
            "Invalid account status.",
            "error"
        )

        return redirect(
            url_for("admin_users")
        )

    conn = get_db()

    user = conn.execute("""
        SELECT
            id,
            phone,
            role,
            status
        FROM users
        WHERE id = ?
    """, (
        user_id,
    )).fetchone()

    if not user:

        conn.close()

        flash(
            "User account not found.",
            "error"
        )

        return redirect(
            url_for("admin_users")
        )

    # =================================================
    # ADMIN PROTECTION
    # =================================================
    # Admin account cannot be activated/deactivated
    # through normal user management.
    # =================================================

    if user["role"] == "admin":

        conn.close()

        flash(
            "Admin accounts cannot be changed from "
            "the user management page.",
            "error"
        )

        return redirect(
            url_for("admin_users")
        )

    # =================================================
    # UPDATE USER STATUS
    # =================================================

    conn.execute("""
        UPDATE users
        SET status = ?
        WHERE id = ?
        AND role = 'user'
    """, (
        new_status,
        user_id
    ))

    conn.commit()
    conn.close()

    if new_status == "Active":

        flash(
            "User account activated successfully.",
            "success"
        )

    else:

        flash(
            "User account deactivated successfully.",
            "success"
        )

    return redirect(
        url_for("admin_users")
    )


# =====================================================
# ADMIN USER DETAILS
# =====================================================

@app.route(
    "/admin/users/<int:user_id>"
)
def admin_user_details(user_id):

    if not admin_required():
        return redirect(
            url_for("login")
        )

    conn = get_db()

    user = conn.execute("""
        SELECT *
        FROM users
        WHERE id = ?
        AND role = 'user'
    """, (
        user_id,
    )).fetchone()

    if not user:
        conn.close()

        flash(
            "User account not found.",
            "error"
        )

        return redirect(
            url_for("admin_users")
        )

    transactions = conn.execute("""
        SELECT
            id,
            user_id,
            transaction_type,
            amount,
            created_at,
            destination_phone,
            status,
            reference_id
        FROM transactions
        WHERE user_id = ?
        ORDER BY id DESC
    """, (
        user_id,
    )).fetchall()

    conn.close()

    return render_template(
        "admin_user_details.html",
        user=user,
        transactions=transactions
    )


# =====================================================
# ADMIN TRANSACTIONS
# =====================================================

@app.route("/admin/transactions")
def admin_transactions():

    if not admin_required():
        return redirect(
            url_for("login")
        )

    transaction_type = request.args.get(
        "type",
        ""
    ).strip()

    conn = get_db()

    if transaction_type in [
        "Save",
        "Withdraw"
    ]:

        transactions = conn.execute("""
            SELECT
                transactions.*,
                users.phone
            FROM transactions
            INNER JOIN users
                ON transactions.user_id = users.id
            WHERE transactions.transaction_type = ?
            ORDER BY transactions.id DESC
        """, (
            transaction_type,
        )).fetchall()

    else:

        transactions = conn.execute("""
            SELECT
                transactions.*,
                users.phone
            FROM transactions
            INNER JOIN users
                ON transactions.user_id = users.id
            ORDER BY transactions.id DESC
        """).fetchall()

    conn.close()

    return render_template(
        "admin_transactions.html",
        transactions=transactions,
        transaction_type=transaction_type
    )


# =====================================================
# ADMIN WITHDRAWALS
# =====================================================

@app.route("/admin/withdrawals")
def admin_withdrawals():

    if not admin_required():
        return redirect(
            url_for("login")
        )

    status_filter = request.args.get(
        "status",
        ""
    ).strip()

    conn = get_db()

    if status_filter in [
        "Pending",
        "Completed",
        "Rejected"
    ]:

        withdrawals = conn.execute("""
            SELECT
                transactions.*,
                users.phone
            FROM transactions
            INNER JOIN users
                ON transactions.user_id = users.id
            WHERE transactions.transaction_type = 'Withdraw'
            AND transactions.status = ?
            ORDER BY transactions.id DESC
        """, (
            status_filter,
        )).fetchall()

    else:

        withdrawals = conn.execute("""
            SELECT
                transactions.*,
                users.phone
            FROM transactions
            INNER JOIN users
                ON transactions.user_id = users.id
            WHERE transactions.transaction_type = 'Withdraw'
            ORDER BY transactions.id DESC
        """).fetchall()

    conn.close()

    return render_template(
        "admin_withdrawals.html",
        withdrawals=withdrawals,
        status_filter=status_filter
    )


# =====================================================
# ADMIN WITHDRAWAL DETAILS
# =====================================================

@app.route(
    "/admin/withdrawals/<int:transaction_id>"
)
def admin_withdrawal_details(transaction_id):

    if not admin_required():
        return redirect(
            url_for("login")
        )

    conn = get_db()

    withdrawal = conn.execute("""
        SELECT
            t.id,
            t.user_id,
            t.transaction_type,
            t.amount,
            t.destination_phone,
            t.status,
            t.reference_id,
            t.created_at,
            u.phone,
            u.balance,
            u.status AS user_status
        FROM transactions t
        INNER JOIN users u
            ON t.user_id = u.id
        WHERE t.id = ?
        AND t.transaction_type = 'Withdraw'
    """, (
        transaction_id,
    )).fetchone()

    conn.close()

    if not withdrawal:

        flash(
            "Withdrawal not found.",
            "error"
        )

        return redirect(
            url_for("admin_withdrawals")
        )

    return render_template(
        "admin_withdrawal_details.html",
        withdrawal=withdrawal
    )


# =====================================================
# ADMIN UPDATE WITHDRAWAL STATUS
# =====================================================

@app.route(
    "/admin/withdrawals/<int:transaction_id>/status",
    methods=["POST"]
)
def admin_update_withdrawal_status(
    transaction_id
):

    if not admin_required():
        return redirect(
            url_for("login")
        )

    new_status = request.form.get(
        "status",
        ""
    ).strip()

    if new_status not in [
        "Pending",
        "Completed",
        "Rejected"
    ]:

        flash(
            "Invalid withdrawal status.",
            "error"
        )

        return redirect(
            url_for("admin_withdrawals")
        )

    conn = get_db()

    withdrawal = conn.execute("""
        SELECT *
        FROM transactions
        WHERE id = ?
        AND transaction_type = 'Withdraw'
    """, (
        transaction_id,
    )).fetchone()

    if not withdrawal:

        conn.close()

        flash(
            "Withdrawal not found.",
            "error"
        )

        return redirect(
            url_for("admin_withdrawals")
        )

    current_status = (
        withdrawal["status"]
        or "Pending"
    )

    # =================================================
    # FINAL STATE PROTECTION
    # =================================================

    if current_status in [
        "Completed",
        "Rejected"
    ]:

        conn.close()

        flash(
            f"This withdrawal is already "
            f"{current_status}.",
            "error"
        )

        return redirect(
            url_for("admin_withdrawals")
        )

    # =================================================
    # PENDING
    # =================================================

    if new_status == "Pending":

        conn.execute("""
            UPDATE transactions
            SET status = 'Pending'
            WHERE id = ?
        """, (
            transaction_id,
        ))

        conn.commit()
        conn.close()

        flash(
            "Withdrawal marked as Pending.",
            "success"
        )

        return redirect(
            url_for("admin_withdrawals")
        )

    # =================================================
    # COMPLETED
    # =================================================

    if new_status == "Completed":

        conn.execute("""
            UPDATE transactions
            SET status = 'Completed'
            WHERE id = ?
        """, (
            transaction_id,
        ))

        conn.commit()
        conn.close()

        flash(
            "Withdrawal marked as Completed.",
            "success"
        )

        return redirect(
            url_for("admin_withdrawals")
        )

    # =================================================
    # REJECTED
    # =================================================

    if new_status == "Rejected":

        user_id = withdrawal["user_id"]
        amount = withdrawal["amount"]

        # Return reserved amount to user.
        conn.execute("""
            UPDATE users
            SET balance = balance + ?
            WHERE id = ?
        """, (
            amount,
            user_id
        ))

        conn.execute("""
            UPDATE transactions
            SET status = 'Rejected'
            WHERE id = ?
        """, (
            transaction_id,
        ))

        conn.commit()
        conn.close()

        flash(
            "Withdrawal rejected and the amount "
            "was returned to the user's balance.",
            "success"
        )

        return redirect(
            url_for("admin_withdrawals")
        )

    conn.close()

    return redirect(
        url_for("admin_withdrawals")
    )


# =====================================================
# LOGOUT
# =====================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =====================================================
# START APPLICATION
# =====================================================

if __name__ == "__main__":

    init_db()

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )