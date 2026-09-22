from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify
)

from flask_wtf.csrf import CSRFProtect

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

import psycopg
from psycopg.rows import dict_row

import os
import secrets

from datetime import (
    datetime,
    timedelta,
    timezone
)


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


# =====================================================
# CSRF PROTECTION
# =====================================================

csrf = CSRFProtect(app)


# =====================================================
# DATABASE
# =====================================================

DATABASE_URL = os.environ.get("NEON_DATABASE_URL")


# =====================================================
# SECURITY SETTINGS
# =====================================================

OTP_EXPIRY_MINUTES = 5
MAX_OTP_ATTEMPTS = 5

MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCK_MINUTES = 15


# =====================================================
# RUD_BIT TASK CYCLE SETTINGS
# =====================================================

TASK_CYCLE_SAVE_AMOUNT = 3000.0
TASK_CYCLE_REWARD = 2500.0
TASK_CYCLE_DAYS = 3

TASK_CYCLE_DURATION = timedelta(
    days=TASK_CYCLE_DAYS
)


# =====================================================
# DATABASE CONNECTION
# =====================================================

def get_db():
    if not DATABASE_URL:
        raise RuntimeError(
            "NEON_DATABASE_URL is not configured."
        )

    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row
    )


# =====================================================
# DATETIME HELPERS
# =====================================================

def utc_now():
    return datetime.now(timezone.utc)


def parse_datetime(value):
    if not value:
        return None

    if isinstance(value, datetime):
        parsed = value

    else:
        try:
            parsed = datetime.fromisoformat(value)

        except (ValueError, TypeError):
            return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed.astimezone(timezone.utc)


# =====================================================
# NOTIFICATION HELPER
# =====================================================

def create_notification(
    conn,
    user_id,
    title,
    message,
    notification_type="info"
):
    allowed_types = [
        "info",
        "success",
        "warning",
        "error"
    ]

    if notification_type not in allowed_types:
        notification_type = "info"

    conn.execute("""
        INSERT INTO notifications
        (
            user_id,
            title,
            message,
            notification_type,
            is_read
        )
        VALUES (%s, %s, %s, %s, FALSE)
    """, (
        user_id,
        title,
        message,
        notification_type
    ))


# =====================================================
# TASK CYCLE HELPERS
# =====================================================

def get_active_task_cycle(
    conn,
    user_id,
    for_update=False
):
    lock_sql = " FOR UPDATE" if for_update else ""

    return conn.execute(
        f"""
        SELECT *
        FROM task_cycles
        WHERE user_id = %s
        AND status = 'Active'
        ORDER BY id DESC
        LIMIT 1
        {lock_sql}
        """,
        (
            user_id,
        )
    ).fetchone()


def get_task_cycle_day(
    conn,
    cycle_id,
    day_number
):
    return conn.execute("""
        SELECT
            tcd.*,
            t.title AS task_title,
            t.description AS task_description,
            t.instructions AS task_instructions,
            t.reward AS task_reward,
            t.max_users,
            t.deadline,
            t.proof_type,
            t.status AS task_status
        FROM task_cycle_days tcd
        LEFT JOIN tasks t
            ON tcd.task_id = t.id
        WHERE tcd.cycle_id = %s
        AND tcd.day_number = %s
        LIMIT 1
    """, (
        cycle_id,
        day_number
    )).fetchone()


def get_current_cycle_day_number(cycle):
    if not cycle:
        return None

    started_at = parse_datetime(
        cycle["started_at"]
    )

    if not started_at:
        return None

    elapsed = utc_now() - started_at

    if elapsed.total_seconds() < 0:
        return 1

    day_number = int(
        elapsed.total_seconds() // 86400
    ) + 1

    return min(
        day_number,
        TASK_CYCLE_DAYS
    )


def format_remaining_time(seconds):
    seconds = max(
        0,
        int(seconds)
    )

    days = seconds // 86400
    seconds %= 86400

    hours = seconds // 3600
    seconds %= 3600

    minutes = seconds // 60
    seconds %= 60

    parts = []

    if days:
        parts.append(
            f"{days} day(s)"
        )

    if hours:
        parts.append(
            f"{hours} hour(s)"
        )

    if minutes:
        parts.append(
            f"{minutes} minute(s)"
        )

    if not parts:
        parts.append(
            f"{seconds} second(s)"
        )

    return ", ".join(parts)


def assign_task_to_cycle_day(
    conn,
    cycle_id,
    day_number
):
    existing_day = conn.execute("""
        SELECT *
        FROM task_cycle_days
        WHERE cycle_id = %s
        AND day_number = %s
        LIMIT 1
    """, (
        cycle_id,
        day_number
    )).fetchone()

    if existing_day:
        return existing_day

    # -------------------------------------------------
    # Pick a published task.
    #
    # Day 1 -> newest published task
    # Day 2 -> second newest if available
    # Day 3 -> third newest if available
    #
    # If there are fewer than 3 published tasks,
    # the newest published task is reused.
    # -------------------------------------------------

    published_tasks = conn.execute("""
        SELECT
            id,
            title,
            description,
            instructions,
            reward,
            max_users,
            deadline,
            proof_type,
            status
        FROM tasks
        WHERE status = 'Published'
        AND (
            deadline IS NULL
            OR deadline >= CURRENT_TIMESTAMP
        )
        ORDER BY id DESC
    """).fetchall()

    task_id = None

    if published_tasks:
        index = day_number - 1

        if index >= len(published_tasks):
            index = 0

        task_id = published_tasks[index]["id"]

    conn.execute("""
        INSERT INTO task_cycle_days
        (
            cycle_id,
            day_number,
            task_id,
            reward,
            status,
            notification_sent
        )
        VALUES (%s, %s, %s, %s, %s, FALSE)
    """, (
        cycle_id,
        day_number,
        task_id,
        TASK_CYCLE_REWARD,
        "Available"
    ))

    return conn.execute("""
        SELECT *
        FROM task_cycle_days
        WHERE cycle_id = %s
        AND day_number = %s
        LIMIT 1
    """, (
        cycle_id,
        day_number
    )).fetchone()


def ensure_task_cycle_progress(
    conn,
    user_id
):
    cycle = get_active_task_cycle(
        conn,
        user_id,
        for_update=True
    )

    if not cycle:
        return None

    started_at = parse_datetime(
        cycle["started_at"]
    )

    unlock_at = parse_datetime(
        cycle["unlock_at"]
    )

    if not started_at:
        return cycle

    now = utc_now()

    # -------------------------------------------------
    # Cycle has reached withdrawal unlock time.
    # -------------------------------------------------

    if unlock_at and now >= unlock_at:
        conn.execute("""
            UPDATE task_cycles
            SET status = 'Completed'
            WHERE id = %s
            AND status = 'Active'
        """, (
            cycle["id"],
        ))

        cycle["status"] = "Completed"

        return cycle

    current_day = get_current_cycle_day_number(
        cycle
    )

    if not current_day:
        return cycle

    # -------------------------------------------------
    # Ensure current day assignment exists.
    # -------------------------------------------------

    cycle_day = assign_task_to_cycle_day(
        conn,
        cycle["id"],
        current_day
    )

    # -------------------------------------------------
    # If a task exists and notification has not been
    # sent yet, send it now.
    # -------------------------------------------------

    if (
        cycle_day
        and cycle_day["task_id"]
        and not cycle_day["notification_sent"]
    ):
        task = conn.execute("""
            SELECT
                id,
                title
            FROM tasks
            WHERE id = %s
        """, (
            cycle_day["task_id"],
        )).fetchone()

        if task:
            create_notification(
                conn,
                user_id,
                f"Day {current_day} Task Available",
                (
                    f'Your Day {current_day} task '
                    f'"{task["title"]}" is now available. '
                    f'Complete it and submit your proof. '
                    f'Your reward is '
                    f'{TASK_CYCLE_REWARD:,.0f} Frw.'
                ),
                "info"
            )

            conn.execute("""
                UPDATE task_cycle_days
                SET notification_sent = TRUE
                WHERE id = %s
            """, (
                cycle_day["id"],
            ))

    # -------------------------------------------------
    # If no task was available when the cycle started,
    # try again whenever the user opens a task-related
    # page.
    # -------------------------------------------------

    conn.commit()

    return cycle


def start_task_cycle(
    conn,
    user_id,
    save_transaction_id
):
    # -------------------------------------------------
    # Do not create another active cycle.
    # -------------------------------------------------

    existing_cycle = get_active_task_cycle(
        conn,
        user_id,
        for_update=True
    )

    if existing_cycle:
        return existing_cycle, False

    started_at = utc_now()

    unlock_at = (
        started_at
        + TASK_CYCLE_DURATION
    )

    cursor = conn.execute("""
        INSERT INTO task_cycles
        (
            user_id,
            save_transaction_id,
            started_at,
            unlock_at,
            status
        )
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id
    """, (
        user_id,
        save_transaction_id,
        started_at,
        unlock_at,
        "Active"
    ))

    cycle_id = cursor.fetchone()["id"]

    cycle = conn.execute("""
        SELECT *
        FROM task_cycles
        WHERE id = %s
    """, (
        cycle_id,
    )).fetchone()

    # -------------------------------------------------
    # Create Day 1 immediately.
    # -------------------------------------------------

    cycle_day = assign_task_to_cycle_day(
        conn,
        cycle_id,
        1
    )

    if cycle_day and cycle_day["task_id"]:
        task = conn.execute("""
            SELECT
                id,
                title
            FROM tasks
            WHERE id = %s
        """, (
            cycle_day["task_id"],
        )).fetchone()

        if task:
            create_notification(
                conn,
                user_id,
                "Your Day 1 Task Is Ready",
                (
                    f'Your 3-day task cycle has started. '
                    f'Your Day 1 task is '
                    f'"{task["title"]}". '
                    f'Complete it and submit proof. '
                    f'You will receive '
                    f'{TASK_CYCLE_REWARD:,.0f} Frw '
                    f'when the task is approved.'
                ),
                "success"
            )

            conn.execute("""
                UPDATE task_cycle_days
                SET notification_sent = TRUE
                WHERE id = %s
            """, (
                cycle_day["id"],
            ))

    else:
        create_notification(
            conn,
            user_id,
            "Task Cycle Started",
            (
                "Your 3-day task cycle has started, "
                "but there is currently no published task. "
                "Your task will appear automatically when "
                "the administrator publishes one."
            ),
            "warning"
        )

    return cycle, True


def get_withdrawal_lock_info(
    conn,
    user_id
):
    cycle = get_active_task_cycle(
        conn,
        user_id,
        for_update=False
    )

    if not cycle:
        return {
            "locked": False,
            "cycle": None,
            "remaining_seconds": 0,
            "remaining_text": ""
        }

    unlock_at = parse_datetime(
        cycle["unlock_at"]
    )

    if not unlock_at:
        return {
            "locked": False,
            "cycle": cycle,
            "remaining_seconds": 0,
            "remaining_text": ""
        }

    remaining_seconds = (
        unlock_at - utc_now()
    ).total_seconds()

    if remaining_seconds <= 0:
        return {
            "locked": False,
            "cycle": cycle,
            "remaining_seconds": 0,
            "remaining_text": ""
        }

    return {
        "locked": True,
        "cycle": cycle,
        "remaining_seconds": int(
            remaining_seconds
        ),
        "remaining_text": format_remaining_time(
            remaining_seconds
        )
    }


# =====================================================
# DATABASE INITIALIZATION
# =====================================================

def init_db():
    conn = get_db()

    try:

        # =================================================
        # USERS
        # =================================================

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                phone TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                balance DOUBLE PRECISION DEFAULT 0,
                status TEXT DEFAULT 'Pending',
                role TEXT DEFAULT 'user',
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user'
        """)

        conn.execute("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS
            failed_login_attempts INTEGER DEFAULT 0
        """)

        conn.execute("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS
            locked_until TEXT
        """)

        conn.execute("""
            UPDATE users
            SET role = 'user'
            WHERE role IS NULL
            OR role = ''
        """)

        conn.execute("""
            UPDATE users
            SET failed_login_attempts = 0
            WHERE failed_login_attempts IS NULL
        """)


        # =================================================
        # TRANSACTIONS
        # =================================================

        conn.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                user_id BIGINT NOT NULL,
                transaction_type TEXT NOT NULL,
                amount DOUBLE PRECISION NOT NULL,
                destination_phone TEXT,
                network TEXT,
                status TEXT DEFAULT 'Completed',
                reference_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id)
                    REFERENCES users(id)
            )
        """)

        conn.execute("""
            ALTER TABLE transactions
            ADD COLUMN IF NOT EXISTS
            destination_phone TEXT
        """)

        conn.execute("""
            ALTER TABLE transactions
            ADD COLUMN IF NOT EXISTS
            network TEXT
        """)

        conn.execute("""
            ALTER TABLE transactions
            ADD COLUMN IF NOT EXISTS
            status TEXT DEFAULT 'Completed'
        """)

        conn.execute("""
            ALTER TABLE transactions
            ADD COLUMN IF NOT EXISTS
            reference_id TEXT
        """)


        # =================================================
        # PASSWORD RESETS
        # =================================================

        conn.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                user_id BIGINT NOT NULL,
                otp_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                attempts INTEGER DEFAULT 0,
                used INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id)
                    REFERENCES users(id)
            )
        """)


        # =================================================
        # TASKS
        # =================================================

        conn.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                instructions TEXT,
                reward DOUBLE PRECISION NOT NULL DEFAULT 0,
                max_users INTEGER,
                deadline TIMESTAMP,
                proof_type TEXT DEFAULT 'text',
                status TEXT DEFAULT 'Draft',
                created_by BIGINT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by)
                    REFERENCES users(id)
            )
        """)

        conn.execute("""
            ALTER TABLE tasks
            ADD COLUMN IF NOT EXISTS description TEXT
        """)

        conn.execute("""
            ALTER TABLE tasks
            ADD COLUMN IF NOT EXISTS instructions TEXT
        """)

        conn.execute("""
            ALTER TABLE tasks
            ADD COLUMN IF NOT EXISTS reward DOUBLE PRECISION DEFAULT 0
        """)

        conn.execute("""
            ALTER TABLE tasks
            ADD COLUMN IF NOT EXISTS max_users INTEGER
        """)

        conn.execute("""
            ALTER TABLE tasks
            ADD COLUMN IF NOT EXISTS deadline TIMESTAMP
        """)

        conn.execute("""
            ALTER TABLE tasks
            ADD COLUMN IF NOT EXISTS proof_type TEXT DEFAULT 'text'
        """)

        conn.execute("""
            ALTER TABLE tasks
            ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'Draft'
        """)

        conn.execute("""
            ALTER TABLE tasks
            ADD COLUMN IF NOT EXISTS
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        """)


        # =================================================
        # TASK SUBMISSIONS
        # =================================================

        conn.execute("""
            CREATE TABLE IF NOT EXISTS task_submissions (
                id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                task_id BIGINT NOT NULL,
                user_id BIGINT NOT NULL,
                cycle_day_id BIGINT,
                proof TEXT,
                status TEXT DEFAULT 'Pending',
                reviewed_by BIGINT,
                reviewed_at TIMESTAMP,
                rejection_reason TEXT,
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (task_id)
                    REFERENCES tasks(id),
                FOREIGN KEY (user_id)
                    REFERENCES users(id),
                FOREIGN KEY (reviewed_by)
                    REFERENCES users(id)
            )
        """)

        conn.execute("""
            ALTER TABLE task_submissions
            ADD COLUMN IF NOT EXISTS
            cycle_day_id BIGINT
        """)

        conn.execute("""
            ALTER TABLE task_submissions
            ADD COLUMN IF NOT EXISTS
            rejection_reason TEXT
        """)

        conn.execute("""
            ALTER TABLE task_submissions
            ADD COLUMN IF NOT EXISTS
            reviewed_by BIGINT
        """)

        conn.execute("""
            ALTER TABLE task_submissions
            ADD COLUMN IF NOT EXISTS
            reviewed_at TIMESTAMP
        """)


        # =================================================
        conn.execute('ALTER TABLE task_submissions ADD COLUMN IF NOT EXISTS proof_screenshot BYTEA')
        conn.execute('ALTER TABLE task_submissions ADD COLUMN IF NOT EXISTS proof_screenshot_mime TEXT')

        # NOTIFICATIONS
        # =================================================

        conn.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                user_id BIGINT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                notification_type TEXT DEFAULT 'info',
                is_read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        conn.execute("""
            ALTER TABLE notifications
            ADD COLUMN IF NOT EXISTS
            title TEXT
        """)

        conn.execute("""
            ALTER TABLE notifications
            ADD COLUMN IF NOT EXISTS
            message TEXT
        """)

        conn.execute("""
            ALTER TABLE notifications
            ADD COLUMN IF NOT EXISTS
            notification_type TEXT DEFAULT 'info'
        """)

        conn.execute("""
            ALTER TABLE notifications
            ADD COLUMN IF NOT EXISTS
            is_read BOOLEAN DEFAULT FALSE
        """)

        conn.execute("""
            ALTER TABLE notifications
            ADD COLUMN IF NOT EXISTS
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        """)

        conn.execute("""
            UPDATE notifications
            SET notification_type = 'info'
            WHERE notification_type IS NULL
            OR notification_type = ''
        """)

        conn.execute("""
            UPDATE notifications
            SET is_read = FALSE
            WHERE is_read IS NULL
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_notifications_user_id
            ON notifications(user_id)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_notifications_user_unread
            ON notifications(user_id, is_read)
        """)


        # =================================================
        # TASK CYCLES
        # =================================================

        conn.execute("""
            CREATE TABLE IF NOT EXISTS task_cycles (
                id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                user_id BIGINT NOT NULL,
                save_transaction_id BIGINT,
                started_at TIMESTAMP NOT NULL,
                unlock_at TIMESTAMP NOT NULL,
                status TEXT DEFAULT 'Active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE,
                FOREIGN KEY (save_transaction_id)
                    REFERENCES transactions(id)
                    ON DELETE SET NULL
            )
        """)

        conn.execute("""
            ALTER TABLE task_cycles
            ADD COLUMN IF NOT EXISTS
            save_transaction_id BIGINT
        """)

        conn.execute("""
            ALTER TABLE task_cycles
            ADD COLUMN IF NOT EXISTS
            started_at TIMESTAMP
        """)

        conn.execute("""
            ALTER TABLE task_cycles
            ADD COLUMN IF NOT EXISTS
            unlock_at TIMESTAMP
        """)

        conn.execute("""
            ALTER TABLE task_cycles
            ADD COLUMN IF NOT EXISTS
            status TEXT DEFAULT 'Active'
        """)

        conn.execute("""
            ALTER TABLE task_cycles
            ADD COLUMN IF NOT EXISTS
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_task_cycles_user_status
            ON task_cycles(user_id, status)
        """)


        # =================================================
        # TASK CYCLE DAYS
        # =================================================

        conn.execute("""
            CREATE TABLE IF NOT EXISTS task_cycle_days (
                id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                cycle_id BIGINT NOT NULL,
                day_number INTEGER NOT NULL,
                task_id BIGINT,
                reward DOUBLE PRECISION NOT NULL DEFAULT 2500,
                status TEXT DEFAULT 'Available',
                notification_sent BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cycle_id)
                    REFERENCES task_cycles(id)
                    ON DELETE CASCADE,
                FOREIGN KEY (task_id)
                    REFERENCES tasks(id)
                    ON DELETE SET NULL,
                UNIQUE (cycle_id, day_number)
            )
        """)

        conn.execute("""
            ALTER TABLE task_cycle_days
            ADD COLUMN IF NOT EXISTS
            task_id BIGINT
        """)

        conn.execute("""
            ALTER TABLE task_cycle_days
            ADD COLUMN IF NOT EXISTS
            reward DOUBLE PRECISION DEFAULT 2500
        """)

        conn.execute("""
            ALTER TABLE task_cycle_days
            ADD COLUMN IF NOT EXISTS
            status TEXT DEFAULT 'Available'
        """)

        conn.execute("""
            ALTER TABLE task_cycle_days
            ADD COLUMN IF NOT EXISTS
            notification_sent BOOLEAN DEFAULT FALSE
        """)

        conn.execute("""
            ALTER TABLE task_cycle_days
            ADD COLUMN IF NOT EXISTS
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_task_cycle_days_cycle
            ON task_cycle_days(cycle_id, day_number)
        """)


        # =================================================
        # OLD TRANSACTION REFERENCES
        # =================================================

        existing_transactions = conn.execute("""
            SELECT id
            FROM transactions
            WHERE reference_id IS NULL
            OR reference_id = ''
            ORDER BY id
        """).fetchall()

        for transaction in existing_transactions:
            reference_id = (
                f"RUD-{transaction['id']:06d}"
            )

            conn.execute("""
                UPDATE transactions
                SET reference_id = %s
                WHERE id = %s
            """, (
                reference_id,
                transaction["id"]
            ))


        # =================================================
        # IDENTITY SEQUENCES
        # =================================================

        conn.execute("""
            SELECT setval(
                pg_get_serial_sequence(
                    'users',
                    'id'
                ),
                COALESCE(MAX(id), 1),
                COUNT(*) > 0
            )
            FROM users
        """)

        conn.execute("""
            SELECT setval(
                pg_get_serial_sequence(
                    'transactions',
                    'id'
                ),
                COALESCE(MAX(id), 1),
                COUNT(*) > 0
            )
            FROM transactions
        """)

        conn.execute("""
            SELECT setval(
                pg_get_serial_sequence(
                    'password_resets',
                    'id'
                ),
                COALESCE(MAX(id), 1),
                COUNT(*) > 0
            )
            FROM password_resets
        """)

        conn.execute("""
            SELECT setval(
                pg_get_serial_sequence(
                    'tasks',
                    'id'
                ),
                COALESCE(MAX(id), 1),
                COUNT(*) > 0
            )
            FROM tasks
        """)

        conn.execute("""
            SELECT setval(
                pg_get_serial_sequence(
                    'task_submissions',
                    'id'
                ),
                COALESCE(MAX(id), 1),
                COUNT(*) > 0
            )
            FROM task_submissions
        """)

        conn.execute("""
            SELECT setval(
                pg_get_serial_sequence(
                    'notifications',
                    'id'
                ),
                COALESCE(MAX(id), 1),
                COUNT(*) > 0
            )
            FROM notifications
        """)

        conn.execute("""
            SELECT setval(
                pg_get_serial_sequence(
                    'task_cycles',
                    'id'
                ),
                COALESCE(MAX(id), 1),
                COUNT(*) > 0
            )
            FROM task_cycles
        """)

        conn.execute("""
            SELECT setval(
                pg_get_serial_sequence(
                    'task_cycle_days',
                    'id'
                ),
                COALESCE(MAX(id), 1),
                COUNT(*) > 0
            )
            FROM task_cycle_days
        """)

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
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

        phone = (
            phone
            .replace(" ", "")
            .replace("-", "")
        )

        if country_code and not country_code.startswith("+"):
            country_code = "+" + country_code

        if phone.startswith("0"):
            phone = phone[1:]

        full_phone = (
            country_code
            + phone
        )

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

        try:

            existing_user = conn.execute("""
                SELECT id
                FROM users
                WHERE phone = %s
            """, (
                full_phone,
            )).fetchone()

            if existing_user:
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
                VALUES (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s
                )
            """, (
                full_phone,
                hashed_password,
                0,
                "Active",
                "user",
                0,
                None
            ))

            conn.commit()

        except Exception:
            conn.rollback()
            raise

        finally:
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

        phone = (
            phone
            .replace(" ", "")
            .replace("-", "")
        )

        if country_code and not country_code.startswith("+"):
            country_code = "+" + country_code

        if phone.startswith("0"):
            phone = phone[1:]

        full_phone = (
            country_code
            + phone
        )

        conn = get_db()

        try:

            user = conn.execute("""
                SELECT *
                FROM users
                WHERE phone = %s
            """, (
                full_phone,
            )).fetchone()

            if not user:
                flash(
                    "Phone number or password is incorrect.",
                    "error"
                )

                return redirect(
                    url_for("login")
                )


            # =================================================
            # ACCOUNT STATUS
            # =================================================

            if (
                user["role"] != "admin"
                and user["status"] != "Active"
            ):
                flash(
                    "Your account is currently inactive. "
                    "Please contact the administrator.",
                    "error"
                )

                return redirect(
                    url_for("login")
                )


            # =================================================
            # LOGIN LOCK
            # =================================================

            locked_until = user["locked_until"]

            if locked_until:

                lock_time = parse_datetime(
                    locked_until
                )

                if (
                    lock_time
                    and utc_now() < lock_time
                ):

                    remaining_seconds = (
                        lock_time - utc_now()
                    ).total_seconds()

                    remaining_minutes = max(
                        1,
                        int(
                            (
                                remaining_seconds
                                + 59
                            )
                            // 60
                        )
                    )

                    flash(
                        "Account temporarily locked. "
                        "Please try again in approximately "
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
                    WHERE id = %s
                """, (
                    user["id"],
                ))

                conn.commit()

                user = conn.execute("""
                    SELECT *
                    FROM users
                    WHERE id = %s
                """, (
                    user["id"],
                )).fetchone()


            # =================================================
            # PASSWORD CHECK
            # =================================================

            password_is_correct = check_password_hash(
                user["password"],
                password
            )

            if not password_is_correct:

                new_attempts = (
                    (
                        user["failed_login_attempts"]
                        or 0
                    )
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
                        SET failed_login_attempts = %s,
                            locked_until = %s
                        WHERE id = %s
                    """, (
                        new_attempts,
                        lock_until.isoformat(),
                        user["id"]
                    ))

                    conn.commit()

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
                    SET failed_login_attempts = %s
                    WHERE id = %s
                """, (
                    new_attempts,
                    user["id"]
                ))

                conn.commit()

                remaining_attempts = (
                    MAX_LOGIN_ATTEMPTS
                    - new_attempts
                )

                flash(
                    "Phone number or password is incorrect. "
                    f"{remaining_attempts} attempt(s) remaining.",
                    "error"
                )

                return redirect(
                    url_for("login")
                )


            # =================================================
            # SUCCESSFUL LOGIN
            # =================================================

            conn.execute("""
                UPDATE users
                SET failed_login_attempts = 0,
                    locked_until = NULL
                WHERE id = %s
            """, (
                user["id"],
            ))

            conn.commit()

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

        finally:
            conn.close()

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

        phone = (
            phone
            .replace(" ", "")
            .replace("-", "")
        )

        if country_code and not country_code.startswith("+"):
            country_code = "+" + country_code

        if phone.startswith("0"):
            phone = phone[1:]

        full_phone = (
            country_code
            + phone
        )

        if not country_code or not phone:
            flash(
                "Please enter your phone number.",
                "error"
            )

            return redirect(
                url_for("forgot_password")
            )

        conn = get_db()

        try:

            user = conn.execute("""
                SELECT *
                FROM users
                WHERE phone = %s
            """, (
                full_phone,
            )).fetchone()

            if not user:
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
                WHERE user_id = %s
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
                VALUES (%s, %s, %s, %s, %s)
            """, (
                user["id"],
                otp_hash,
                expires_at.isoformat(),
                0,
                0
            ))

            conn.commit()

            session["reset_user_id"] = user["id"]
            session["reset_phone"] = user["phone"]
            session["development_otp"] = otp

            flash(
                f"Development OTP: {otp}",
                "success"
            )

            return redirect(
                url_for("verify_reset_otp")
            )

        except Exception:
            conn.rollback()
            raise

        finally:
            conn.close()

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

        try:

            reset = conn.execute("""
                SELECT *
                FROM password_resets
                WHERE user_id = %s
                AND used = 0
                ORDER BY id DESC
                LIMIT 1
            """, (
                session["reset_user_id"],
            )).fetchone()

            if not reset:

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

            if (
                not expires_at
                or utc_now() > expires_at
            ):

                conn.execute("""
                    UPDATE password_resets
                    SET used = 1
                    WHERE id = %s
                """, (
                    reset["id"],
                ))

                conn.commit()

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
                    WHERE id = %s
                """, (
                    reset["id"],
                ))

                conn.commit()

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
                    WHERE id = %s
                """, (
                    reset["id"],
                ))

                conn.commit()

                remaining_attempts = (
                    MAX_OTP_ATTEMPTS
                    - reset["attempts"]
                    - 1
                )

                flash(
                    "Incorrect OTP. "
                    f"{remaining_attempts} attempts remaining.",
                    "error"
                )

                return redirect(
                    url_for("verify_reset_otp")
                )

            conn.execute("""
                UPDATE password_resets
                SET used = 1
                WHERE id = %s
            """, (
                reset["id"],
            ))

            conn.commit()

            session["reset_verified"] = True

            session.pop(
                "development_otp",
                None
            )

            return redirect(
                url_for("reset_password")
            )

        except Exception:
            conn.rollback()
            raise

        finally:
            conn.close()

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

        try:

            user = conn.execute("""
                SELECT *
                FROM users
                WHERE id = %s
            """, (
                session["reset_user_id"],
            )).fetchone()

            if not user:
                session.clear()

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
                SET password = %s,
                    failed_login_attempts = 0,
                    locked_until = NULL
                WHERE id = %s
            """, (
                hashed_password,
                user["id"]
            ))

            conn.commit()

        except Exception:
            conn.rollback()
            raise

        finally:
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

    try:

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE id = %s
        """, (
            session["user_id"],
        )).fetchone()

        if not user:
            session.clear()

            return redirect(
                url_for("login")
            )

        # -------------------------------------------------
        # Update task cycle progress.
        # -------------------------------------------------

        cycle = ensure_task_cycle_progress(
            conn,
            session["user_id"]
        )

        transactions = conn.execute("""
            SELECT *
            FROM transactions
            WHERE user_id = %s
            ORDER BY id DESC
            LIMIT 5
        """, (
            session["user_id"],
        )).fetchall()


        # TOTAL SAVED

        total_saved = conn.execute("""
            SELECT COALESCE(
                SUM(amount),
                0
            ) AS total_saved
            FROM transactions
            WHERE user_id = %s
            AND transaction_type = 'Save'
            AND status = 'Completed'
        """, (
            session["user_id"],
        )).fetchone()["total_saved"]


        # TOTAL EARNED FROM TASKS

        total_earned = conn.execute("""
            SELECT COALESCE(
                SUM(amount),
                0
            ) AS total_earned
            FROM transactions
            WHERE user_id = %s
            AND transaction_type = 'Task Reward'
            AND status = 'Completed'
        """, (
            session["user_id"],
        )).fetchone()["total_earned"]


        # TOTAL WITHDRAWN

        total_withdrawn = conn.execute("""
            SELECT COALESCE(
                SUM(amount),
                0
            ) AS total_withdrawn
            FROM transactions
            WHERE user_id = %s
            AND transaction_type = 'Withdraw'
            AND status = 'Completed'
        """, (
            session["user_id"],
        )).fetchone()["total_withdrawn"]


        # PENDING WITHDRAWALS

        pending_withdrawals = conn.execute("""
            SELECT COALESCE(
                SUM(amount),
                0
            ) AS pending_withdrawals
            FROM transactions
            WHERE user_id = %s
            AND transaction_type = 'Withdraw'
            AND status = 'Pending'
        """, (
            session["user_id"],
        )).fetchone()["pending_withdrawals"]


        # -------------------------------------------------
        # Current task cycle information
        # -------------------------------------------------

        cycle_day = None
        current_day_number = None
        withdrawal_lock = None

        if cycle and cycle["status"] == "Active":

            current_day_number = (
                get_current_cycle_day_number(
                    cycle
                )
            )

            if current_day_number:

                cycle_day = get_task_cycle_day(
                    conn,
                    cycle["id"],
                    current_day_number
                )

                withdrawal_lock = (
                    get_withdrawal_lock_info(
                        conn,
                        session["user_id"]
                    )
                )

    finally:
        conn.close()

    return render_template(
        "dashboard.html",
        user=user,
        transactions=transactions,
        total_saved=total_saved,
        total_earned=total_earned,
        total_withdrawn=total_withdrawn,
        pending_withdrawals=pending_withdrawals,
        task_cycle=cycle,
        task_cycle_day=cycle_day,
        current_day_number=current_day_number,
        withdrawal_lock=withdrawal_lock
    )


# =====================================================
# NOTIFICATIONS
# =====================================================

@app.route("/notifications")
def notifications():

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    if session.get("role") == "admin":
        return redirect(
            url_for("admin_dashboard")
        )

    conn = get_db()

    try:

        # Make sure today's task notification exists.

        ensure_task_cycle_progress(
            conn,
            session["user_id"]
        )

        user_notifications = conn.execute("""
            SELECT
                id,
                user_id,
                title,
                message,
                notification_type,
                is_read,
                created_at
            FROM notifications
            WHERE user_id = %s
            ORDER BY id DESC
        """, (
            session["user_id"],
        )).fetchall()

        unread_count = conn.execute("""
            SELECT COUNT(*) AS value
            FROM notifications
            WHERE user_id = %s
            AND is_read = FALSE
        """, (
            session["user_id"],
        )).fetchone()["value"]

    finally:
        conn.close()

    return render_template(
        "notifications.html",
        notifications=user_notifications,
        unread_count=unread_count
    )


# =====================================================
# NOTIFICATION COUNT API
# =====================================================

@app.route("/api/notifications")
def notification_api():

    if "user_id" not in session:
        return jsonify({
            "success": False,
            "message": "Authentication required."
        }), 401

    if session.get("role") == "admin":
        return jsonify({
            "success": False,
            "message": (
                "Admin accounts do not use "
                "user notifications."
            )
        }), 403

    conn = get_db()

    try:

        ensure_task_cycle_progress(
            conn,
            session["user_id"]
        )

        notifications_data = conn.execute("""
            SELECT
                id,
                title,
                message,
                notification_type,
                is_read,
                created_at
            FROM notifications
            WHERE user_id = %s
            ORDER BY id DESC
            LIMIT 20
        """, (
            session["user_id"],
        )).fetchall()

        unread_count = conn.execute("""
            SELECT COUNT(*) AS value
            FROM notifications
            WHERE user_id = %s
            AND is_read = FALSE
        """, (
            session["user_id"],
        )).fetchone()["value"]

    finally:
        conn.close()

    result = []

    for notification in notifications_data:

        created_at = notification["created_at"]

        if isinstance(
            created_at,
            datetime
        ):
            created_at = created_at.isoformat()

        result.append({
            "id": notification["id"],
            "title": notification["title"],
            "message": notification["message"],
            "notification_type": (
                notification["notification_type"]
                or "info"
            ),
            "is_read": bool(
                notification["is_read"]
            ),
            "created_at": created_at
        })

    return jsonify({
        "success": True,
        "unread_count": unread_count,
        "notifications": result
    })


# =====================================================
# MARK ONE NOTIFICATION AS READ
# =====================================================

@app.route(
    "/notifications/<int:notification_id>/read",
    methods=["POST"]
)
def mark_notification_read(
    notification_id
):

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    if session.get("role") == "admin":
        return redirect(
            url_for("admin_dashboard")
        )

    conn = get_db()

    try:

        conn.execute("""
            UPDATE notifications
            SET is_read = TRUE
            WHERE id = %s
            AND user_id = %s
        """, (
            notification_id,
            session["user_id"]
        ))

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    return redirect(
        url_for("notifications")
    )


# =====================================================
# MARK ALL NOTIFICATIONS AS READ
# =====================================================

@app.route(
    "/notifications/read-all",
    methods=["POST"]
)
def mark_all_notifications_read():

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    if session.get("role") == "admin":
        return redirect(
            url_for("admin_dashboard")
        )

    conn = get_db()

    try:

        conn.execute("""
            UPDATE notifications
            SET is_read = TRUE
            WHERE user_id = %s
            AND is_read = FALSE
        """, (
            session["user_id"],
        ))

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    return redirect(
        url_for("notifications")
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
# ADMIN SEND NOTIFICATION
# =====================================================

@app.route(
    "/admin/notifications/send",
    methods=["POST"]
)
def admin_send_notification():

    if not admin_required():
        return redirect(
            url_for("login")
        )

    user_id_text = request.form.get(
        "user_id",
        ""
    ).strip()

    title = request.form.get(
        "title",
        ""
    ).strip()

    message = request.form.get(
        "message",
        ""
    ).strip()

    notification_type = request.form.get(
        "notification_type",
        "info"
    ).strip()

    if notification_type not in [
        "info",
        "success",
        "warning",
        "error"
    ]:
        notification_type = "info"

    if not user_id_text:
        flash(
            "Please select a user.",
            "error"
        )

        return redirect(
            url_for("admin_users")
        )

    try:
        user_id = int(user_id_text)

    except (
        ValueError,
        TypeError
    ):
        flash(
            "Invalid user ID.",
            "error"
        )

        return redirect(
            url_for("admin_users")
        )

    if not title:
        flash(
            "Notification title is required.",
            "error"
        )

        return redirect(
            url_for(
                "admin_user_details",
                user_id=user_id
            )
        )

    if not message:
        flash(
            "Notification message is required.",
            "error"
        )

        return redirect(
            url_for(
                "admin_user_details",
                user_id=user_id
            )
        )

    conn = get_db()

    try:

        user = conn.execute("""
            SELECT
                id,
                phone,
                role
            FROM users
            WHERE id = %s
        """, (
            user_id,
        )).fetchone()

        if not user or user["role"] != "user":
            flash(
                "User account not found.",
                "error"
            )

            return redirect(
                url_for("admin_users")
            )

        create_notification(
            conn,
            user_id,
            title,
            message,
            notification_type
        )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    flash(
        "Notification sent successfully.",
        "success"
    )

    return redirect(
        url_for(
            "admin_user_details",
            user_id=user_id
        )
    )


# =====================================================
# USER TASKS
# =====================================================

@app.route("/tasks")
def tasks():

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    if session.get("role") == "admin":
        return redirect(
            url_for("admin_dashboard")
        )

    conn = get_db()

    try:

        cycle = ensure_task_cycle_progress(
            conn,
            session["user_id"]
        )

        tasks_list = []

        current_day_number = None
        cycle_day = None

        if (
            cycle
            and cycle["status"] == "Active"
        ):

            current_day_number = (
                get_current_cycle_day_number(
                    cycle
                )
            )

            if current_day_number:

                cycle_day = get_task_cycle_day(
                    conn,
                    cycle["id"],
                    current_day_number
                )

                if (
                    cycle_day
                    and cycle_day["task_id"]
                ):

                    task = conn.execute("""
                        SELECT
                            t.id,
                            t.title,
                            t.description,
                            t.instructions,
                            t.reward,
                            t.max_users,
                            t.deadline,
                            t.proof_type,
                            t.status,
                            t.created_at,
                            COUNT(ts.id) AS submission_count
                        FROM tasks t
                        LEFT JOIN task_submissions ts
                            ON t.id = ts.task_id
                        AND ts.cycle_day_id = %s
                        WHERE t.id = %s
                        AND t.status = 'Published'
                        GROUP BY
                            t.id,
                            t.title,
                            t.description,
                            t.instructions,
                            t.reward,
                            t.max_users,
                            t.deadline,
                            t.proof_type,
                            t.status,
                            t.created_at
                    """, (
                        cycle_day["id"],
                        cycle_day["task_id"]
                    )).fetchone()

                    if task:
                        tasks_list.append(task)

    finally:
        conn.close()

    return render_template(
        "tasks.html",
        tasks=tasks_list,
        task_cycle=cycle,
        task_cycle_day=cycle_day,
        current_day_number=current_day_number,
        cycle_reward=TASK_CYCLE_REWARD
    )


# =====================================================
# USER TASK DETAIL
# =====================================================

@app.route(
    "/tasks/<int:task_id>"
)
def task_detail(task_id):

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    if session.get("role") == "admin":
        return redirect(
            url_for("admin_dashboard")
        )

    conn = get_db()

    try:

        cycle = ensure_task_cycle_progress(
            conn,
            session["user_id"]
        )

        if (
            not cycle
            or cycle["status"] != "Active"
        ):
            flash(
                "You do not currently have an active task.",
                "error"
            )

            return redirect(
                url_for("tasks")
            )

        current_day_number = (
            get_current_cycle_day_number(
                cycle
            )
        )

        cycle_day = get_task_cycle_day(
            conn,
            cycle["id"],
            current_day_number
        )

        if (
            not cycle_day
            or cycle_day["task_id"] != task_id
        ):
            flash(
                "This task is not your current daily task.",
                "error"
            )

            return redirect(
                url_for("tasks")
            )

        task = conn.execute("""
            SELECT
                t.id,
                t.title,
                t.description,
                t.instructions,
                t.reward,
                t.max_users,
                t.deadline,
                t.proof_type,
                t.status,
                t.created_at,
                COUNT(ts.id) AS submission_count
            FROM tasks t
            LEFT JOIN task_submissions ts
                ON t.id = ts.task_id
            AND ts.cycle_day_id = %s
            WHERE t.id = %s
            AND t.status = 'Published'
            GROUP BY
                t.id,
                t.title,
                t.description,
                t.instructions,
                t.reward,
                t.max_users,
                t.deadline,
                t.proof_type,
                t.status,
                t.created_at
        """, (
            cycle_day["id"],
            task_id
        )).fetchone()

        if not task:
            flash(
                "Task not found or is no longer available.",
                "error"
            )

            return redirect(
                url_for("tasks")
            )

        user_submission = conn.execute("""
            SELECT *
            FROM task_submissions
            WHERE cycle_day_id = %s
            AND user_id = %s
            ORDER BY id DESC
            LIMIT 1
        """, (
            cycle_day["id"],
            session["user_id"]
        )).fetchone()

    finally:
        conn.close()

    deadline = parse_datetime(
        task["deadline"]
    )

    if (
        deadline
        and utc_now() > deadline
    ):
        flash(
            "This task has expired.",
            "error"
        )

        return redirect(
            url_for("tasks")
        )

    return render_template(
        "task_detail.html",
        task=task,
        user_submission=user_submission,
        task_cycle=cycle,
        task_cycle_day=cycle_day,
        current_day_number=current_day_number,
        cycle_reward=TASK_CYCLE_REWARD
    )


# =====================================================
# USER SUBMIT TASK
# =====================================================

@app.route(
    "/tasks/<int:task_id>/submit",
    methods=["GET", "POST"]
)
def submit_task(task_id):

    if "user_id" not in session:
        return redirect(
            url_for("login")
        )

    if session.get("role") == "admin":
        return redirect(
            url_for("admin_dashboard")
        )

    conn = get_db()

    try:

        cycle = ensure_task_cycle_progress(
            conn,
            session["user_id"]
        )

        if (
            not cycle
            or cycle["status"] != "Active"
        ):
            flash(
                "You do not currently have an active task.",
                "error"
            )

            return redirect(
                url_for("tasks")
            )

        current_day_number = (
            get_current_day_number
            if False else
            get_current_cycle_day_number(cycle)
        )

        cycle_day = get_task_cycle_day(
            conn,
            cycle["id"],
            current_day_number
        )

        if (
            not cycle_day
            or cycle_day["task_id"] != task_id
        ):
            flash(
                "This task is not your current daily task.",
                "error"
            )

            return redirect(
                url_for("tasks")
            )

        task = conn.execute("""
            SELECT
                t.id,
                t.title,
                t.description,
                t.instructions,
                t.reward,
                t.max_users,
                t.deadline,
                t.proof_type,
                t.status,
                COUNT(ts.id) AS submission_count
            FROM tasks t
            LEFT JOIN task_submissions ts
                ON t.id = ts.task_id
            AND ts.cycle_day_id = %s
            WHERE t.id = %s
            AND t.status = 'Published'
            GROUP BY
                t.id,
                t.title,
                t.description,
                t.instructions,
                t.reward,
                t.max_users,
                t.deadline,
                t.proof_type,
                t.status
        """, (
            cycle_day["id"],
            task_id
        )).fetchone()

        if not task:
            flash(
                "Task not found or is no longer available.",
                "error"
            )

            return redirect(
                url_for("tasks")
            )

        deadline = parse_datetime(
            task["deadline"]
        )

        if (
            deadline
            and utc_now() > deadline
        ):
            flash(
                "This task has expired.",
                "error"
            )

            return redirect(
                url_for("tasks")
            )

        existing_submission = conn.execute("""
            SELECT *
            FROM task_submissions
            WHERE cycle_day_id = %s
            AND user_id = %s
            ORDER BY id DESC
            LIMIT 1
        """, (
            cycle_day["id"],
            session["user_id"]
        )).fetchone()

        if existing_submission:
            flash(
                "You have already submitted today's task.",
                "error"
            )

            return redirect(
                url_for(
                    "task_detail",
                    task_id=task_id
                )
            )

        if request.method == "POST":

            proof = request.form.get(
                "proof",
                ""
            ).strip()

            if not proof:
                flash(
                    "Please provide your proof.",
                    "error"
                )

                return redirect(
                    url_for(
                        "submit_task",
                        task_id=task_id
                    )
                )

            conn.execute("""
                INSERT INTO task_submissions
                (
                    task_id,
                    user_id,
                    cycle_day_id,
                    proof,
                    status
                )
                VALUES (%s, %s, %s, %s, %s)
            """, (
                task_id,
                session["user_id"],
                cycle_day["id"],
                proof,
                "Pending"
            ))

            conn.execute("""
                UPDATE task_cycle_days
                SET status = 'Submitted'
                WHERE id = %s
            """, (
                cycle_day["id"],
            ))

            conn.commit()

            flash(
                "Task submitted successfully. "
                "Your submission is now waiting "
                "for admin review.",
                "success"
            )

            return redirect(
                url_for(
                    "task_detail",
                    task_id=task_id
                )
            )

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    return render_template(
        "submit_task.html",
        task=task,
        task_cycle=cycle,
        task_cycle_day=cycle_day,
        current_day_number=current_day_number,
        cycle_reward=TASK_CYCLE_REWARD
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

        except (
            ValueError,
            TypeError
        ):
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

        try:

            # -------------------------------------------------
            # Add saved money to balance.
            # -------------------------------------------------

            conn.execute("""
                UPDATE users
                SET balance = balance + %s
                WHERE id = %s
            """, (
                amount,
                session["user_id"]
            ))

            reference_id = (
                f"RUD-{secrets.token_hex(4).upper()}"
            )

            cursor = conn.execute("""
                INSERT INTO transactions
                (
                    user_id,
                    transaction_type,
                    amount,
                    status,
                    reference_id
                )
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            """, (
                session["user_id"],
                "Save",
                amount,
                "Completed",
                reference_id
            ))

            save_transaction_id = (
                cursor.fetchone()["id"]
            )

            # -------------------------------------------------
            # Start a new 3-day cycle when the save reaches
            # 3,000 Frw.
            #
            # If a cycle is already active, don't start
            # another one.
            # -------------------------------------------------

            cycle_started = False

            if amount >= TASK_CYCLE_SAVE_AMOUNT:

                existing_cycle = (
                    get_active_task_cycle(
                        conn,
                        session["user_id"],
                        for_update=True
                    )
                )

                if not existing_cycle:

                    start_task_cycle(
                        conn,
                        session["user_id"],
                        save_transaction_id
                    )

                    cycle_started = True

            conn.commit()

        except Exception:
            conn.rollback()
            raise

        finally:
            conn.close()

        if cycle_started:

            flash(
                (
                    f"{amount:,.0f} Frw saved successfully. "
                    f"Your 3-day task cycle has started. "
                    f"You can earn "
                    f"{TASK_CYCLE_REWARD:,.0f} Frw "
                    f"per approved daily task."
                ),
                "success"
            )

        else:

            flash(
                f"{amount:,.2f} added to your balance successfully.",
                "success"
            )

        return redirect(
            url_for("save_payment")
        )

    conn = get_db()

    try:

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE id = %s
        """, (
            session["user_id"],
        )).fetchone()

        transactions = conn.execute("""
            SELECT *
            FROM transactions
            WHERE user_id = %s
            ORDER BY id DESC
            LIMIT 5
        """, (
            session["user_id"],
        )).fetchall()

        cycle = ensure_task_cycle_progress(
            conn,
            session["user_id"]
        )

    finally:
        conn.close()

    return render_template(
        "save.html",
        user=user,
        transactions=transactions,
        task_cycle=cycle
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

        network = request.form.get(
            "network",
            ""
        ).strip().lower()

        destination_phone = request.form.get(
            "destination_phone",
            ""
        ).strip()

        destination_phone = (
            destination_phone
            .replace(" ", "")
            .replace("-", "")
        )

        allowed_networks = {
            "mtn",
            "airtel"
        }

        if network not in allowed_networks:
            flash(
                "Please select a valid mobile network.",
                "error"
            )

            return redirect(
                url_for("withdraw")
            )

        try:
            amount = float(amount_text)

        except (
            ValueError,
            TypeError
        ):
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

        try:

            # -------------------------------------------------
            # Update cycle state first.
            # -------------------------------------------------

            cycle = ensure_task_cycle_progress(
                conn,
                session["user_id"]
            )

            # -------------------------------------------------
            # Withdrawal lock.
            # -------------------------------------------------

            lock_info = get_withdrawal_lock_info(
                conn,
                session["user_id"]
            )

            if lock_info["locked"]:

                flash(
                    (
                        "Withdrawal is currently locked. "
                        "You can withdraw after "
                        f"{lock_info['remaining_text']}."
                    ),
                    "warning"
                )

                return redirect(
                    url_for("withdraw")
                )

            # -------------------------------------------------
            # Lock user row before changing balance.
            # -------------------------------------------------

            user = conn.execute("""
                SELECT *
                FROM users
                WHERE id = %s
                FOR UPDATE
            """, (
                session["user_id"],
            )).fetchone()

            if not user:

                flash(
                    "User account not found.",
                    "error"
                )

                return redirect(
                    url_for("login")
                )

            if amount > user["balance"]:

                flash(
                    "Insufficient balance for this withdrawal.",
                    "error"
                )

                return redirect(
                    url_for("withdraw")
                )

            conn.execute("""
                UPDATE users
                SET balance = balance - %s
                WHERE id = %s
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
                    network,
                    status,
                    reference_id
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s
                )
            """, (
                session["user_id"],
                "Withdraw",
                amount,
                destination_phone,
                network,
                "Pending",
                reference_id
            ))

            conn.commit()

        except Exception:
            conn.rollback()
            raise

        finally:
            conn.close()

        flash(
            (
                f"Withdrawal request for "
                f"{amount:,.2f} submitted successfully."
            ),
            "success"
        )

        return redirect(
            url_for("withdraw")
        )

    conn = get_db()

    try:

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE id = %s
        """, (
            session["user_id"],
        )).fetchone()

        transactions = conn.execute("""
            SELECT *
            FROM transactions
            WHERE user_id = %s
            AND transaction_type = 'Withdraw'
            ORDER BY id DESC
            LIMIT 5
        """, (
            session["user_id"],
        )).fetchall()

        cycle = ensure_task_cycle_progress(
            conn,
            session["user_id"]
        )

        withdrawal_lock = (
            get_withdrawal_lock_info(
                conn,
                session["user_id"]
            )
        )

    finally:
        conn.close()

    return render_template(
        "withdraw.html",
        user=user,
        transactions=transactions,
        task_cycle=cycle,
        withdrawal_lock=withdrawal_lock
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

    try:

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE id = %s
        """, (
            session["user_id"],
        )).fetchone()

    finally:
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

    try:

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE id = %s
        """, (
            session["user_id"],
        )).fetchone()

    finally:
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

        try:

            user = conn.execute("""
                SELECT *
                FROM users
                WHERE id = %s
            """, (
                session["user_id"],
            )).fetchone()

            if not user:
                session.clear()

                return redirect(
                    url_for("login")
                )

            if not check_password_hash(
                user["password"],
                current_password
            ):
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
                SET password = %s,
                    failed_login_attempts = 0,
                    locked_until = NULL
                WHERE id = %s
            """, (
                hashed_password,
                session["user_id"]
            ))

            conn.commit()

        except Exception:
            conn.rollback()
            raise

        finally:
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
# ADMIN DASHBOARD
# =====================================================

@app.route("/admin")
def admin_dashboard():

    if not admin_required():
        return redirect(
            url_for("login")
        )

    conn = get_db()

    try:

        total_users = conn.execute("""
            SELECT COUNT(*) AS value
            FROM users
            WHERE role = 'user'
        """).fetchone()["value"]

        active_users = conn.execute("""
            SELECT COUNT(*) AS value
            FROM users
            WHERE role = 'user'
            AND status = 'Active'
        """).fetchone()["value"]

        pending_users = conn.execute("""
            SELECT COUNT(*) AS value
            FROM users
            WHERE role = 'user'
            AND status = 'Pending'
        """).fetchone()["value"]

        total_balance = conn.execute("""
            SELECT COALESCE(
                SUM(balance),
                0
            ) AS value
            FROM users
            WHERE role = 'user'
        """).fetchone()["value"]

        total_saves = conn.execute("""
            SELECT COALESCE(
                SUM(amount),
                0
            ) AS value
            FROM transactions
            WHERE transaction_type = 'Save'
        """).fetchone()["value"]

        total_withdrawals = conn.execute("""
            SELECT COALESCE(
                SUM(amount),
                0
            ) AS value
            FROM transactions
            WHERE transaction_type = 'Withdraw'
        """).fetchone()["value"]

        withdrawal_count = conn.execute("""
            SELECT COUNT(*) AS value
            FROM transactions
            WHERE transaction_type = 'Withdraw'
        """).fetchone()["value"]

        pending_withdrawals = conn.execute("""
            SELECT COUNT(*) AS value
            FROM transactions
            WHERE transaction_type = 'Withdraw'
            AND status = 'Pending'
        """).fetchone()["value"]

        pending_task_submissions = conn.execute("""
            SELECT COUNT(*) AS value
            FROM task_submissions
            WHERE status = 'Pending'
        """).fetchone()["value"]

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

    finally:
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
        pending_task_submissions=pending_task_submissions,
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

    try:

        if search:

            users = conn.execute("""
                SELECT *
                FROM users
                WHERE role = 'user'
                AND phone LIKE %s
                ORDER BY id DESC
            """, (
                f"%{search}%"
            )).fetchall()

        else:

            users = conn.execute("""
                SELECT *
                FROM users
                WHERE role = 'user'
                ORDER BY id DESC
            """).fetchall()

    finally:
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
def admin_update_user_status(
    user_id
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

    try:

        user = conn.execute("""
            SELECT
                id,
                phone,
                role,
                status
            FROM users
            WHERE id = %s
        """, (
            user_id,
        )).fetchone()

        if not user:

            flash(
                "User account not found.",
                "error"
            )

            return redirect(
                url_for("admin_users")
            )

        if user["role"] == "admin":

            flash(
                "Admin accounts cannot be changed from "
                "the user management page.",
                "error"
            )

            return redirect(
                url_for("admin_users")
            )

        conn.execute("""
            UPDATE users
            SET status = %s
            WHERE id = %s
            AND role = 'user'
        """, (
            new_status,
            user_id
        ))

        if new_status == "Active":

            create_notification(
                conn,
                user_id,
                "Account Activated",
                (
                    "Your Rudbit account has been activated. "
                    "You can now use your account normally."
                ),
                "success"
            )

        else:

            create_notification(
                conn,
                user_id,
                "Account Status Updated",
                (
                    "Your Rudbit account has been temporarily "
                    "deactivated. Please contact the administrator "
                    "if you need assistance."
                ),
                "warning"
            )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
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

    try:

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE id = %s
            AND role = 'user'
        """, (
            user_id,
        )).fetchone()

        if not user:

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
                network,
                status,
                reference_id
            FROM transactions
            WHERE user_id = %s
            ORDER BY id DESC
        """, (
            user_id,
        )).fetchall()

        notification_count = conn.execute("""
            SELECT COUNT(*) AS value
            FROM notifications
            WHERE user_id = %s
        """, (
            user_id,
        )).fetchone()["value"]

        active_cycle = get_active_task_cycle(
            conn,
            user_id
        )

    finally:
        conn.close()

    return render_template(
        "admin_user_details.html",
        user=user,
        transactions=transactions,
        notification_count=notification_count,
        task_cycle=active_cycle
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

    try:

        if transaction_type in [
            "Save",
            "Withdraw",
            "Task Reward"
        ]:

            transactions = conn.execute("""
                SELECT
                    transactions.*,
                    users.phone
                FROM transactions
                INNER JOIN users
                    ON transactions.user_id = users.id
                WHERE transactions.transaction_type = %s
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

    finally:
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

    try:

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
                AND transactions.status = %s
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

    finally:
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
def admin_withdrawal_details(
    transaction_id
):

    if not admin_required():
        return redirect(
            url_for("login")
        )

    conn = get_db()

    try:

        withdrawal = conn.execute("""
            SELECT
                t.id,
                t.user_id,
                t.transaction_type,
                t.amount,
                t.destination_phone,
                t.network,
                t.status,
                t.reference_id,
                t.created_at,
                u.phone,
                u.balance,
                u.status AS user_status
            FROM transactions t
            INNER JOIN users u
                ON t.user_id = u.id
            WHERE t.id = %s
            AND t.transaction_type = 'Withdraw'
        """, (
            transaction_id,
        )).fetchone()

    finally:
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

    try:

        withdrawal = conn.execute("""
            SELECT *
            FROM transactions
            WHERE id = %s
            AND transaction_type = 'Withdraw'
            FOR UPDATE
        """, (
            transaction_id,
        )).fetchone()

        if not withdrawal:

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

        if current_status in [
            "Completed",
            "Rejected"
        ]:

            flash(
                f"This withdrawal is already "
                f"{current_status}.",
                "error"
            )

            return redirect(
                url_for("admin_withdrawals")
            )

        if new_status == "Pending":

            conn.execute("""
                UPDATE transactions
                SET status = 'Pending'
                WHERE id = %s
            """, (
                transaction_id,
            ))

            conn.commit()

            flash(
                "Withdrawal marked as Pending.",
                "success"
            )

            return redirect(
                url_for("admin_withdrawals")
            )

        if new_status == "Completed":

            conn.execute("""
                UPDATE transactions
                SET status = 'Completed'
                WHERE id = %s
            """, (
                transaction_id,
            ))

            create_notification(
                conn,
                withdrawal["user_id"],
                "Withdrawal Completed",
                (
                    f"Your withdrawal request of "
                    f"{float(withdrawal['amount']):,.2f} Frw "
                    f"has been completed successfully."
                ),
                "success"
            )

            conn.commit()

            flash(
                "Withdrawal marked as Completed.",
                "success"
            )

            return redirect(
                url_for("admin_withdrawals")
            )

        if new_status == "Rejected":

            user_id = withdrawal["user_id"]
            amount = withdrawal["amount"]

            conn.execute("""
                UPDATE users
                SET balance = balance + %s
                WHERE id = %s
            """, (
                amount,
                user_id
            ))

            conn.execute("""
                UPDATE transactions
                SET status = 'Rejected'
                WHERE id = %s
            """, (
                transaction_id,
            ))

            create_notification(
                conn,
                user_id,
                "Withdrawal Rejected",
                (
                    f"Your withdrawal request of "
                    f"{float(amount):,.2f} Frw "
                    f"was rejected. The amount has been "
                    f"returned to your Rudbit balance."
                ),
                "warning"
            )

            conn.commit()

            flash(
                "Withdrawal rejected and the amount "
                "was returned to the user's balance.",
                "success"
            )

            return redirect(
                url_for("admin_withdrawals")
            )

        return redirect(
            url_for("admin_withdrawals")
        )

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


# =====================================================
# ADMIN TASKS
# =====================================================

@app.route("/admin/tasks")
def admin_tasks():

    if not admin_required():
        return redirect(
            url_for("login")
        )

    conn = get_db()

    try:

        tasks = conn.execute("""
            SELECT
                t.id,
                t.title,
                t.reward,
                t.max_users,
                t.deadline,
                t.proof_type,
                t.status,
                t.created_at,
                COUNT(ts.id) AS submission_count
            FROM tasks t
            LEFT JOIN task_submissions ts
                ON t.id = ts.task_id
            GROUP BY
                t.id,
                t.title,
                t.reward,
                t.max_users,
                t.deadline,
                t.proof_type,
                t.status,
                t.created_at
            ORDER BY t.id DESC
        """).fetchall()

        pending_task_submissions = conn.execute("""
            SELECT COUNT(*) AS value
            FROM task_submissions
            WHERE status = 'Pending'
        """).fetchone()["value"]

    finally:
        conn.close()

    return render_template(
        "admin_tasks.html",
        tasks=tasks,
        pending_task_submissions=pending_task_submissions,
        cycle_reward=TASK_CYCLE_REWARD
    )


# =====================================================
# ADMIN CREATE TASK
# =====================================================

@app.route(
    "/admin/tasks/create",
    methods=["POST"]
)
def admin_create_task():

    if not admin_required():
        return redirect(
            url_for("login")
        )

    title = request.form.get(
        "title",
        ""
    ).strip()

    description = request.form.get(
        "description",
        ""
    ).strip()

    instructions = request.form.get(
        "instructions",
        ""
    ).strip()

    reward_text = request.form.get(
        "reward",
        ""
    ).strip()

    max_users_text = request.form.get(
        "max_users",
        ""
    ).strip()

    deadline_text = request.form.get(
        "deadline",
        ""
    ).strip()

    proof_type = request.form.get(
        "proof_type",
        "text"
    ).strip()

    status = request.form.get(
        "status",
        "Draft"
    ).strip()


    # =================================================
    # VALIDATION
    # =================================================

    if not title:

        flash(
            "Task title is required.",
            "error"
        )

        return redirect(
            url_for("admin_tasks")
        )

    if not description:

        flash(
            "Task description is required.",
            "error"
        )

        return redirect(
            url_for("admin_tasks")
        )

    # -------------------------------------------------
    # The task-cycle reward is fixed at 2,500 Frw.
    #
    # We still accept the old reward field so the
    # existing Admin Task form does not break.
    # -------------------------------------------------

    if reward_text:

        try:
            float(reward_text)

        except (
            ValueError,
            TypeError
        ):
            flash(
                "Please enter a valid reward amount.",
                "error"
            )

            return redirect(
                url_for("admin_tasks")
            )

    reward = TASK_CYCLE_REWARD

    max_users = None

    if max_users_text:

        try:
            max_users = int(
                max_users_text
            )

        except (
            ValueError,
            TypeError
        ):
            flash(
                "Maximum users must be a valid number.",
                "error"
            )

            return redirect(
                url_for("admin_tasks")
            )

        if max_users < 1:

            flash(
                "Maximum users must be at least 1.",
                "error"
            )

            return redirect(
                url_for("admin_tasks")
            )

    deadline = None

    if deadline_text:

        try:
            deadline = datetime.fromisoformat(
                deadline_text
            )

        except (
            ValueError,
            TypeError
        ):
            flash(
                "Please enter a valid deadline.",
                "error"
            )

            return redirect(
                url_for("admin_tasks")
            )

    if proof_type not in [
        "text",
        "image",
        "link"
    ]:

        flash(
            "Invalid proof type.",
            "error"
        )

        return redirect(
            url_for("admin_tasks")
        )

    if status not in [
        "Draft",
        "Published"
    ]:

        flash(
            "Invalid task status.",
            "error"
        )

        return redirect(
            url_for("admin_tasks")
        )


    # =================================================
    # CREATE TASK
    # =================================================

    conn = get_db()

    try:

        conn.execute("""
            INSERT INTO tasks
            (
                title,
                description,
                instructions,
                reward,
                max_users,
                deadline,
                proof_type,
                status,
                created_by
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )
        """, (
            title,
            description,
            instructions or None,
            reward,
            max_users,
            deadline,
            proof_type,
            status,
            session["user_id"]
        ))

        conn.commit()

    except Exception:

        conn.rollback()

        flash(
            "An error occurred while creating the task.",
            "error"
        )

        return redirect(
            url_for("admin_tasks")
        )

    finally:
        conn.close()

    flash(
        (
            "Task created successfully. "
            f"Task-cycle reward is "
            f"{TASK_CYCLE_REWARD:,.0f} Frw."
        ),
        "success"
    )

    return redirect(
        url_for("admin_tasks")
    )


# =====================================================
# ADMIN TASK SUBMISSIONS
# =====================================================

@app.route("/admin/task-submissions")
def admin_task_submissions():

    if not admin_required():
        return redirect(
            url_for("login")
        )

    status_filter = request.args.get(
        "status",
        "Pending"
    ).strip()

    task_id = request.args.get(
        "task_id",
        type=int
    )

    allowed_statuses = [
        "Pending",
        "Approved",
        "Rejected"
    ]

    if status_filter not in allowed_statuses:
        status_filter = "Pending"

    conn = get_db()

    try:

        if task_id:

            submissions = conn.execute("""
                SELECT
                    ts.id,
                    ts.task_id,
                    ts.user_id,
                    ts.cycle_day_id,
                    ts.proof,
                    ts.status,
                    ts.reviewed_by,
                    ts.reviewed_at,
                    ts.rejection_reason,
                    ts.submitted_at,
                    t.title AS task_title,
                    t.reward AS task_reward,
                    t.proof_type,
                    u.phone AS user_phone
                FROM task_submissions ts
                INNER JOIN tasks t
                    ON ts.task_id = t.id
                INNER JOIN users u
                    ON ts.user_id = u.id
                WHERE ts.status = %s
                AND ts.task_id = %s
                ORDER BY ts.id DESC
            """, (
                status_filter,
                task_id
            )).fetchall()

        else:

            submissions = conn.execute("""
                SELECT
                    ts.id,
                    ts.task_id,
                    ts.user_id,
                    ts.cycle_day_id,
                    ts.proof,
                    ts.status,
                    ts.reviewed_by,
                    ts.reviewed_at,
                    ts.rejection_reason,
                    ts.submitted_at,
                    t.title AS task_title,
                    t.reward AS task_reward,
                    t.proof_type,
                    u.phone AS user_phone
                FROM task_submissions ts
                INNER JOIN tasks t
                    ON ts.task_id = t.id
                INNER JOIN users u
                    ON ts.user_id = u.id
                WHERE ts.status = %s
                ORDER BY ts.id DESC
            """, (
                status_filter,
            )).fetchall()

        pending_count = conn.execute("""
            SELECT COUNT(*) AS value
            FROM task_submissions
            WHERE status = 'Pending'
        """).fetchone()["value"]

        approved_count = conn.execute("""
            SELECT COUNT(*) AS value
            FROM task_submissions
            WHERE status = 'Approved'
        """).fetchone()["value"]

        rejected_count = conn.execute("""
            SELECT COUNT(*) AS value
            FROM task_submissions
            WHERE status = 'Rejected'
        """).fetchone()["value"]

    finally:
        conn.close()

    return render_template(
        "admin_task_submissions.html",
        submissions=submissions,
        status_filter=status_filter,
        task_id=task_id,
        pending_count=pending_count,
        approved_count=approved_count,
        rejected_count=rejected_count,
        cycle_reward=TASK_CYCLE_REWARD
    )


# =====================================================
# ADMIN TASK SUBMISSION DETAILS
# =====================================================

@app.route(
    "/admin/task-submissions/<int:submission_id>"
)
def admin_task_submission_details(
    submission_id
):

    if not admin_required():
        return redirect(
            url_for("login")
        )

    conn = get_db()

    try:

        submission = conn.execute("""
            SELECT
                ts.id,
                ts.task_id,
                ts.user_id,
                ts.cycle_day_id,
                ts.proof,
                ts.status,
                ts.reviewed_by,
                ts.reviewed_at,
                ts.rejection_reason,
                ts.submitted_at,
                t.title AS task_title,
                t.description AS task_description,
                t.instructions AS task_instructions,
                t.reward AS task_reward,
                t.max_users,
                t.deadline,
                t.proof_type,
                t.status AS task_status,
                u.phone AS user_phone,
                u.balance AS user_balance
            FROM task_submissions ts
            INNER JOIN tasks t
                ON ts.task_id = t.id
            INNER JOIN users u
                ON ts.user_id = u.id
            WHERE ts.id = %s
        """, (
            submission_id,
        )).fetchone()

    finally:
        conn.close()

    if not submission:

        flash(
            "Task submission not found.",
            "error"
        )

        return redirect(
            url_for("admin_task_submissions")
        )

    return render_template(
        "admin_task_submission_details.html",
        submission=submission,
        cycle_reward=TASK_CYCLE_REWARD
    )


# =====================================================
# ADMIN REVIEW TASK SUBMISSION
# =====================================================

@app.route(
    "/admin/task-submissions/<int:submission_id>/review",
    methods=["POST"]
)
def admin_review_task_submission(
    submission_id
):

    if not admin_required():
        return redirect(
            url_for("login")
        )

    decision = request.form.get(
        "decision",
        ""
    ).strip()

    rejection_reason = request.form.get(
        "rejection_reason",
        ""
    ).strip()

    if decision not in [
        "Approved",
        "Rejected"
    ]:

        flash(
            "Invalid submission review action.",
            "error"
        )

        return redirect(
            url_for(
                "admin_task_submission_details",
                submission_id=submission_id
            )
        )

    if (
        decision == "Rejected"
        and not rejection_reason
    ):

        flash(
            "Please provide a reason for rejecting "
            "the submission.",
            "error"
        )

        return redirect(
            url_for(
                "admin_task_submission_details",
                submission_id=submission_id
            )
        )

    conn = get_db()

    try:

        # =================================================
        # LOCK SUBMISSION
        # =================================================

        submission = conn.execute("""
            SELECT
                ts.*,
                t.title AS task_title,
                t.reward AS task_reward,
                u.phone AS user_phone,
                u.balance AS user_balance
            FROM task_submissions ts
            INNER JOIN tasks t
                ON ts.task_id = t.id
            INNER JOIN users u
                ON ts.user_id = u.id
            WHERE ts.id = %s
            FOR UPDATE OF ts
        """, (
            submission_id,
        )).fetchone()

        if not submission:

            flash(
                "Task submission not found.",
                "error"
            )

            return redirect(
                url_for("admin_task_submissions")
            )

        current_status = (
            submission["status"]
            or "Pending"
        )

        # =================================================
        # PREVENT DOUBLE REVIEW
        # =================================================

        if current_status != "Pending":

            flash(
                f"This submission has already been "
                f"{current_status.lower()}.",
                "error"
            )

            return redirect(
                url_for(
                    "admin_task_submission_details",
                    submission_id=submission_id
                )
            )


        # =================================================
        # APPROVE
        # =================================================

        if decision == "Approved":

            # -------------------------------------------------
            # Cycle task reward is always exactly 2,500 Frw.
            # Legacy submissions continue using task.reward.
            # -------------------------------------------------

            if submission["cycle_day_id"]:

                reward = TASK_CYCLE_REWARD

                cycle_day = conn.execute("""
                    SELECT *
                    FROM task_cycle_days
                    WHERE id = %s
                    FOR UPDATE
                """, (
                    submission["cycle_day_id"],
                )).fetchone()

                if not cycle_day:
                    raise RuntimeError(
                        "The task-cycle day associated "
                        "with this submission could not "
                        "be found."
                    )

                # Prevent another payment for the same
                # cycle day.

                existing_reward = conn.execute("""
                    SELECT id
                    FROM transactions
                    WHERE user_id = %s
                    AND transaction_type = 'Task Reward'
                    AND reference_id = %s
                    LIMIT 1
                """, (
                    submission["user_id"],
                    f"RUD-CYCLE-{submission['cycle_day_id']}"
                )).fetchone()

                if existing_reward:
                    raise RuntimeError(
                        "This task reward has already been paid."
                    )

            else:

                reward = float(
                    submission["task_reward"]
                    or 0
                )


            user_id = submission["user_id"]

            user = conn.execute("""
                SELECT
                    id,
                    balance
                FROM users
                WHERE id = %s
                FOR UPDATE
            """, (
                user_id,
            )).fetchone()

            if not user:
                raise RuntimeError(
                    "The user associated with this submission "
                    "could not be found."
                )


            # -------------------------------------------------
            # ADD REWARD TO BALANCE
            # -------------------------------------------------

            conn.execute("""
                UPDATE users
                SET balance = balance + %s
                WHERE id = %s
            """, (
                reward,
                user_id
            ))


            # -------------------------------------------------
            # TRANSACTION RECORD
            # -------------------------------------------------

            if submission["cycle_day_id"]:

                reference_id = (
                    f"RUD-CYCLE-"
                    f"{submission['cycle_day_id']}"
                )

            else:

                reference_id = (
                    f"RUD-TASK-"
                    f"{submission_id:06d}"
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
                VALUES (%s, %s, %s, %s, %s)
            """, (
                user_id,
                "Task Reward",
                reward,
                "Completed",
                reference_id
            ))


            # -------------------------------------------------
            # UPDATE SUBMISSION
            # -------------------------------------------------

            conn.execute("""
                UPDATE task_submissions
                SET status = 'Approved',
                    reviewed_by = %s,
                    reviewed_at = CURRENT_TIMESTAMP,
                    rejection_reason = NULL
                WHERE id = %s
                AND status = 'Pending'
            """, (
                session["user_id"],
                submission_id
            ))


            # -------------------------------------------------
            # UPDATE CYCLE DAY
            # -------------------------------------------------

            if submission["cycle_day_id"]:

                conn.execute("""
                    UPDATE task_cycle_days
                    SET status = 'Approved',
                        reward = %s
                    WHERE id = %s
                """, (
                    TASK_CYCLE_REWARD,
                    submission["cycle_day_id"]
                ))


            # -------------------------------------------------
            # USER NOTIFICATION
            # -------------------------------------------------

            create_notification(
                conn,
                user_id,
                "Task Approved",
                (
                    f'Your task '
                    f'"{submission["task_title"]}" '
                    f'was approved. '
                    f'{reward:,.0f} Frw has been added '
                    f'to your balance.'
                ),
                "success"
            )

            conn.commit()

            flash(
                (
                    "Submission approved successfully. "
                    f"{reward:,.0f} Frw has been added "
                    "to the user's balance."
                ),
                "success"
            )

            return redirect(
                url_for(
                    "admin_task_submissions"
                )
            )


        # =================================================
        # REJECT
        # =================================================

        conn.execute("""
            UPDATE task_submissions
            SET status = 'Rejected',
                reviewed_by = %s,
                reviewed_at = CURRENT_TIMESTAMP,
                rejection_reason = %s
            WHERE id = %s
            AND status = 'Pending'
        """, (
            session["user_id"],
            rejection_reason,
            submission_id
        ))


        if submission["cycle_day_id"]:

            conn.execute("""
                UPDATE task_cycle_days
                SET status = 'Rejected'
                WHERE id = %s
            """, (
                submission["cycle_day_id"],
            ))


        create_notification(
            conn,
            submission["user_id"],
            "Task Submission Rejected",
            (
                f'Your submission for '
                f'"{submission["task_title"]}" '
                f'was rejected. '
                f'Reason: {rejection_reason}'
            ),
            "error"
        )

        conn.commit()

        flash(
            "Submission rejected successfully.",
            "success"
        )

        return redirect(
            url_for(
                "admin_task_submissions"
            )
        )

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


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
