import os
import re
from pathlib import Path
from datetime import timedelta

import mysql.connector
from mysql.connector import IntegrityError
from flask import Flask, jsonify, request, session, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

from datetime import datetime
from flask import request, jsonify, session
import mysql.connector


# --------------------------------------------------
# Configuration
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"

load_dotenv(BASE_DIR / ".env")

app = Flask(
    __name__,
    static_folder=str(FRONTEND_DIR),
    static_url_path=""
)

CORS(
    app,
    origins=["http://127.0.0.1:5500"],
    supports_credentials=True
)



app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "dev-only-change-this-secret"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)


# --------------------------------------------------
# MySQL connection
# --------------------------------------------------

def get_db_connection():
    """Create a new MySQL connection for each operation."""
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "des_tech_masters"),
    )


def valid_email(email):
    return bool(
        re.fullmatch(
            r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
            r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+",
            email,
        )
    )



def current_user():
    """Return the authenticated user's current information from the database."""
    user_id = session.get("user_id")

    if not user_id:
        return None

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, full_name, email, role
            FROM users
            WHERE id = %s
            """,
            (user_id,)
        )

        user = cursor.fetchone()

        if not user:
            session.clear()
            return None

        return {
            "id": user["id"],
            "name": user["full_name"],
            "email": user["email"],
            "role": user["role"],
        }

    except mysql.connector.Error:
        app.logger.exception("Unable to retrieve the current user")
        raise

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


def error_response(message, status=400):
    return jsonify({"success": False, "message": message}), status


# --------------------------------------------------
# Frontend routes
# The HTML pages and API share the same origin.
# --------------------------------------------------

@app.get("/")
def home():
    return send_from_directory(FRONTEND_DIR, "index.html")


# --------------------------------------------------
# Register
# POST /api/auth/register
# --------------------------------------------------

@app.post("/api/auth/register")
def register():
    data = request.get_json(silent=True) or {}

    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    if not name or len(name) > 100:
        return error_response("Enter a name between 1 and 100 characters.")

    if not valid_email(email) or len(email) > 254:
        return error_response("Enter a valid email address.")

    if not isinstance(password, str) or len(password) < 8:
        return error_response("Password must be at least 8 characters long.")

    if len(password) > 128:
        return error_response("Password is too long.")

    # Never accept an admin role from public registration.
    password_hash = generate_password_hash(password)

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO users (full_name, email, password_hash, role)
            VALUES (%s, %s, %s, %s)
            """,
            (name, email, password_hash, "member"),
        )

        connection.commit()
        user_id = cursor.lastrowid

        # Sign the new user in after successful registration.
        session.clear()
        session.permanent = True
        session["user_id"] = user_id
        session["user_name"] = name
        session["user_email"] = email
        session["user_role"] = "member"

        return jsonify({
            "success": True,
            "message": "Account created successfully.",
            "user": current_user(),
        }), 201

    except IntegrityError:
        if connection:
            connection.rollback()
        return error_response("An account with this email already exists.", 409)

    except mysql.connector.Error:
        app.logger.exception("Database error during registration")
        return error_response("Unable to create the account right now.", 500)

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# --------------------------------------------------
# Login
# POST /api/auth/login
# --------------------------------------------------

@app.post("/api/auth/login")
def login():
    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    if not email or not isinstance(password, str) or not password:
        return error_response("Enter your email and password.")

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, full_name, email, password_hash, role
            FROM users
            WHERE email = %s
            LIMIT 1
            """,
            (email,),
        )

        user = cursor.fetchone()

        if not user or not check_password_hash(
            user["password_hash"], password
        ):
            return error_response("Invalid email or password.", 401)

        if user["role"] not in ("admin", "member"):
            return error_response("This account has an invalid role.", 403)

        # Regenerate authentication state after login.
        session.clear()
        session.permanent = True
        session["user_id"] = user["id"]
        session["user_name"] = user["full_name"]
        session["user_email"] = user["email"]
        session["user_role"] = user["role"]

        return jsonify({
            "success": True,
            "message": "Login successful.",
            "user": current_user(),
        })

    except mysql.connector.Error:
        app.logger.exception("Database error during login")
        return error_response("Unable to log in right now.", 500)

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# --------------------------------------------------
# Current session
# GET /api/auth/me
# --------------------------------------------------

@app.get("/api/auth/me")
def get_me():
    user = current_user()

    if not user:
        return error_response("You are not logged in.", 401)

    return jsonify({"success": True, "user": user})


# --------------------------------------------------
# Logout
# POST /api/auth/logout
# --------------------------------------------------

@app.post("/api/auth/logout")
def logout():
    session.clear()

    return jsonify({
        "success": True,
        "message": "Logged out successfully.",
    })


# --------------------------------------------------
# Example protected admin endpoint
# --------------------------------------------------

@app.get("/api/admin/check")
def admin_check():
    user = current_user()

    if not user:
        return error_response("Please log in first.", 401)

    if user["role"] != "admin":
        return error_response("Admin access required.", 403)

    return jsonify({
        "success": True,
        "message": "Admin access granted.",
    })



# --------------------------------------------------
# Hackathons API
# GET /api/hackathons
# --------------------------------------------------

@app.get("/api/hackathons")
def get_hackathons():
    # Require an authenticated session.
    user = current_user()

    if not user:
        return error_response("Please log in to view hackathons.", 401)

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Fetch records without assuming a particular column layout.
        cursor.execute("SELECT * FROM hackathons")
        rows = cursor.fetchall()

        def find_value(row, *names, default=None):
            """Find a database value using alternative column names."""
            lowered = {str(key).lower(): value for key, value in row.items()}

            for name in names:
                if name.lower() in lowered:
                    return lowered[name.lower()]

            return default

        def json_value(value):
            """Convert dates and datetimes to JSON-friendly ISO strings."""
            if value is not None and hasattr(value, "isoformat"):
                return value.isoformat()
            return value

        hackathons = []

        for row in rows:
            hackathons.append({
                "id": find_value(
                    row, "id", "hackathon_id"
                ),
                "name": find_value(
                    row, "name", "title", "hackathon_name", "event_name",
                    default="Untitled hackathon"
                ),
                "description": find_value(
                    row, "description", "details",
                    default="No description provided."
                ),
                "theme": find_value(
                    row, "theme", "category",
                    default="Open theme"
                ),
                "location": find_value(
                    row, "location", "venue",
                    default="To be announced"
                ),
                "event_type": find_value(
                    row, "event_type", "mode", "format",
                    default="online"
                ),
                "start_date": json_value(find_value(
                    row, "start_date", "startDate", "event_date",
                    "start_datetime"
                )),
                "end_date": json_value(find_value(
                    row, "end_date", "endDate", "end_datetime"
                )),
                "registration_deadline": json_value(find_value(
                    row, "registration_deadline",
                    "registrationDeadline", "deadline"
                )),
                "registration_url": find_value(
                    row, "registration_url", "registration_link",
                    "url", "website",
                    default=""
                ),
                "prize": find_value(
                    row, "prize", "prize_pool", "prize_money",
                    default=""
                ),
                "status": find_value(
                    row, "status",
                    default="upcoming"
                )
            })

        return jsonify({
            "success": True,
            "count": len(hackathons),
            "hackathons": hackathons
        })

    except mysql.connector.Error:
        app.logger.exception("Database error while fetching hackathons")
        return error_response(
            "Unable to load hackathons right now.", 500
        )

    finally:
        if cursor:
            cursor.close()

        if connection and connection.is_connected():
            connection.close()


# --------------------------------------------------
# Admin-only hackathon management
# --------------------------------------------------

ALLOWED_HACKATHON_STATUSES = {
    "upcoming",
    "open",
    "ongoing",
    "completed",
    "cancelled",
}


def validate_hackathon_payload(data):
    """Validate and normalize the hackathon form data."""
    if not isinstance(data, dict):
        return None, "A valid JSON object is required."

    title = data.get("title")
    if not isinstance(title, str) or not title.strip():
        return None, "Hackathon title is required."

    title = title.strip()
    if len(title) > 200:
        return None, "Title cannot exceed 200 characters."

    status = str(data.get("status", "upcoming")).strip().lower()
    if status not in ALLOWED_HACKATHON_STATUSES:
        return None, "Invalid hackathon status."

    def clean_text(key, max_length=None):
        value = data.get(key)
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError(f"{key} must be text.")
        value = value.strip()
        if max_length and len(value) > max_length:
            raise ValueError(
                f"{key} cannot exceed {max_length} characters."
            )
        return value or None

    def clean_datetime(key, required=False):
        value = data.get(key)

        if value is None or value == "":
            if required:
                raise ValueError(f"{key} is required.")
            return None

        if not isinstance(value, str):
            raise ValueError(f"{key} must be a valid date and time.")

        try:
            parsed = datetime.fromisoformat(value.strip())
        except ValueError:
            raise ValueError(f"{key} must be a valid date and time.")

        # MySQL DATETIME stores a local date/time without a timezone.
        if parsed.tzinfo is not None:
            raise ValueError(
                f"{key} must not include a timezone offset."
            )

        return parsed.strftime("%Y-%m-%d %H:%M:%S")

    try:
        start_date = clean_datetime("start_date", required=True)
        end_date = clean_datetime("end_date", required=True)
        deadline = clean_datetime("registration_deadline")

        start = datetime.strptime(start_date, "%Y-%m-%d %H:%M:%S")
        end = datetime.strptime(end_date, "%Y-%m-%d %H:%M:%S")

        if end <= start:
            return None, "End date must be later than start date."

        if deadline:
            deadline_dt = datetime.strptime(
                deadline, "%Y-%m-%d %H:%M:%S"
            )
            if deadline_dt > start:
                return None, (
                    "Registration deadline cannot be later than "
                    "the start date."
                )

        payload = {
            "title": title,
            "description": clean_text("description"),
            "organizer": clean_text("organizer", 200),
            "venue": clean_text("venue", 255),
            "event_url": clean_text("event_url", 1000),
            "start_date": start_date,
            "end_date": end_date,
            "registration_deadline": deadline,
            "status": status,
        }

        return payload, None

    except ValueError as exc:
        return None, str(exc)


def admin_required():
    """Return the current user only if the user is an administrator."""
    user = current_user()

    if not user:
        return None, error_response("Please log in first.", 401)

    if user.get("role") != "admin":
        return None, error_response("Admin access required.", 403)

    return user, None


# --------------------------------------------------
# Create hackathon
# POST /api/hackathons
# --------------------------------------------------

@app.post("/api/hackathons")
def create_hackathon():
    user, auth_error = admin_required()
    if auth_error:
        return auth_error

    data = request.get_json(silent=True)
    payload, validation_error = validate_hackathon_payload(data)

    if validation_error:
        return error_response(validation_error, 400)

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO hackathons (
                title, description, organizer, venue, event_url,
                start_date, end_date, registration_deadline,
                status, created_by
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                payload["title"],
                payload["description"],
                payload["organizer"],
                payload["venue"],
                payload["event_url"],
                payload["start_date"],
                payload["end_date"],
                payload["registration_deadline"],
                payload["status"],
                user["id"],
            ),
        )

        hackathon_id = cursor.lastrowid
        connection.commit()

        return jsonify({
            "success": True,
            "message": "Hackathon created successfully.",
            "id": hackathon_id,
        }), 201

    except mysql.connector.Error:
        if connection:
            connection.rollback()
        app.logger.exception("Failed to create hackathon")
        return error_response("Unable to create hackathon.", 500)

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# --------------------------------------------------
# Update hackathon
# PUT /api/hackathons/<id>
# --------------------------------------------------

@app.put("/api/hackathons/<int:hackathon_id>")
def update_hackathon(hackathon_id):
    _, auth_error = admin_required()
    if auth_error:
        return auth_error

    data = request.get_json(silent=True)
    payload, validation_error = validate_hackathon_payload(data)

    if validation_error:
        return error_response(validation_error, 400)

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT id FROM hackathons WHERE id = %s",
            (hackathon_id,),
        )

        if not cursor.fetchone():
            return error_response("Hackathon not found.", 404)

        cursor.execute(
            """
            UPDATE hackathons
            SET title = %s,
                description = %s,
                organizer = %s,
                venue = %s,
                event_url = %s,
                start_date = %s,
                end_date = %s,
                registration_deadline = %s,
                status = %s
            WHERE id = %s
            """,
            (
                payload["title"],
                payload["description"],
                payload["organizer"],
                payload["venue"],
                payload["event_url"],
                payload["start_date"],
                payload["end_date"],
                payload["registration_deadline"],
                payload["status"],
                hackathon_id,
            ),
        )

        connection.commit()

        return jsonify({
            "success": True,
            "message": "Hackathon updated successfully.",
            "id": hackathon_id,
        })

    except mysql.connector.Error:
        if connection:
            connection.rollback()
        app.logger.exception("Failed to update hackathon")
        return error_response("Unable to update hackathon.", 500)

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# --------------------------------------------------
# Delete hackathon
# DELETE /api/hackathons/<id>
# --------------------------------------------------

@app.delete("/api/hackathons/<int:hackathon_id>")
def delete_hackathon(hackathon_id):
    _, auth_error = admin_required()
    if auth_error:
        return auth_error

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT id FROM hackathons WHERE id = %s",
            (hackathon_id,),
        )

        if not cursor.fetchone():
            return error_response("Hackathon not found.", 404)

        cursor.execute(
            "DELETE FROM hackathons WHERE id = %s",
            (hackathon_id,),
        )

        connection.commit()

        return jsonify({
            "success": True,
            "message": "Hackathon deleted successfully.",
            "id": hackathon_id,
        })

    except mysql.connector.IntegrityError:
        if connection:
            connection.rollback()
        return error_response(
            "This hackathon has related records and cannot be deleted. "
            "Remove or reassign its related records first.",
            409,
        )

    except mysql.connector.Error:
        if connection:
            connection.rollback()
        app.logger.exception("Failed to delete hackathon")
        return error_response("Unable to delete hackathon.", 500)

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# --------------------------------------------------
# Team Lineup API
# --------------------------------------------------

def get_lineup_access_user():
    """Return the logged-in user, or an appropriate authentication error."""
    user = current_user()

    if not user:
        return None, error_response("Please log in first.", 401)

    return user, None


# --------------------------------------------------
# GET /api/lineups
# List lineups created by or joined by the logged-in user
# --------------------------------------------------

@app.get("/api/lineups")
def get_lineups():
    user, auth_error = get_lineup_access_user()
    if auth_error:
        return auth_error

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT DISTINCT
                tl.id,
                tl.hackathon_id,
                tl.team_name,
                tl.description,
                tl.created_by,
                h.title AS hackathon_title
            FROM team_lineups tl
            LEFT JOIN hackathons h
                ON h.id = tl.hackathon_id
            LEFT JOIN lineup_members lm
                ON lm.lineup_id = tl.id
            WHERE tl.created_by = %s
               OR lm.user_id = %s
            ORDER BY tl.id DESC
            """,
            (user["id"], user["id"]),
        )

        lineups = cursor.fetchall()

        for lineup in lineups:
            cursor.execute(
                """
                SELECT
                    u.id AS user_id,
                    u.full_name,
                    u.email
                FROM lineup_members lm
                JOIN users u ON u.id = lm.user_id
                WHERE lm.lineup_id = %s
                ORDER BY u.full_name
                """,
                (lineup["id"],),
            )

            lineup["members"] = cursor.fetchall()

        return jsonify({
            "success": True,
            "lineups": lineups,
            "count": len(lineups),
        })

    except mysql.connector.Error:
        app.logger.exception("Failed to retrieve team lineups")
        return error_response("Unable to load team lineups.", 500)

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# --------------------------------------------------
# POST /api/lineups
# Create a lineup and add registered teammates by email
# --------------------------------------------------

@app.post("/api/lineups")
def create_lineup():
    user, auth_error = get_lineup_access_user()
    if auth_error:
        return auth_error

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response("A valid JSON object is required.", 400)

    team_name = data.get("team_name")
    description = data.get("description", "")
    hackathon_id = data.get("hackathon_id")
    member_emails = data.get("member_emails", [])

    if not isinstance(team_name, str) or not team_name.strip():
        return error_response("Team name is required.", 400)

    team_name = team_name.strip()

    if len(team_name) > 100:
        return error_response(
            "Team name cannot exceed 100 characters.", 400
        )

    if description is None:
        description = ""

    if not isinstance(description, str):
        return error_response("Description must be text.", 400)

    description = description.strip()

    if len(description) > 500:
        return error_response(
            "Description cannot exceed 500 characters.", 400
        )

    try:
        hackathon_id = int(hackathon_id)
        if hackathon_id <= 0:
            raise ValueError
    except (TypeError, ValueError):
        return error_response("A valid hackathon is required.", 400)

    if not isinstance(member_emails, list):
        return error_response(
            "Teammate emails must be provided as a list.", 400
        )

    # Validate and deduplicate email addresses.
    emails = []

    for email in member_emails:
        if not isinstance(email, str):
            return error_response(
                "Each teammate email must be text.", 400
            )

        email = email.strip().lower()

        if not email:
            continue

        if (
            len(email) > 254
            or "@" not in email
            or email.startswith("@")
            or email.endswith("@")
            or any(char.isspace() for char in email)
        ):
            return error_response(
                f"Invalid email address: {email}", 400
            )

        if email not in emails:
            emails.append(email)

    if len(emails) > 20:
        return error_response(
            "A maximum of 20 teammate emails can be added at once.", 400
        )

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Verify that the hackathon exists.
        cursor.execute(
            "SELECT id FROM hackathons WHERE id = %s",
            (hackathon_id,),
        )

        if not cursor.fetchone():
            return error_response("Hackathon not found.", 404)

        # Only existing registered users can be added.
        # The creator is automatically included in the lineup.
        member_ids = {user["id"]}

        for email in emails:
            cursor.execute(
                "SELECT id FROM users WHERE LOWER(email) = %s",
                (email,),
            )

            member = cursor.fetchone()

            if not member:
                connection.rollback()
                return error_response(
                    f"No registered user found for {email}. "
                    "Ask them to register first.",
                    400,
                )

            member_ids.add(member["id"])

        # Create the lineup.
        cursor.execute(
            """
            INSERT INTO team_lineups (
                hackathon_id,
                team_name,
                description,
                created_by
            )
            VALUES (%s, %s, %s, %s)
            """,
            (
                hackathon_id,
                team_name,
                description or None,
                user["id"],
            ),
        )

        lineup_id = cursor.lastrowid

        # Add creator and teammates to the lineup.
        member_cursor = connection.cursor()

        try:
            for member_id in member_ids:
                member_cursor.execute(
                    """
                    INSERT INTO lineup_members (lineup_id, user_id)
                    VALUES (%s, %s)
                    """,
                    (lineup_id, member_id),
                )
        finally:
            member_cursor.close()

        connection.commit()

        return jsonify({
            "success": True,
            "message": "Team lineup created successfully.",
            "id": lineup_id,
        }), 201

    except mysql.connector.IntegrityError:
        if connection:
            connection.rollback()

        app.logger.exception("Lineup database constraint failed")
        return error_response(
            "Unable to create the lineup. Check the team and member records.",
            409,
        )

    except mysql.connector.Error:
        if connection:
            connection.rollback()

        app.logger.exception("Failed to create team lineup")
        return error_response("Unable to create team lineup.", 500)

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# --------------------------------------------------
# DELETE /api/lineups/<id>
# Only the lineup creator or an admin may delete it
# --------------------------------------------------

@app.delete("/api/lineups/<int:lineup_id>")
def delete_lineup(lineup_id):
    user, auth_error = get_lineup_access_user()
    if auth_error:
        return auth_error

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, created_by
            FROM team_lineups
            WHERE id = %s
            """,
            (lineup_id,),
        )

        lineup = cursor.fetchone()

        if not lineup:
            return error_response("Team lineup not found.", 404)

        if (
            lineup["created_by"] != user["id"]
            and user.get("role") != "admin"
        ):
            return error_response(
                "Only the lineup creator or an admin can delete this team.",
                403,
            )

        # Remove member associations first to satisfy foreign keys.
        cursor.execute(
            "DELETE FROM lineup_members WHERE lineup_id = %s",
            (lineup_id,),
        )

        cursor.execute(
            "DELETE FROM team_lineups WHERE id = %s",
            (lineup_id,),
        )

        connection.commit()

        return jsonify({
            "success": True,
            "message": "Team lineup deleted successfully.",
            "id": lineup_id,
        })

    except mysql.connector.IntegrityError:
        if connection:
            connection.rollback()

        return error_response(
            "This lineup has related records and cannot be deleted yet.",
            409,
        )

    except mysql.connector.Error:
        if connection:
            connection.rollback()

        app.logger.exception("Failed to delete team lineup")
        return error_response("Unable to delete team lineup.", 500)

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


@app.get("/api/hackathons/<int:hackathon_id>/lineups")
def discover_lineups(hackathon_id):
    user, auth_error = get_lineup_access_user()
    if auth_error:
        return auth_error

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT
                tl.id,
                tl.hackathon_id,
                tl.team_name,
                tl.description,
                tl.created_by,
                u.full_name AS creator_name,
                h.title AS hackathon_title,
                (
                    SELECT COUNT(*)
                    FROM lineup_members lm
                    WHERE lm.lineup_id = tl.id
                ) AS member_count
            FROM team_lineups tl
            JOIN users u ON u.id = tl.created_by
            JOIN hackathons h ON h.id = tl.hackathon_id
            WHERE tl.hackathon_id = %s
            ORDER BY tl.id DESC
            """,
            (hackathon_id,),
        )

        teams = cursor.fetchall()

        return jsonify({
            "success": True,
            "lineups": teams,
            "count": len(teams),
        })

    except mysql.connector.Error:
        app.logger.exception("Failed to discover team lineups")
        return error_response("Unable to load teams.", 500)

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()



@app.post("/api/lineups/<int:lineup_id>/join")
def join_lineup(lineup_id):
    user, auth_error = get_lineup_access_user()
    if auth_error:
        return auth_error

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            "SELECT id FROM team_lineups WHERE id = %s",
            (lineup_id,),
        )

        if not cursor.fetchone():
            return error_response("Team lineup not found.", 404)

        cursor.execute(
            """
            INSERT IGNORE INTO lineup_members (lineup_id, user_id)
            VALUES (%s, %s)
            """,
            (lineup_id, user["id"]),
        )

        connection.commit()

        return jsonify({
            "success": True,
            "message": "You have joined the team.",
            "id": lineup_id,
        })

    except mysql.connector.Error:
        if connection:
            connection.rollback()
        app.logger.exception("Failed to join team lineup")
        return error_response("Unable to join this team.", 500)

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()




@app.route("/api/lineups/<int:lineup_id>/leave", methods=["POST"])
def leave_lineup(lineup_id):
    conn = None
    cursor = None

    try:
        # user = get_lineup_access_user()
        # print("DEBUG lineup user:", repr(user))
        # print("DEBUG session:", dict(session))

        # if not user:
        #     return jsonify({
        #         "success": False,
        #         "message": "Please log in first."
        #     }), 401

        # # Support either a dictionary or a user object.
        # if isinstance(user, dict):
        #     user_id = user.get("id") or user.get("user_id")
        # else:
        #     user_id = getattr(user, "id", None)

        
        user_result = get_lineup_access_user()

        if not user_result:
            return jsonify({
                "success": False,
                "message": "Please log in first."
            }), 401

        # get_lineup_access_user() returns (user, error).
        # Extract the user dictionary from the tuple.
        if isinstance(user_result, tuple):
            user, error = user_result

            if error:
                return jsonify({
                    "success": False,
                    "message": str(error)
                }), 401
        else:
            user = user_result

        if not user:
            return jsonify({
                "success": False,
                "message": "Please log in first."
            }), 401

        user_id = user.get("id") or user.get("user_id")

        if user_id is None:
            app.logger.error("Could not determine user ID: %r", user)
            return jsonify({
                "success": False,
                "message": "Could not identify your account."
            }), 401

        #this is below
        if user_id is None:
            print("Leave lineup error: User ID missing. User:", repr(user))
            return jsonify({
                "success": False,
                "message": "Could not identify your account."
            }), 401

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            "SELECT id, created_by FROM team_lineups WHERE id = %s",
            (lineup_id,)
        )
        lineup = cursor.fetchone()

        if not lineup:
            return jsonify({
                "success": False,
                "message": "Team not found."
            }), 404

        if int(lineup["created_by"]) == int(user_id):
            return jsonify({
                "success": False,
                "message": "The team creator cannot leave their own team. Delete the team instead."
            }), 400

        cursor.execute(
            """
            DELETE FROM lineup_members
            WHERE lineup_id = %s AND user_id = %s
            """,
            (lineup_id, user_id)
        )

        if cursor.rowcount == 0:
            conn.rollback()
            return jsonify({
                "success": False,
                "message": "You are not a member of this team."
            }), 400

        conn.commit()

        return jsonify({
            "success": True,
            "message": "You have left the team."
        }), 200

    except Exception as e:
        if conn is not None:
            conn.rollback()

        # The Flask terminal will show the actual cause.
        app.logger.exception("Leave lineup failed for team %s", lineup_id)

        return jsonify({
            "success": False,
            "message": "Could not leave the team. Check the Flask terminal for details."
        }), 500

    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()


# =========================
# HACKATHON RESULTS API
# =========================

def _get_results_user():
    """Return (user, error) using the existing lineup authentication helper."""
    result = get_lineup_access_user()

    if isinstance(result, tuple):
        return result

    return result, None


@app.route("/api/results", methods=["GET"])
def get_results():
    user, error = _get_results_user()

    if error:
        return error

    if not user:
        return jsonify({
            "success": False,
            "message": "Please log in to view results."
        }), 401

    hackathon_id = request.args.get("hackathon_id", type=int)

    if not hackathon_id:
        return jsonify({
            "success": False,
            "message": "hackathon_id is required."
        }), 400

    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                hr.id,
                hr.hackathon_id,
                hr.lineup_id,
                hr.placement,
                hr.award,
                hr.notes,
                hr.created_by,
                hr.created_at,
                tl.team_name
            FROM hackathon_results hr
            JOIN team_lineups tl ON tl.id = hr.lineup_id
            WHERE hr.hackathon_id = %s
            ORDER BY
                CASE WHEN hr.placement = 0 THEN 256
                     ELSE hr.placement END ASC,
                hr.created_at ASC
        """, (hackathon_id,))

        results = cursor.fetchall()

        return jsonify({
            "success": True,
            "count": len(results),
            "results": results
        }), 200

    except Exception:
        app.logger.exception("Failed to fetch hackathon results")
        return jsonify({
            "success": False,
            "message": "Could not load results."
        }), 500

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/results", methods=["POST"])
def create_result():
    user, error = _get_results_user()

    if error:
        return error

    if not user:
        return jsonify({
            "success": False,
            "message": "Please log in."
        }), 401

    if str(user.get("role", "")).lower() != "admin":
        return jsonify({
            "success": False,
            "message": "Only administrators can manage results."
        }), 403

    data = request.get_json(silent=True) or {}

    try:
        hackathon_id = int(data.get("hackathon_id"))
        lineup_id = int(data.get("lineup_id", data.get("team_id")))
        placement = int(data.get("placement", 0))
    except (TypeError, ValueError):
        return jsonify({
            "success": False,
            "message": "Valid hackathon_id, lineup_id, and placement are required."
        }), 400

    award = (data.get("award") or "").strip() or None
    notes = (data.get("notes") or "").strip() or None

    if hackathon_id < 1 or lineup_id < 1 or not 0 <= placement <= 255:
        return jsonify({
            "success": False,
            "message": "Invalid hackathon, team, or placement."
        }), 400

    if award and len(award) > 150:
        return jsonify({
            "success": False,
            "message": "Award must be 150 characters or fewer."
        }), 400

    if notes and len(notes) > 2000:
        return jsonify({
            "success": False,
            "message": "Notes must be 2000 characters or fewer."
        }), 400

    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id
            FROM team_lineups
            WHERE id = %s AND hackathon_id = %s
        """, (lineup_id, hackathon_id))

        if not cursor.fetchone():
            return jsonify({
                "success": False,
                "message": "That team does not belong to this hackathon."
            }), 400

        cursor.execute("""
            INSERT INTO hackathon_results
                (hackathon_id, lineup_id, placement, award, notes, created_by)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            hackathon_id,
            lineup_id,
            placement,
            award,
            notes,
            user.get("id") or user.get("user_id")
        ))

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Result created successfully.",
            "id": cursor.lastrowid
        }), 201

    except Exception as exc:
        if conn:
            conn.rollback()

        app.logger.exception("Failed to create hackathon result")

        if "Duplicate entry" in str(exc):
            return jsonify({
                "success": False,
                "message": "A result already exists for this team in this hackathon."
            }), 409

        return jsonify({
            "success": False,
            "message": "Could not create result."
        }), 500

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/results/<int:result_id>", methods=["PUT"])
def update_result(result_id):
    user, error = _get_results_user()

    if error:
        return error

    if not user:
        return jsonify({
            "success": False,
            "message": "Please log in."
        }), 401

    if str(user.get("role", "")).lower() != "admin":
        return jsonify({
            "success": False,
            "message": "Only administrators can manage results."
        }), 403

    data = request.get_json(silent=True) or {}

    try:
        hackathon_id = int(data.get("hackathon_id"))
        lineup_id = int(data.get("lineup_id", data.get("team_id")))
        placement = int(data.get("placement", 0))
    except (TypeError, ValueError):
        return jsonify({
            "success": False,
            "message": "Valid hackathon_id, lineup_id, and placement are required."
        }), 400

    award = (data.get("award") or "").strip() or None
    notes = (data.get("notes") or "").strip() or None

    if hackathon_id < 1 or lineup_id < 1 or not 0 <= placement <= 255:
        return jsonify({
            "success": False,
            "message": "Invalid hackathon, team, or placement."
        }), 400

    if award and len(award) > 150:
        return jsonify({
            "success": False,
            "message": "Award must be 150 characters or fewer."
        }), 400

    if notes and len(notes) > 2000:
        return jsonify({
            "success": False,
            "message": "Notes must be 2000 characters or fewer."
        }), 400

    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id
            FROM hackathon_results
            WHERE id = %s
        """, (result_id,))

        if not cursor.fetchone():
            return jsonify({
                "success": False,
                "message": "Result not found."
            }), 404

        cursor.execute("""
            SELECT id
            FROM team_lineups
            WHERE id = %s AND hackathon_id = %s
        """, (lineup_id, hackathon_id))

        if not cursor.fetchone():
            return jsonify({
                "success": False,
                "message": "That team does not belong to this hackathon."
            }), 400

        cursor.execute("""
            UPDATE hackathon_results
            SET hackathon_id = %s,
                lineup_id = %s,
                placement = %s,
                award = %s,
                notes = %s
            WHERE id = %s
        """, (
            hackathon_id,
            lineup_id,
            placement,
            award,
            notes,
            result_id
        ))

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Result updated successfully."
        }), 200

    except Exception as exc:
        if conn:
            conn.rollback()

        app.logger.exception("Failed to update hackathon result")

        if "Duplicate entry" in str(exc):
            return jsonify({
                "success": False,
                "message": "A result already exists for this team in this hackathon."
            }), 409

        return jsonify({
            "success": False,
            "message": "Could not update result."
        }), 500

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route("/api/results/<int:result_id>", methods=["DELETE"])
def delete_result(result_id):
    user, error = _get_results_user()

    if error:
        return error

    if not user:
        return jsonify({
            "success": False,
            "message": "Please log in."
        }), 401

    if str(user.get("role", "")).lower() != "admin":
        return jsonify({
            "success": False,
            "message": "Only administrators can manage results."
        }), 403

    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            DELETE FROM hackathon_results
            WHERE id = %s
        """, (result_id,))

        if cursor.rowcount == 0:
            return jsonify({
                "success": False,
                "message": "Result not found."
            }), 404

        conn.commit()

        return jsonify({
            "success": True,
            "message": "Result deleted successfully."
        }), 200

    except Exception:
        if conn:
            conn.rollback()

        app.logger.exception("Failed to delete hackathon result")

        return jsonify({
            "success": False,
            "message": "Could not delete result."
        }), 500

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


# --------------------------------------------------
# Health check
# GET /api/health
# --------------------------------------------------

@app.get("/api/health")
def health():
    return jsonify({
        "success": True,
        "message": "DesTech Masters API is running.",
    })


# --------------------------------------------------
# Start server
# --------------------------------------------------

if __name__ == "__main__":
    if app.config["SECRET_KEY"] == "dev-only-change-this-secret":
        app.logger.warning(
            "Using the development secret key. Set SECRET_KEY in .env "
            "before using this application beyond local development."
        )

    app.run(
        host="127.0.0.1",
        port=int(os.getenv("PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "0") == "1",
    )