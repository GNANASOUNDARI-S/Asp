import os
import sqlite3
from datetime import datetime
from functools import wraps
from uuid import uuid4

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template_string,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


APP_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(APP_DIR, "portal.db")
UPLOAD_DIR = os.path.join(APP_DIR, "uploads")
ALLOWED_EXTENSIONS = {"pdf"}

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-secret-key"
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB

os.makedirs(UPLOAD_DIR, exist_ok=True)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('student', 'faculty'))
        );

        CREATE TABLE IF NOT EXISTS assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL,
            deadline TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            assignment_id INTEGER NOT NULL,
            file_name TEXT NOT NULL,
            submitted_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending'
                CHECK(status IN ('Pending', 'Approved', 'Rejected')),
            faculty_comment TEXT DEFAULT '',
            reviewed_at TEXT DEFAULT '',
            reviewed_by INTEGER,
            FOREIGN KEY(student_id) REFERENCES users(id),
            FOREIGN KEY(assignment_id) REFERENCES assignments(id),
            FOREIGN KEY(reviewed_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            login_time TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
    )
    db.commit()
    seed_data(db)


def seed_data(db):
    users = [
        ("Dr. Priya Faculty", "faculty@college.edu", hash_password("faculty123"), "faculty"),
        ("Arun Student", "arun@student.edu", hash_password("student123"), "student"),
        ("Meena Student", "meena@student.edu", hash_password("student123"), "student"),
        ("Rahul Student", "rahul@student.edu", hash_password("student123"), "student"),
    ]
    for user in users:
        db.execute(
            "INSERT OR IGNORE INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
            user,
        )

    assignments = [
        (
            "Data Structures - Week 1",
            "Implement stack and queue operations with test cases.",
            "2026-03-05 23:59",
        ),
        (
            "Database Systems - Mini Project",
            "Design schema and SQL queries for library management.",
            "2026-03-10 23:59",
        ),
        (
            "Operating Systems - Report",
            "Write report on process scheduling algorithms.",
            "2026-03-14 23:59",
        ),
    ]
    for item in assignments:
        db.execute(
            "INSERT OR IGNORE INTO assignments (title, description, deadline) VALUES (?, ?, ?)",
            item,
        )
    db.commit()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def hash_password(password):
    return generate_password_hash(password)


def verify_password(raw_password, stored_password):
    # Backward-compatible verification in case old plain-text rows already exist.
    if stored_password.startswith("pbkdf2:") or stored_password.startswith("scrypt:"):
        return check_password_hash(stored_password, raw_password), False
    return raw_password == stored_password, True


def parse_dt(value):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def is_pdf_content(file_storage):
    # Lightweight content validation: PDF files start with %PDF.
    head = file_storage.stream.read(4)
    file_storage.stream.seek(0)
    return head == b"%PDF"


def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                flash("Access denied for your role.", "error")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)

        return wrapper

    return decorator


BASE_STYLE = """
<style>
* { box-sizing: border-box; }
body {
    margin: 0;
    font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(120deg, #eaf7ff, #fdf7ee);
    color: #1f2937;
}
.container {
    max-width: 1100px;
    margin: 28px auto;
    padding: 0 16px;
}
.card {
    background: #fff;
    border-radius: 14px;
    box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
    padding: 18px;
    margin-bottom: 16px;
}
h1, h2, h3 { margin: 0 0 12px; }
.topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
}
.badge {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 700;
    background: #dbeafe;
    color: #1d4ed8;
}
table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 10px;
}
th, td {
    text-align: left;
    padding: 10px;
    border-bottom: 1px solid #e5e7eb;
    vertical-align: top;
}
th { background: #f9fafb; }
input, select, textarea {
    width: 100%;
    padding: 10px;
    margin-top: 6px;
    margin-bottom: 12px;
    border: 1px solid #d1d5db;
    border-radius: 8px;
}
button, .btn {
    border: none;
    border-radius: 8px;
    padding: 9px 14px;
    font-weight: 600;
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
}
.btn-primary { background: #0ea5e9; color: #fff; }
.btn-danger { background: #ef4444; color: #fff; }
.btn-success { background: #16a34a; color: #fff; }
.btn-muted { background: #475569; color: #fff; }
.status-pending { color: #b45309; font-weight: 700; }
.status-approved { color: #166534; font-weight: 700; }
.status-rejected { color: #b91c1c; font-weight: 700; }
.flash {
    padding: 10px 12px;
    border-radius: 8px;
    margin-bottom: 10px;
}
.flash-success { background: #dcfce7; color: #166534; }
.flash-error { background: #fee2e2; color: #991b1b; }
.two-col {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
}
@media (max-width: 900px) {
    .two-col { grid-template-columns: 1fr; }
}
</style>
"""


def render_page(content, **context):
    tpl = (
        """
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1" />
            <title>Assignment Submission Portal</title>
            """
        + BASE_STYLE
        + """
        </head>
        <body>
            <div class="container">
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, msg in messages %}
                            <div class="flash flash-{{ category }}">{{ msg }}</div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                """
        + content
        + """
            </div>
        </body>
        </html>
        """
    )
    return render_template_string(tpl, **context)


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not name or not email or not password:
            flash("All fields are required.", "error")
            return redirect(url_for("register"))

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, 'student')",
                (name, email, hash_password(password)),
            )
            db.commit()
            flash("Student account created. Login now.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Email already exists.", "error")
            return redirect(url_for("register"))

    content = """
    <div class="card" style="max-width: 500px; margin: 50px auto;">
        <h2>Create Student Account</h2>
        <form method="post">
            <label>Full Name</label>
            <input name="name" required />
            <label>Email</label>
            <input name="email" type="email" required />
            <label>Password</label>
            <input name="password" type="password" required />
            <button class="btn btn-primary" type="submit">Register</button>
            <a class="btn btn-muted" href="{{ url_for('login') }}">Back to Login</a>
        </form>
    </div>
    """
    return render_page(content)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "").strip()

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email = ? AND role = ?",
            (email, role),
        ).fetchone()

        if not user:
            flash("Invalid credentials or wrong role selected.", "error")
            return redirect(url_for("login"))
        valid, should_upgrade = verify_password(password, user["password"])
        if not valid:
            flash("Invalid credentials or wrong role selected.", "error")
            return redirect(url_for("login"))
        if should_upgrade:
            db.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (hash_password(password), user["id"]),
            )
            db.commit()

        session["user_id"] = user["id"]
        session["name"] = user["name"]
        session["role"] = user["role"]

        db.execute(
            "INSERT INTO login_logs (user_id, login_time) VALUES (?, ?)",
            (user["id"], now_text()),
        )
        db.commit()

        flash(f"Welcome, {user['name']}!", "success")
        return redirect(url_for("dashboard"))

    content = """
    <div class="card" style="max-width: 500px; margin: 50px auto;">
        <h2>Assignment Submission Portal</h2>
        <p>Select role and login.</p>
        <form method="post">
            <label>Email</label>
            <input name="email" type="email" required />
            <label>Password</label>
            <input name="password" type="password" required />
            <label>Role</label>
            <select name="role" required>
                <option value="student">Student</option>
                <option value="faculty">Faculty</option>
            </select>
            <button class="btn btn-primary" type="submit">Login</button>
            <a class="btn btn-muted" href="{{ url_for('register') }}">New Student Register</a>
        </form>
        <hr />
        <p><b>Demo faculty:</b> faculty@college.edu / faculty123</p>
        <p><b>Demo students:</b> arun@student.edu / student123</p>
    </div>
    """
    return render_page(content)


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required()
def dashboard():
    if session.get("role") == "faculty":
        return redirect(url_for("faculty_dashboard"))
    return redirect(url_for("student_dashboard"))


@app.route("/student", methods=["GET", "POST"])
@login_required("student")
def student_dashboard():
    db = get_db()
    student_id = session["user_id"]

    if request.method == "POST":
        assignment_id = request.form.get("assignment_id", "").strip()
        file = request.files.get("pdf_file")

        if not assignment_id:
            flash("Please select an assignment.", "error")
            return redirect(url_for("student_dashboard"))
        if not file or file.filename == "":
            flash("Please choose a PDF file.", "error")
            return redirect(url_for("student_dashboard"))
        if not allowed_file(file.filename):
            flash("Only PDF files are allowed.", "error")
            return redirect(url_for("student_dashboard"))
        if not is_pdf_content(file):
            flash("Invalid file content. Please upload a valid PDF.", "error")
            return redirect(url_for("student_dashboard"))

        assignment = db.execute(
            "SELECT * FROM assignments WHERE id = ?", (assignment_id,)
        ).fetchone()
        if not assignment:
            flash("Assignment not found.", "error")
            return redirect(url_for("student_dashboard"))

        old = db.execute(
            """
            SELECT * FROM submissions
            WHERE student_id = ? AND assignment_id = ? AND status = 'Pending'
            """,
            (student_id, assignment_id),
        ).fetchone()
        if old:
            try:
                os.remove(os.path.join(UPLOAD_DIR, old["file_name"]))
            except FileNotFoundError:
                pass
            db.execute("DELETE FROM submissions WHERE id = ?", (old["id"],))

        safe_name = secure_filename(file.filename)
        final_name = f"{student_id}_{assignment_id}_{uuid4().hex}_{safe_name}"
        save_path = os.path.join(UPLOAD_DIR, final_name)
        file.save(save_path)

        db.execute(
            """
            INSERT INTO submissions (student_id, assignment_id, file_name, submitted_at)
            VALUES (?, ?, ?, ?)
            """,
            (student_id, assignment_id, final_name, now_text()),
        )
        db.commit()
        flash("Assignment submitted successfully.", "success")
        return redirect(url_for("student_dashboard"))

    assignments = db.execute(
        "SELECT id, title, description, deadline FROM assignments ORDER BY deadline ASC"
    ).fetchall()
    submissions = db.execute(
        """
        SELECT s.id, s.file_name, s.submitted_at, s.status, s.faculty_comment, s.reviewed_at,
               a.title, a.deadline
        FROM submissions s
        JOIN assignments a ON a.id = s.assignment_id
        WHERE s.student_id = ?
        ORDER BY s.submitted_at DESC
        """,
        (student_id,),
    ).fetchall()
    submissions_view = []
    for s in submissions:
        row = dict(s)
        dead = parse_dt(row["deadline"])
        sub = parse_dt(row["submitted_at"])
        row["late"] = bool(dead and sub and sub > dead)
        submissions_view.append(row)

    content = """
    <div class="card topbar">
        <div>
            <h2>Student Dashboard</h2>
            <div class="badge">{{ session['name'] }}</div>
        </div>
        <a href="{{ url_for('logout') }}" class="btn btn-muted">Logout</a>
    </div>

    <div class="two-col">
        <div class="card">
            <h3>Submit Assignment (PDF only)</h3>
            <form method="post" enctype="multipart/form-data">
                <label>Choose Assignment</label>
                <select name="assignment_id" required>
                    <option value="">-- Select Assignment --</option>
                    {% for a in assignments %}
                    <option value="{{ a['id'] }}">{{ a['title'] }} (Deadline: {{ a['deadline'] }})</option>
                    {% endfor %}
                </select>
                <label>Upload PDF</label>
                <input name="pdf_file" type="file" accept=".pdf,application/pdf" required />
                <button class="btn btn-primary" type="submit">Submit</button>
            </form>
        </div>

        <div class="card">
            <h3>Assignment Deadlines</h3>
            <table>
                <tr><th>Title</th><th>Deadline</th></tr>
                {% for a in assignments %}
                <tr>
                    <td>{{ a['title'] }}</td>
                    <td>{{ a['deadline'] }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
    </div>

    <div class="card">
        <h3>My Submissions</h3>
        <table>
            <tr>
                <th>Assignment</th>
                <th>Deadline</th>
                <th>Submitted At</th>
                <th>On Time</th>
                <th>Status</th>
                <th>Faculty Comment</th>
                <th>File</th>
                <th>Delete</th>
            </tr>
            {% for s in submissions_view %}
            <tr>
                <td>{{ s['title'] }}</td>
                <td>{{ s['deadline'] }}</td>
                <td>{{ s['submitted_at'] }}</td>
                <td>{{ 'Late' if s['late'] else 'On Time' }}</td>
                <td class="status-{{ s['status'].lower() }}">{{ s['status'] }}</td>
                <td>{{ s['faculty_comment'] if s['faculty_comment'] else '-' }}</td>
                <td><a class="btn btn-primary" href="{{ url_for('download_file', filename=s['file_name']) }}">View PDF</a></td>
                <td>
                    {% if s['status'] == 'Pending' %}
                    <form method="post" action="{{ url_for('delete_submission', submission_id=s['id']) }}"
                          onsubmit="return confirm('Delete this submission?');">
                        <button class="btn btn-danger" type="submit">Delete</button>
                    </form>
                    {% else %}
                        -
                    {% endif %}
                </td>
            </tr>
            {% else %}
            <tr><td colspan="8">No submissions yet.</td></tr>
            {% endfor %}
        </table>
    </div>
    """
    return render_page(content, assignments=assignments, submissions_view=submissions_view)


@app.route("/delete-submission/<int:submission_id>", methods=["POST"])
@login_required("student")
def delete_submission(submission_id):
    db = get_db()
    row = db.execute(
        """
        SELECT * FROM submissions
        WHERE id = ? AND student_id = ?
        """,
        (submission_id, session["user_id"]),
    ).fetchone()
    if not row:
        flash("Submission not found.", "error")
        return redirect(url_for("student_dashboard"))
    if row["status"] != "Pending":
        flash("You can delete only pending submissions.", "error")
        return redirect(url_for("student_dashboard"))

    try:
        os.remove(os.path.join(UPLOAD_DIR, row["file_name"]))
    except FileNotFoundError:
        pass

    db.execute("DELETE FROM submissions WHERE id = ?", (submission_id,))
    db.commit()
    flash("Submission deleted.", "success")
    return redirect(url_for("student_dashboard"))


@app.route("/faculty", methods=["GET", "POST"])
@login_required("faculty")
def faculty_dashboard():
    db = get_db()

    if request.method == "POST":
        form_type = request.form.get("form_type", "").strip()
        if form_type == "review":
            submission_id = request.form.get("submission_id", "").strip()
            action = request.form.get("action", "").strip()
            comment = request.form.get("comment", "").strip()

            if action not in {"Approved", "Rejected"}:
                flash("Invalid action.", "error")
                return redirect(url_for("faculty_dashboard"))

            row = db.execute(
                "SELECT * FROM submissions WHERE id = ?", (submission_id,)
            ).fetchone()
            if not row:
                flash("Submission not found.", "error")
                return redirect(url_for("faculty_dashboard"))

            db.execute(
                """
                UPDATE submissions
                SET status = ?, faculty_comment = ?, reviewed_at = ?, reviewed_by = ?
                WHERE id = ?
                """,
                (action, comment, now_text(), session["user_id"], submission_id),
            )
            db.commit()
            flash(f"Submission {action.lower()} successfully.", "success")
            return redirect(url_for("faculty_dashboard"))

        if form_type == "assignment":
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            deadline = request.form.get("deadline", "").strip()

            if not title or not description or not deadline:
                flash("All assignment fields are required.", "error")
                return redirect(url_for("faculty_dashboard"))
            try:
                datetime.strptime(deadline, "%Y-%m-%dT%H:%M")
            except ValueError:
                flash("Deadline format is invalid.", "error")
                return redirect(url_for("faculty_dashboard"))

            normalized_deadline = datetime.strptime(deadline, "%Y-%m-%dT%H:%M").strftime(
                "%Y-%m-%d %H:%M"
            )
            try:
                db.execute(
                    "INSERT INTO assignments (title, description, deadline) VALUES (?, ?, ?)",
                    (title, description, normalized_deadline),
                )
                db.commit()
                flash("Assignment created successfully.", "success")
            except sqlite3.IntegrityError:
                flash("Assignment title already exists.", "error")
            return redirect(url_for("faculty_dashboard"))

    submissions = db.execute(
        """
        SELECT s.id, s.file_name, s.submitted_at, s.status, s.faculty_comment, s.reviewed_at,
               u.name AS student_name, u.email AS student_email,
               a.title AS assignment_title, a.deadline
        FROM submissions s
        JOIN users u ON u.id = s.student_id
        JOIN assignments a ON a.id = s.assignment_id
        ORDER BY s.submitted_at DESC
        """
    ).fetchall()
    assignments = db.execute(
        "SELECT id, title, description, deadline FROM assignments ORDER BY deadline ASC"
    ).fetchall()
    logs = db.execute(
        """
        SELECT l.login_time, u.name, u.role, u.email
        FROM login_logs l
        JOIN users u ON u.id = l.user_id
        ORDER BY l.login_time DESC
        LIMIT 50
        """
    ).fetchall()

    content = """
    <div class="card topbar">
        <div>
            <h2>Faculty Dashboard</h2>
            <div class="badge">{{ session['name'] }}</div>
        </div>
        <a href="{{ url_for('logout') }}" class="btn btn-muted">Logout</a>
    </div>

    <div class="card">
        <h3>Create New Assignment</h3>
        <form method="post">
            <input type="hidden" name="form_type" value="assignment" />
            <label>Title</label>
            <input name="title" required />
            <label>Description</label>
            <textarea name="description" required></textarea>
            <label>Deadline</label>
            <input name="deadline" type="datetime-local" required />
            <button class="btn btn-primary" type="submit">Add Assignment</button>
        </form>
    </div>

    <div class="card">
        <h3>Assignments List</h3>
        <table>
            <tr><th>Title</th><th>Description</th><th>Deadline</th></tr>
            {% for a in assignments %}
            <tr>
                <td>{{ a['title'] }}</td>
                <td>{{ a['description'] }}</td>
                <td>{{ a['deadline'] }}</td>
            </tr>
            {% else %}
            <tr><td colspan="3">No assignments available.</td></tr>
            {% endfor %}
        </table>
    </div>

    <div class="card">
        <h3>All Student Submissions</h3>
        <table>
            <tr>
                <th>Student</th>
                <th>Assignment</th>
                <th>Deadline</th>
                <th>Submitted At</th>
                <th>Status</th>
                <th>File</th>
                <th>Review</th>
            </tr>
            {% for s in submissions %}
            <tr>
                <td>{{ s['student_name'] }}<br /><small>{{ s['student_email'] }}</small></td>
                <td>{{ s['assignment_title'] }}</td>
                <td>{{ s['deadline'] }}</td>
                <td>{{ s['submitted_at'] }}</td>
                <td class="status-{{ s['status'].lower() }}">{{ s['status'] }}</td>
                <td><a class="btn btn-primary" href="{{ url_for('download_file', filename=s['file_name']) }}">View PDF</a></td>
                <td>
                    <form method="post">
                        <input type="hidden" name="form_type" value="review" />
                        <input type="hidden" name="submission_id" value="{{ s['id'] }}" />
                        <textarea name="comment" placeholder="Feedback (optional)">{{ s['faculty_comment'] }}</textarea>
                        <button class="btn btn-success" name="action" value="Approved" type="submit">Approve</button>
                        <button class="btn btn-danger" name="action" value="Rejected" type="submit">Reject</button>
                    </form>
                </td>
            </tr>
            {% else %}
            <tr><td colspan="7">No submissions yet.</td></tr>
            {% endfor %}
        </table>
    </div>

    <div class="card">
        <h3>Recent Login Activity</h3>
        <table>
            <tr><th>Name</th><th>Email</th><th>Role</th><th>Login Time</th></tr>
            {% for l in logs %}
            <tr>
                <td>{{ l['name'] }}</td>
                <td>{{ l['email'] }}</td>
                <td>{{ l['role'] }}</td>
                <td>{{ l['login_time'] }}</td>
            </tr>
            {% else %}
            <tr><td colspan="4">No login logs yet.</td></tr>
            {% endfor %}
        </table>
    </div>
    """
    return render_page(content, submissions=submissions, logs=logs, assignments=assignments)


@app.route("/uploads/<path:filename>")
@login_required()
def download_file(filename):
    db = get_db()
    submission = db.execute(
        "SELECT student_id FROM submissions WHERE file_name = ?",
        (filename,),
    ).fetchone()
    if not submission:
        flash("File not found.", "error")
        return redirect(url_for("dashboard"))
    if session.get("role") == "student" and submission["student_id"] != session.get("user_id"):
        flash("You are not allowed to access this file.", "error")
        return redirect(url_for("student_dashboard"))
    return send_from_directory(UPLOAD_DIR, filename)


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(debug=True)
