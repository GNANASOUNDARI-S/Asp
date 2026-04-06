
import os
import sqlite3
from datetime import datetime
from functools import wraps
from uuid import uuid4

from flask import Flask, flash, g, redirect, render_template_string, request, send_from_directory, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

APP_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(APP_DIR, "portal.db"))
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", os.path.join(APP_DIR, "uploads"))
ALLOWED_EXTENSIONS = {"pdf"}

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-secret-key"
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Optional MongoDB connection (use MONGO_URI env var)
MONGO_URI = os.environ.get("MONGO_URI")
mdb = None
if MONGO_URI:
    try:
        from mongo import get_mongo_db, init_mongo, seed_mongo

        mdb = get_mongo_db(MONGO_URI)
        init_mongo(mdb)
        seed_mongo(mdb)
        print("MongoDB connected.")
    except Exception as e:
        mdb = None
        print("MongoDB init failed:", e)


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


def col_exists(db, table, col):
    return any(r["name"] == col for r in db.execute(f"PRAGMA table_info({table})").fetchall())


def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def hash_pw(p):
    return generate_password_hash(p)


def verify_pw(raw, stored):
    if stored.startswith("pbkdf2:") or stored.startswith("scrypt:"):
        return check_password_hash(stored, raw), False
    return raw == stored, True


def allowed_file(name):
    return "." in name and name.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def is_pdf_content(f):
    head = f.stream.read(4)
    f.stream.seek(0)
    return head == b"%PDF"


def parse_dt(value):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass
    return None


def login_required(role=None):
    def deco(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                flash("Access denied.", "error")
                return redirect(url_for("dashboard"))
            return func(*args, **kwargs)
        return wrapper
    return deco


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS departments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('student','faculty')),
            department_id INTEGER,
            FOREIGN KEY(department_id) REFERENCES departments(id)
        );
        CREATE TABLE IF NOT EXISTS assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL,
            deadline TEXT NOT NULL,
            department_id INTEGER,
            FOREIGN KEY(department_id) REFERENCES departments(id)
        );
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            assignment_id INTEGER NOT NULL,
            file_name TEXT NOT NULL,
            submitted_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending','Approved','Rejected')),
            faculty_comment TEXT DEFAULT '',
            reviewed_at TEXT DEFAULT '',
            reviewed_by INTEGER,
            FOREIGN KEY(student_id) REFERENCES users(id),
            FOREIGN KEY(assignment_id) REFERENCES assignments(id),
            FOREIGN KEY(reviewed_by) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS quizzes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            deadline TEXT NOT NULL,
            department_id INTEGER,
            created_by INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(department_id) REFERENCES departments(id),
            FOREIGN KEY(created_by) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS quiz_questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            quiz_id INTEGER NOT NULL,
            question_text TEXT NOT NULL,
            option_a TEXT NOT NULL,
            option_b TEXT NOT NULL,
            option_c TEXT NOT NULL,
            option_d TEXT NOT NULL,
            correct_option TEXT NOT NULL CHECK(correct_option IN ('A','B','C','D')),
            FOREIGN KEY(quiz_id) REFERENCES quizzes(id)
        );
        CREATE TABLE IF NOT EXISTS quiz_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            quiz_id INTEGER NOT NULL,
            student_id INTEGER NOT NULL,
            score INTEGER NOT NULL,
            total INTEGER NOT NULL,
            submitted_at TEXT NOT NULL,
            UNIQUE(quiz_id, student_id),
            FOREIGN KEY(quiz_id) REFERENCES quizzes(id),
            FOREIGN KEY(student_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            department_id INTEGER,
            created_by INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(department_id) REFERENCES departments(id),
            FOREIGN KEY(created_by) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            login_time TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
    )
    if not col_exists(db, "users", "department_id"):
        db.execute("ALTER TABLE users ADD COLUMN department_id INTEGER")
    if not col_exists(db, "assignments", "department_id"):
        db.execute("ALTER TABLE assignments ADD COLUMN department_id INTEGER")
    db.commit()
    seed_data(db)


def seed_data(db):
    for n in ["Computer Science", "Electronics", "Mechanical", "Civil"]:
        db.execute("INSERT OR IGNORE INTO departments(name) VALUES(?)", (n,))
    cse = db.execute("SELECT id FROM departments WHERE name='Computer Science'").fetchone()
    cse_id = cse["id"] if cse else None
    users = [
        ("Dr. Priya Faculty", "faculty@college.edu", hash_pw("faculty123"), "faculty", cse_id),
        ("Arun Student", "arun@student.edu", hash_pw("student123"), "student", cse_id),
        ("Meena Student", "meena@student.edu", hash_pw("student123"), "student", cse_id),
    ]
    for u in users:
        db.execute("INSERT OR IGNORE INTO users(name,email,password,role,department_id) VALUES(?,?,?,?,?)", u)
    db.execute(
        "INSERT OR IGNORE INTO assignments(title,description,deadline,department_id) VALUES(?,?,?,?)",
        ("Data Structures - Week 1", "Implement stack and queue operations.", "2026-03-20 23:59", cse_id),
    )
    fac = db.execute("SELECT id FROM users WHERE email='faculty@college.edu'").fetchone()
    if fac:
        exists = db.execute(
            """
            SELECT 1 FROM announcements
            WHERE title=? AND message=? AND department_id IS ?
            LIMIT 1
            """,
            ("Portal Update", "Assignments, quizzes and announcements are enabled.", cse_id),
        ).fetchone()
        if not exists:
            db.execute(
                "INSERT INTO announcements(title,message,department_id,created_by,created_at) VALUES(?,?,?,?,?)",
                ("Portal Update", "Assignments, quizzes and announcements are enabled.", cse_id, fac["id"], now_text()),
            )
        # Remove accidental duplicates, keep the most recent per (title,message,department)
        db.execute(
            """
            DELETE FROM announcements
            WHERE rowid NOT IN (
                SELECT MAX(rowid) FROM announcements
                GROUP BY title, message, department_id
            )
            """
        )
    db.commit()


BASE_STYLE = """
<style>
:root{
  --bg-1:#f7f2e9;--bg-2:#e8f4f1;--ink:#101826;--muted:#536171;
  --card:#ffffff;--edge:#e6e2da;--accent:#0f766e;--accent-2:#f97316;
  --good:#15803d;--warn:#b45309;--bad:#b91c1c;
}
*{box-sizing:border-box}
body{
  margin:0;color:var(--ink);
  font-family:"Georgia","Times New Roman",serif;
  background:#ffffff;
}
.container{max-width:1200px;margin:28px auto;padding:0 16px}
.card{
  background:var(--card);
  border:1px solid var(--edge);
  border-radius:14px;
  padding:18px;
  margin-bottom:16px;
  box-shadow:0 14px 30px rgba(16,24,38,.08);
}
.topbar{display:flex;justify-content:space-between;align-items:center;gap:12px}
.badge{
  background:#ecfdf3;color:#116a4b;
  padding:6px 12px;border-radius:999px;
  font-size:12px;font-weight:700;letter-spacing:.3px;
}
h2,h3{font-family:"Trebuchet MS","Verdana",sans-serif;margin:0 0 10px}
p{color:var(--muted)}
input,select,textarea{
  width:100%;padding:10px 12px;border:1px solid var(--edge);
  border-radius:10px;margin:6px 0 12px;font-family:"Trebuchet MS","Verdana",sans-serif;
}
textarea{min-height:90px}
button,.btn{
  border:none;border-radius:10px;padding:9px 14px;font-weight:700;
  cursor:pointer;text-decoration:none;display:inline-block;
  font-family:"Trebuchet MS","Verdana",sans-serif;
}
.btn-primary{background:var(--accent);color:#fff}
.btn-success{background:var(--good);color:#fff}
.btn-danger{background:var(--bad);color:#fff}
.btn-muted{background:#2f3a4a;color:#fff}
.flash{padding:10px;border-radius:10px;margin-bottom:10px}
.flash-success{background:#dcfce7;color:#166534}
.flash-error{background:#fee2e2;color:#991b1b}
table{width:100%;border-collapse:separate;border-spacing:0 6px}
th{background:#f8fafc;border:1px solid var(--edge);padding:10px}
td{
  background:#fff;border:1px solid var(--edge);padding:10px;
}
.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.three{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}
@media(max-width:900px){.two,.three{grid-template-columns:1fr}}
.status-pending{color:var(--warn);font-weight:800}
.status-approved{color:var(--good);font-weight:800}
.status-rejected{color:var(--bad);font-weight:800}
</style>
"""


def render_page(content, **ctx):
    return render_template_string(
        """<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>"""
        + BASE_STYLE
        + """</head><body><div class='container'>
        {% with messages=get_flashed_messages(with_categories=true) %}{% if messages %}{% for c,m in messages %}<div class='flash flash-{{c}}'>{{m}}</div>{% endfor %}{% endif %}{% endwith %}
        """
        + content
        + """</div></body></html>""",
        **ctx,
    )

@app.route("/")
def home():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    db = get_db()
    depts = db.execute("SELECT id,name FROM departments ORDER BY name").fetchall()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        dept_id = request.form.get("department_id", "").strip() or None
        if not name or not email or not password:
            flash("All fields required.", "error")
            return redirect(url_for("register"))
        try:
            db.execute(
                "INSERT INTO users(name,email,password,role,department_id) VALUES(?,?,?,'student',?)",
                (name, email, hash_pw(password), dept_id),
            )
            db.commit()
            # If MongoDB available, upsert the user into Atlas as well
            if mdb is not None:
                try:
                    mdb.users.update_one(
                        {"email": email},
                        {
                            "$set": {
                                "name": name,
                                "email": email,
                                "password": hash_pw(password),
                                "role": "student",
                                "department_id": int(dept_id) if dept_id else None,
                                "created_at": now_text(),
                            }
                        },
                        upsert=True,
                    )
                except Exception:
                    # don't block registration on MongoDB errors
                    pass
            flash("Account created.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Email already exists.", "error")
    return render_page(
        """
        <div class='card' style='max-width:560px;margin:40px auto'>
          <h2>Student Register</h2><form method='post'>
          <label>Name</label><input name='name' required>
          <label>Email</label><input name='email' type='email' required>
          <label>Password</label><input name='password' type='password' required>
          <label>Department</label><select name='department_id'><option value=''>Optional</option>{% for d in depts %}<option value='{{d["id"]}}'>{{d["name"]}}</option>{% endfor %}</select>
          <button class='btn btn-primary'>Register</button> <a class='btn btn-muted' href='{{url_for("login")}}'>Back</a>
          </form></div>
        """,
        depts=depts,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "").strip()
        db = get_db()
        user = db.execute(
            """
            SELECT u.*, d.name AS dept_name FROM users u
            LEFT JOIN departments d ON d.id=u.department_id
            WHERE u.email=? AND u.role=?
            """,
            (email, role),
        ).fetchone()
        if not user:
            flash("Invalid credentials.", "error")
            return redirect(url_for("login"))
        valid, upgrade = verify_pw(password, user["password"])
        if not valid:
            flash("Invalid credentials.", "error")
            return redirect(url_for("login"))
        if upgrade:
            db.execute("UPDATE users SET password=? WHERE id=?", (hash_pw(password), user["id"]))
            db.commit()
        session["user_id"] = user["id"]
        session["name"] = user["name"]
        session["role"] = user["role"]
        session["department_id"] = user["department_id"]
        session["department_name"] = user["dept_name"] or "Not Assigned"
        db.execute("INSERT INTO login_logs(user_id,login_time) VALUES(?,?)", (user["id"], now_text()))
        db.commit()
        return redirect(url_for("dashboard"))
    return render_page(
        """
        <div class='card' style='max-width:520px;margin:40px auto'>
          <h2>College Portal</h2><p>Assignments + Quiz + Department + Announcements</p>
          <form method='post'>
            <label>Email</label><input name='email' type='email' required>
            <label>Password</label><input name='password' type='password' required>
            <label>Role</label><select name='role'><option value='student'>Student</option><option value='faculty'>Faculty</option></select>
            <button class='btn btn-primary'>Login</button> <a class='btn btn-muted' href='{{url_for("register")}}'>Student Register</a>
          </form>
          <hr><p><b>Faculty:</b> faculty@college.edu / faculty123</p><p><b>Student:</b> arun@student.edu / student123</p>
        </div>
        """
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required()
def dashboard():
    return redirect(url_for("faculty_dashboard" if session.get("role") == "faculty" else "student_dashboard"))


@app.route("/student", methods=["GET", "POST"])
@login_required("student")
def student_dashboard():
    db = get_db()
    sid = session["user_id"]
    did = session.get("department_id")

    if request.method == "POST":
        aid = request.form.get("assignment_id", "").strip()
        file = request.files.get("pdf_file")
        if not aid or not file or file.filename == "":
            flash("Select assignment and PDF.", "error")
            return redirect(url_for("student_dashboard"))
        if not allowed_file(file.filename) or not is_pdf_content(file):
            flash("Only valid PDF files allowed.", "error")
            return redirect(url_for("student_dashboard"))
        if did:
            ok = db.execute(
                "SELECT id FROM assignments WHERE id=? AND (department_id IS NULL OR department_id=?)",
                (aid, did),
            ).fetchone()
        else:
            ok = db.execute("SELECT id FROM assignments WHERE id=?", (aid,)).fetchone()
        if not ok:
            flash("Assignment not for your department.", "error")
            return redirect(url_for("student_dashboard"))

        old = db.execute(
            "SELECT * FROM submissions WHERE student_id=? AND assignment_id=? AND status='Pending'",
            (sid, aid),
        ).fetchone()
        if old:
            try:
                os.remove(os.path.join(UPLOAD_DIR, old["file_name"]))
            except FileNotFoundError:
                pass
            db.execute("DELETE FROM submissions WHERE id=?", (old["id"],))

        fname = f"{sid}_{aid}_{uuid4().hex}_{secure_filename(file.filename)}"
        file.save(os.path.join(UPLOAD_DIR, fname))
        db.execute(
            "INSERT INTO submissions(student_id,assignment_id,file_name,submitted_at) VALUES(?,?,?,?)",
            (sid, aid, fname, now_text()),
        )
        db.commit()
        flash("Assignment submitted.", "success")
        return redirect(url_for("student_dashboard"))

    if did:
        assignments = db.execute(
            """
            SELECT a.id,a.title,a.description,a.deadline,d.name AS dept FROM assignments a
            LEFT JOIN departments d ON d.id=a.department_id
            WHERE a.department_id IS NULL OR a.department_id=?
            ORDER BY a.deadline
            """,
            (did,),
        ).fetchall()
    else:
        assignments = db.execute(
            """
            SELECT a.id,a.title,a.description,a.deadline,d.name AS dept FROM assignments a
            LEFT JOIN departments d ON d.id=a.department_id
            ORDER BY a.deadline
            """
        ).fetchall()
    subs = db.execute(
        """
        SELECT s.id,s.file_name,s.submitted_at,s.status,s.faculty_comment,a.title,a.deadline
        FROM submissions s JOIN assignments a ON a.id=s.assignment_id
        WHERE s.student_id=? ORDER BY s.submitted_at DESC
        """,
        (sid,),
    ).fetchall()
    sub_view = []
    for s in subs:
        r = dict(s)
        r["late"] = bool(parse_dt(r["deadline"]) and parse_dt(r["submitted_at"]) and parse_dt(r["submitted_at"]) > parse_dt(r["deadline"]))
        sub_view.append(r)
    if did:
        quizzes = db.execute(
            """
            SELECT q.id,q.title,q.deadline,d.name AS dept,qa.score,qa.total,qa.submitted_at AS attempted_at
            FROM quizzes q
            LEFT JOIN departments d ON d.id=q.department_id
            LEFT JOIN quiz_attempts qa ON qa.quiz_id=q.id AND qa.student_id=?
            WHERE q.department_id IS NULL OR q.department_id=?
            ORDER BY q.deadline
            """,
            (sid, did),
        ).fetchall()
        anns = db.execute(
            """
            SELECT a.title,a.message,a.created_at,d.name AS dept FROM announcements a
            LEFT JOIN departments d ON d.id=a.department_id
            WHERE a.department_id IS NULL OR a.department_id=?
            ORDER BY a.created_at DESC LIMIT 10
            """,
            (did,),
        ).fetchall()
    else:
        quizzes = db.execute(
            """
            SELECT q.id,q.title,q.deadline,d.name AS dept,qa.score,qa.total,qa.submitted_at AS attempted_at
            FROM quizzes q
            LEFT JOIN departments d ON d.id=q.department_id
            LEFT JOIN quiz_attempts qa ON qa.quiz_id=q.id AND qa.student_id=?
            ORDER BY q.deadline
            """,
            (sid,),
        ).fetchall()
        anns = db.execute(
            """
            SELECT a.title,a.message,a.created_at,d.name AS dept FROM announcements a
            LEFT JOIN departments d ON d.id=a.department_id
            ORDER BY a.created_at DESC LIMIT 10
            """
        ).fetchall()

    return render_page(
        """
        <div class='card topbar'><div><h2>Student Dashboard</h2><div class='badge'>{{session['name']}} | {{session['department_name']}}</div></div><a class='btn btn-muted' href='{{url_for("logout")}}'>Logout</a></div>

        <div class='card'><h3>Announcements</h3>
        <table><tr><th>Title</th><th>Message</th><th>Department</th><th>Time</th></tr>
        {% for a in anns %}<tr><td>{{a['title']}}</td><td>{{a['message']}}</td><td>{{a['dept'] if a['dept'] else 'All'}}</td><td>{{a['created_at']}}</td></tr>{% else %}<tr><td colspan='4'>No announcements.</td></tr>{% endfor %}</table></div>

        <div class='two'>
          <div class='card'><h3>Submit Assignment (PDF)</h3><form method='post' enctype='multipart/form-data'>
            <label>Assignment</label><select name='assignment_id' required><option value=''>Select</option>{% for a in assignments %}<option value='{{a['id']}}'>{{a['title']}} ({{a['deadline']}})</option>{% endfor %}</select>
            <table><tr><th>Title</th><th>Description</th><th>Department</th><th>Deadline</th></tr>
            {% for a in assignments %}<tr><td>{{a['title']}}</td><td>{{a['description']}}</td><td>{{a['dept'] if a['dept'] else 'All'}}</td><td>{{a['deadline']}}</td></tr>{% else %}<tr><td colspan='4'>No assignments.</td></tr>{% endfor %}</table>
            <label>PDF File</label><input name='pdf_file' type='file' accept='.pdf,application/pdf' required>
            <button class='btn btn-primary'>Submit</button>
          </form></div>
          <div class='card'><h3>Quiz Section</h3>
            <table><tr><th>Quiz</th><th>Deadline</th><th>Result</th><th>Action</th></tr>
            {% for q in quizzes %}<tr>
              <td>{{q['title']}}</td><td>{{q['deadline']}}</td>
              <td>{% if q['score'] is not none %}{{q['score']}}/{{q['total']}}{% else %}Not Attempted{% endif %}</td>
              <td>{% if q['score'] is none %}<a class='btn btn-primary' href='{{url_for("attempt_quiz", quiz_id=q['id'])}}'>Attempt</a>{% else %}-{% endif %}</td>
            </tr>{% else %}<tr><td colspan='4'>No quizzes.</td></tr>{% endfor %}</table>
          </div>
        </div>

        <div class='card'><h3>My Submissions</h3>
        <table><tr><th>Assignment</th><th>Deadline</th><th>Submitted</th><th>On Time</th><th>Status</th><th>Comment</th><th>File</th><th>Delete</th></tr>
        {% for s in sub_view %}<tr>
          <td>{{s['title']}}</td><td>{{s['deadline']}}</td><td>{{s['submitted_at']}}</td><td>{{'Late' if s['late'] else 'On Time'}}</td>
          <td class='status-{{s['status'].lower()}}'>{{s['status']}}</td><td>{{s['faculty_comment'] if s['faculty_comment'] else '-'}}</td>
          <td><a class='btn btn-primary' href='{{url_for("download_file", filename=s['file_name'])}}'>View PDF</a></td>
          <td>{% if s['status']=='Pending' %}<form method='post' action='{{url_for("delete_submission", submission_id=s['id'])}}'><button class='btn btn-danger'>Delete</button></form>{% else %}-{% endif %}</td>
        </tr>{% else %}<tr><td colspan='8'>No submissions yet.</td></tr>{% endfor %}</table></div>
        """,
        assignments=assignments,
        sub_view=sub_view,
        quizzes=quizzes,
        anns=anns,
    )


@app.route("/student/quiz/<int:quiz_id>", methods=["GET", "POST"])
@login_required("student")
def attempt_quiz(quiz_id):
    db = get_db()
    sid = session["user_id"]
    did = session.get("department_id")
    if did:
        quiz = db.execute(
            "SELECT * FROM quizzes WHERE id=? AND (department_id IS NULL OR department_id=?)",
            (quiz_id, did),
        ).fetchone()
    else:
        quiz = db.execute("SELECT * FROM quizzes WHERE id=?", (quiz_id,)).fetchone()
    if not quiz:
        flash("Quiz not found.", "error")
        return redirect(url_for("student_dashboard"))
    if db.execute("SELECT id FROM quiz_attempts WHERE quiz_id=? AND student_id=?", (quiz_id, sid)).fetchone():
        flash("Quiz already attempted.", "error")
        return redirect(url_for("student_dashboard"))
    questions = db.execute("SELECT * FROM quiz_questions WHERE quiz_id=? ORDER BY id", (quiz_id,)).fetchall()
    if not questions:
        flash("No questions available.", "error")
        return redirect(url_for("student_dashboard"))
    if request.method == "POST":
        score = 0
        for q in questions:
            if request.form.get(f"q_{q['id']}", "").upper() == q["correct_option"]:
                score += 1
        db.execute(
            "INSERT INTO quiz_attempts(quiz_id,student_id,score,total,submitted_at) VALUES(?,?,?,?,?)",
            (quiz_id, sid, score, len(questions), now_text()),
        )
        db.commit()
        flash(f"Quiz submitted. Score: {score}/{len(questions)}", "success")
        return redirect(url_for("student_dashboard"))
    return render_page(
        """
        <div class='card topbar'><div><h2>{{quiz['title']}}</h2><div class='badge'>Deadline: {{quiz['deadline']}}</div></div><a class='btn btn-muted' href='{{url_for("student_dashboard")}}'>Back</a></div>
        <div class='card'><form method='post'>
        {% for q in questions %}<div style='margin-bottom:12px'><b>Q{{loop.index}}. {{q['question_text']}}</b><br>
          <label><input type='radio' name='q_{{q['id']}}' value='A' required> A. {{q['option_a']}}</label><br>
          <label><input type='radio' name='q_{{q['id']}}' value='B'> B. {{q['option_b']}}</label><br>
          <label><input type='radio' name='q_{{q['id']}}' value='C'> C. {{q['option_c']}}</label><br>
          <label><input type='radio' name='q_{{q['id']}}' value='D'> D. {{q['option_d']}}</label></div>{% endfor %}
        <button class='btn btn-primary'>Submit Quiz</button></form></div>
        """,
        quiz=quiz,
        questions=questions,
    )


@app.route("/delete-submission/<int:submission_id>", methods=["POST"])
@login_required("student")
def delete_submission(submission_id):
    db = get_db()
    row = db.execute("SELECT * FROM submissions WHERE id=? AND student_id=?", (submission_id, session["user_id"])).fetchone()
    if not row:
        flash("Submission not found.", "error")
        return redirect(url_for("student_dashboard"))
    if row["status"] != "Pending":
        flash("Only pending submission can be deleted.", "error")
        return redirect(url_for("student_dashboard"))
    try:
        os.remove(os.path.join(UPLOAD_DIR, row["file_name"]))
    except FileNotFoundError:
        pass
    db.execute("DELETE FROM submissions WHERE id=?", (submission_id,))
    db.commit()
    flash("Submission deleted.", "success")
    return redirect(url_for("student_dashboard"))

@app.route("/faculty", methods=["GET", "POST"])
@login_required("faculty")
def faculty_dashboard():
    db = get_db()
    fid = session["user_id"]

    if request.method == "POST":
        t = request.form.get("form_type", "").strip()

        if t == "department":
            name = request.form.get("dept_name", "").strip()
            if not name:
                flash("Department name required.", "error")
                return redirect(url_for("faculty_dashboard"))
            try:
                db.execute("INSERT INTO departments(name) VALUES(?)", (name,))
                db.commit()
                flash("Department added.", "success")
            except sqlite3.IntegrityError:
                flash("Department already exists.", "error")
            return redirect(url_for("faculty_dashboard"))

        if t == "assignment":
            title = request.form.get("title", "").strip()
            desc = request.form.get("description", "").strip()
            deadline = request.form.get("deadline", "").strip()
            dept = request.form.get("department_id", "").strip() or None
            if not title or not desc or not deadline:
                flash("Assignment fields required.", "error")
                return redirect(url_for("faculty_dashboard"))
            try:
                dt = datetime.strptime(deadline, "%Y-%m-%dT%H:%M").strftime("%Y-%m-%d %H:%M")
                db.execute(
                    "INSERT INTO assignments(title,description,deadline,department_id) VALUES(?,?,?,?)",
                    (title, desc, dt, dept),
                )
                db.commit()
                flash("Assignment created.", "success")
            except ValueError:
                flash("Invalid deadline.", "error")
            except sqlite3.IntegrityError:
                flash("Assignment title exists.", "error")
            return redirect(url_for("faculty_dashboard"))

        if t == "announcement":
            title = request.form.get("ann_title", "").strip()
            msg = request.form.get("ann_message", "").strip()
            dept = request.form.get("ann_department_id", "").strip() or None
            if not title or not msg:
                flash("Announcement title/message required.", "error")
                return redirect(url_for("faculty_dashboard"))
            db.execute(
                "INSERT INTO announcements(title,message,department_id,created_by,created_at) VALUES(?,?,?,?,?)",
                (title, msg, dept, fid, now_text()),
            )
            db.commit()
            flash("Announcement published.", "success")
            return redirect(url_for("faculty_dashboard"))

        if t == "quiz":
            qt = request.form.get("quiz_title", "").strip()
            qd = request.form.get("quiz_description", "").strip()
            ddl = request.form.get("quiz_deadline", "").strip()
            dept = request.form.get("quiz_department_id", "").strip() or None
            qq = request.form.get("question_text", "").strip()
            oa = request.form.get("option_a", "").strip()
            ob = request.form.get("option_b", "").strip()
            oc = request.form.get("option_c", "").strip()
            od = request.form.get("option_d", "").strip()
            co = request.form.get("correct_option", "").strip().upper()
            if not all([qt, qd, ddl, qq, oa, ob, oc, od, co]):
                flash("All quiz fields are required.", "error")
                return redirect(url_for("faculty_dashboard"))
            if co not in {"A", "B", "C", "D"}:
                flash("Correct option must be A/B/C/D.", "error")
                return redirect(url_for("faculty_dashboard"))
            try:
                dt = datetime.strptime(ddl, "%Y-%m-%dT%H:%M").strftime("%Y-%m-%d %H:%M")
            except ValueError:
                flash("Invalid quiz deadline.", "error")
                return redirect(url_for("faculty_dashboard"))
            db.execute(
                "INSERT INTO quizzes(title,description,deadline,department_id,created_by,created_at) VALUES(?,?,?,?,?,?)",
                (qt, qd, dt, dept, fid, now_text()),
            )
            qid = db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            db.execute(
                "INSERT INTO quiz_questions(quiz_id,question_text,option_a,option_b,option_c,option_d,correct_option) VALUES(?,?,?,?,?,?,?)",
                (qid, qq, oa, ob, oc, od, co),
            )
            db.commit()
            flash("Quiz created.", "success")
            return redirect(url_for("faculty_dashboard"))

        if t == "add_question":
            qid = request.form.get("quiz_id", "").strip()
            qq = request.form.get("question_text", "").strip()
            oa = request.form.get("option_a", "").strip()
            ob = request.form.get("option_b", "").strip()
            oc = request.form.get("option_c", "").strip()
            od = request.form.get("option_d", "").strip()
            co = request.form.get("correct_option", "").strip().upper()
            if not all([qid, qq, oa, ob, oc, od, co]) or co not in {"A", "B", "C", "D"}:
                flash("Valid question data required.", "error")
                return redirect(url_for("faculty_dashboard"))
            db.execute(
                "INSERT INTO quiz_questions(quiz_id,question_text,option_a,option_b,option_c,option_d,correct_option) VALUES(?,?,?,?,?,?,?)",
                (qid, qq, oa, ob, oc, od, co),
            )
            db.commit()
            flash("Question added.", "success")
            return redirect(url_for("faculty_dashboard"))

        if t == "review":
            sid = request.form.get("submission_id", "").strip()
            action = request.form.get("action", "").strip()
            cmt = request.form.get("comment", "").strip()
            if action not in {"Approved", "Rejected"}:
                flash("Invalid review action.", "error")
                return redirect(url_for("faculty_dashboard"))
            db.execute(
                "UPDATE submissions SET status=?, faculty_comment=?, reviewed_at=?, reviewed_by=? WHERE id=?",
                (action, cmt, now_text(), fid, sid),
            )
            db.commit()
            flash("Submission reviewed.", "success")
            return redirect(url_for("faculty_dashboard"))

    depts = db.execute("SELECT id,name FROM departments ORDER BY name").fetchall()
    assignments = db.execute(
        "SELECT a.title,a.description,a.deadline,d.name AS dept FROM assignments a LEFT JOIN departments d ON d.id=a.department_id ORDER BY a.deadline"
    ).fetchall()
    quizzes = db.execute(
        """
        SELECT q.id,q.title,q.deadline,d.name AS dept,
        (SELECT COUNT(*) FROM quiz_questions qq WHERE qq.quiz_id=q.id) AS qcount,
        (SELECT COUNT(*) FROM quiz_attempts qa WHERE qa.quiz_id=q.id) AS attempts
        FROM quizzes q LEFT JOIN departments d ON d.id=q.department_id ORDER BY q.created_at DESC
        """
    ).fetchall()
    subs = db.execute(
        """
        SELECT s.id,s.file_name,s.submitted_at,s.status,s.faculty_comment,u.name AS student,u.email,
               d.name AS dept,a.title AS assignment,a.deadline
        FROM submissions s
        JOIN users u ON u.id=s.student_id
        LEFT JOIN departments d ON d.id=u.department_id
        JOIN assignments a ON a.id=s.assignment_id
        ORDER BY s.submitted_at DESC
        """
    ).fetchall()
    logs = db.execute(
        """
        SELECT l.login_time,u.name,u.email,u.role,d.name AS dept
        FROM login_logs l JOIN users u ON u.id=l.user_id
        LEFT JOIN departments d ON d.id=u.department_id
        ORDER BY l.login_time DESC LIMIT 50
        """
    ).fetchall()

    return render_page(
        """
        <div class='card topbar'><div><h2>Faculty Dashboard</h2><div class='badge'>{{session['name']}} | {{session['department_name']}}</div></div><a class='btn btn-muted' href='{{url_for("logout")}}'>Logout</a></div>

        <div class='three'>
          <div class='card'><h3>Add Department</h3><form method='post'><input type='hidden' name='form_type' value='department'>
          <label>Name</label><input name='dept_name' required><button class='btn btn-primary'>Add</button></form></div>

          <div class='card'><h3>Create Assignment</h3><form method='post'><input type='hidden' name='form_type' value='assignment'>
          <label>Title</label><input name='title' required><label>Description</label><textarea name='description' required></textarea>
          <label>Department</label><select name='department_id'><option value=''>All</option>{% for d in depts %}<option value='{{d['id']}}'>{{d['name']}}</option>{% endfor %}</select>
          <label>Deadline</label><input name='deadline' type='datetime-local' required><button class='btn btn-primary'>Create</button></form></div>

          <div class='card'><h3>Announcement</h3><form method='post'><input type='hidden' name='form_type' value='announcement'>
          <label>Title</label><input name='ann_title' required><label>Message</label><textarea name='ann_message' required></textarea>
          <label>Department</label><select name='ann_department_id'><option value=''>All</option>{% for d in depts %}<option value='{{d['id']}}'>{{d['name']}}</option>{% endfor %}</select>
          <button class='btn btn-primary'>Publish</button></form></div>
        </div>

        <div class='card'><h3>Create Quiz</h3><form method='post'><input type='hidden' name='form_type' value='quiz'>
        <div class='two'><div>
        <label>Quiz Title</label><input name='quiz_title' required><label>Description</label><textarea name='quiz_description' required></textarea>
        <label>Department</label><select name='quiz_department_id'><option value=''>All</option>{% for d in depts %}<option value='{{d['id']}}'>{{d['name']}}</option>{% endfor %}</select>
        <label>Deadline</label><input name='quiz_deadline' type='datetime-local' required>
        </div><div>
        <label>Question</label><textarea name='question_text' required></textarea>
        <label>A</label><input name='option_a' required><label>B</label><input name='option_b' required><label>C</label><input name='option_c' required><label>D</label><input name='option_d' required>
        <label>Correct Option</label><input name='correct_option' required>
        </div></div><button class='btn btn-primary'>Create Quiz</button></form></div>

        <div class='card'><h3>Add Question To Existing Quiz</h3><form method='post'><input type='hidden' name='form_type' value='add_question'>
        <label>Quiz</label><select name='quiz_id' required><option value=''>Select</option>{% for q in quizzes %}<option value='{{q['id']}}'>{{q['title']}}</option>{% endfor %}</select>
        <label>Question</label><textarea name='question_text' required></textarea>
        <label>A</label><input name='option_a' required><label>B</label><input name='option_b' required><label>C</label><input name='option_c' required><label>D</label><input name='option_d' required>
        <label>Correct Option</label><input name='correct_option' required><button class='btn btn-primary'>Add Question</button></form></div>

        <div class='card'><h3>Quizzes</h3><table><tr><th>Title</th><th>Department</th><th>Deadline</th><th>Questions</th><th>Attempts</th></tr>
        {% for q in quizzes %}<tr><td>{{q['title']}}</td><td>{{q['dept'] if q['dept'] else 'All'}}</td><td>{{q['deadline']}}</td><td>{{q['qcount']}}</td><td>{{q['attempts']}}</td></tr>{% else %}<tr><td colspan='5'>No quizzes.</td></tr>{% endfor %}</table></div>

        <div class='card'><h3>Assignments</h3><table><tr><th>Title</th><th>Description</th><th>Department</th><th>Deadline</th></tr>
        {% for a in assignments %}<tr><td>{{a['title']}}</td><td>{{a['description']}}</td><td>{{a['dept'] if a['dept'] else 'All'}}</td><td>{{a['deadline']}}</td></tr>{% else %}<tr><td colspan='4'>No assignments.</td></tr>{% endfor %}</table></div>

        <div class='card'><h3>Student Submissions</h3><table><tr><th>Student</th><th>Department</th><th>Assignment</th><th>Submitted</th><th>Status</th><th>File</th><th>Review</th></tr>
        {% for s in subs %}<tr>
          <td>{{s['student']}}<br><small>{{s['email']}}</small></td><td>{{s['dept'] if s['dept'] else '-'}}</td><td>{{s['assignment']}}</td><td>{{s['submitted_at']}}</td>
          <td class='status-{{s['status'].lower()}}'>{{s['status']}}</td>
          <td><a class='btn btn-primary' href='{{url_for("download_file", filename=s['file_name'])}}'>View PDF</a></td>
          <td><form method='post'><input type='hidden' name='form_type' value='review'><input type='hidden' name='submission_id' value='{{s['id']}}'>
          <textarea name='comment' placeholder='Feedback'>{{s['faculty_comment']}}</textarea>
          <button class='btn btn-success' name='action' value='Approved'>Approve</button> <button class='btn btn-danger' name='action' value='Rejected'>Reject</button></form></td>
        </tr>{% else %}<tr><td colspan='7'>No submissions.</td></tr>{% endfor %}</table></div>

        <div class='card'><h3>Recent Logins</h3><table><tr><th>Name</th><th>Email</th><th>Role</th><th>Department</th><th>Time</th></tr>
        {% for l in logs %}<tr><td>{{l['name']}}</td><td>{{l['email']}}</td><td>{{l['role']}}</td><td>{{l['dept'] if l['dept'] else '-'}}</td><td>{{l['login_time']}}</td></tr>{% else %}<tr><td colspan='5'>No logs.</td></tr>{% endfor %}</table></div>
        """,
        depts=depts,
        quizzes=quizzes,
        assignments=assignments,
        subs=subs,
        logs=logs,
    )


@app.route("/uploads/<path:filename>")
@login_required()
def download_file(filename):
    db = get_db()
    sub = db.execute("SELECT student_id FROM submissions WHERE file_name=?", (filename,)).fetchone()
    if not sub:
        flash("File not found.", "error")
        return redirect(url_for("dashboard"))
    if session.get("role") == "student" and sub["student_id"] != session.get("user_id"):
        flash("Access denied.", "error")
        return redirect(url_for("student_dashboard"))
    return send_from_directory(UPLOAD_DIR, filename)


with app.app_context():
    init_db()


if __name__ == "__main__":
    # Host/port configuration (defaults to 0.0.0.0:5000 for deployment)
    HOST = os.environ.get("FLASK_RUN_HOST", "0.0.0.0")
    PORT = int(os.environ.get("PORT", os.environ.get("FLASK_RUN_PORT", 5000)))
    DEBUG = os.environ.get("FLASK_DEBUG", "0") in ("1", "true", "True")
    app.run(host=HOST, port=PORT, debug=DEBUG)
