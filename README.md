# Student Assignment Portal

A Flask-based assignment submission and review portal with role-based access for students and faculty.

## Features
- User authentication with `student` and `faculty` roles
- Assignment creation and deadline tracking
- PDF submission upload for students
- Faculty review workflow (`Pending`, `Approved`, `Rejected`) with comments
- File access protection based on ownership and role
- SQLite-backed storage with auto-initialized schema

## Project Structure
- `app.py` - Main Flask application
- `portal.db` - SQLite database file
- `uploads/` - Uploaded PDF submissions
- `requirements.txt` - Python dependencies

## Requirements
- Python 3.9+
- `pip`

## Setup
```bash
py -3 -m venv .venv
.venv\Scripts\activate
py -3 -m pip install -r requirements.txt
```

## Run
```bash
py -3 app.py
```

The app runs on `http://127.0.0.1:5000` by default.

## Deploy (Vercel)
Vercel runs this app as a Python Serverless Function. It is **ephemeral**:
uploads and the SQLite database do not persist between requests. For production,
use an external DB (Postgres/Atlas) and object storage.

### Steps
1. Push this repo to GitHub.
2. Import the repo in Vercel.
3. Set environment variables in Vercel:
   - `SECRET_KEY` (required)
   - `MONGO_URI` (optional, if you use MongoDB)
   - `UPLOAD_DIR=/tmp/uploads` (default for serverless)
4. Deploy.

## Notes
- Update `SECRET_KEY` in `app.py` before production use.
- The database schema is initialized automatically on app startup.
- Maximum upload size is 10 MB and only `.pdf` files are accepted.
