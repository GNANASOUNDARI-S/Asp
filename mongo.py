import os
from datetime import datetime

import pymongo
from werkzeug.security import generate_password_hash


def get_mongo_db(uri=None):
    uri = uri or os.environ.get("MONGO_URI")
    if not uri:
        raise RuntimeError("MONGO_URI not set")
    client = pymongo.MongoClient(uri)
    # prefer database specified in URI, otherwise use 'portal'
    default_db = client.get_default_database()
    db = default_db if default_db is not None else client["portal"]
    return db


def init_mongo(db):
    # create useful indexes
    db.departments.create_index("name", unique=True)
    db.users.create_index("email", unique=True)
    db.assignments.create_index("title", unique=True)
    db.quiz_questions.create_index([("quiz_id", pymongo.ASCENDING)])
    db.submissions.create_index([("student_id", pymongo.ASCENDING), ("assignment_id", pymongo.ASCENDING)])


def seed_mongo(db):
    deps = ["Computer Science", "Electronics", "Mechanical", "Civil"]
    for n in deps:
        db.departments.update_one({"name": n}, {"$setOnInsert": {"name": n}}, upsert=True)
    cse = db.departments.find_one({"name": "Computer Science"})
    cse_id = cse["_id"] if cse else None
    users = [
        {"name": "Dr. Priya Faculty", "email": "faculty@college.edu", "password": generate_password_hash("faculty123"), "role": "faculty", "department_id": cse_id},
        {"name": "Arun Student", "email": "arun@student.edu", "password": generate_password_hash("student123"), "role": "student", "department_id": cse_id},
        {"name": "Meena Student", "email": "meena@student.edu", "password": generate_password_hash("student123"), "role": "student", "department_id": cse_id},
    ]
    for u in users:
        db.users.update_one({"email": u["email"]}, {"$setOnInsert": u}, upsert=True)

    db.assignments.update_one(
        {"title": "Data Structures - Week 1"},
        {"$setOnInsert": {"title": "Data Structures - Week 1", "description": "Implement stack and queue operations.", "deadline": "2026-03-20 23:59", "department_id": cse_id}},
        upsert=True,
    )

    fac = db.users.find_one({"email": "faculty@college.edu"})
    if fac:
        db.announcements.update_one(
            {"title": "Portal Update"},
            {"$setOnInsert": {"title": "Portal Update", "message": "Assignments, quizzes and announcements are enabled.", "department_id": cse_id, "created_by": fac["_id"], "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}},
            upsert=True,
        )
