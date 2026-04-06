import os

# Vercel Python runtime looks for a WSGI app named "app"
from app import app  # noqa: E402

# Use /tmp for uploads on serverless (ephemeral)
os.environ.setdefault("UPLOAD_DIR", "/tmp/uploads")
