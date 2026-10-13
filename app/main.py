"""notes-api: the small service the pipeline builds, scans, signs and ships.

Deliberately ordinary (a CRUD API over SQLite) so the interesting part is the pipeline, but
written the way the gates expect: parameterised SQL, validated input, security headers, no
secrets in code (DATABASE_PATH and API_TOKEN come from the environment).
"""
import hmac
import os
import sqlite3
from contextlib import closing

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field

DB_PATH = os.environ.get("DATABASE_PATH", "/tmp/notes.db")
API_TOKEN = os.environ.get("API_TOKEN", "")

app = FastAPI(title="notes-api", docs_url=None, redoc_url=None, openapi_url=None)

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers.update(SECURITY_HEADERS)
    return response


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner TEXT NOT NULL, body TEXT NOT NULL)")
    return conn


def require_token(authorization: str = Header(default="")):
    """Writes need `Authorization: Bearer <API_TOKEN>`; compared in constant time."""
    if not API_TOKEN or not hmac.compare_digest(authorization, f"Bearer {API_TOKEN}"):
        raise HTTPException(401, "missing or invalid token")


class Note(BaseModel):
    owner: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    body: str = Field(min_length=1, max_length=2000)


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/notes")
def list_notes(owner: str):
    with closing(db()) as conn:
        rows = conn.execute("SELECT id, owner, body FROM notes WHERE owner = ? ORDER BY id", (owner,)).fetchall()
    return [{"id": r[0], "owner": r[1], "body": r[2]} for r in rows]


@app.post("/notes", status_code=201, dependencies=[Depends(require_token)])
def create_note(note: Note):
    with closing(db()) as conn, conn:
        cur = conn.execute("INSERT INTO notes (owner, body) VALUES (?, ?)", (note.owner, note.body))
    return {"id": cur.lastrowid, **note.model_dump()}
