import base64
from datetime import datetime
import hashlib
import hmac
import json
import os
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import closing
from pathlib import Path
from typing import Annotated, Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import DateTime, Integer, String, create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


load_dotenv()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
SECRET_KEY = os.getenv("SECRET_KEY", "")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

DB_PATH = Path(os.getenv("DB_PATH", "/app/data/habit_tracker.db"))
TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7


class Base(DeclarativeBase):
	pass


class AnalyticsUser(Base):
	__tablename__ = "users_analytics"

	id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
	email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
	name: Mapped[str] = mapped_column(String, nullable=False)
	created_at: Mapped[datetime] = mapped_column(
		DateTime(timezone=True), nullable=False, server_default=func.now()
	)


engine = create_engine(
	f"sqlite:///{DB_PATH}",
	connect_args={"check_same_thread": False},
)


class HabitCreate(BaseModel):
	name: str
	time: str
	location: str
	preposition: str
	frequency: str
	customDays: Optional[list] = None
	createdDay: str


class CompletionCreate(BaseModel):
	habit_id: int
	date: str
	completed: bool


class UserName(BaseModel):
	name: str


def get_db_connection() -> sqlite3.Connection:
	conn = sqlite3.connect(DB_PATH)
	conn.row_factory = sqlite3.Row
	return conn


def init_db() -> None:
	with closing(get_db_connection()) as conn:
		cursor = conn.cursor()
		cursor.execute(
			"""
			CREATE TABLE IF NOT EXISTS habits (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				name TEXT NOT NULL,
				time TEXT NOT NULL,
				location TEXT NOT NULL,
				preposition TEXT NOT NULL,
				frequency TEXT NOT NULL,
				customDays TEXT,
				createdDay TEXT NOT NULL,
				user_email TEXT NOT NULL
			)
			"""
		)
		cursor.execute(
			"""
			CREATE TABLE IF NOT EXISTS completions (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				habit_id INTEGER NOT NULL,
				date TEXT NOT NULL,
				user_email TEXT NOT NULL,
				FOREIGN KEY(habit_id) REFERENCES habits(id)
			)
			"""
		)
		cursor.execute(
			"""
			CREATE TABLE IF NOT EXISTS users (
				email TEXT PRIMARY KEY,
				name TEXT NOT NULL
			)
			"""
		)
		conn.commit()

	Base.metadata.create_all(bind=engine)


def ensure_analytics_user_exists(user_email: str, user_name: str) -> None:
	with Session(engine) as session:
		existing_id = session.execute(
			select(AnalyticsUser.id).where(AnalyticsUser.email == user_email)
		).scalar_one_or_none()
		if existing_id is not None:
			return

		session.add(AnalyticsUser(email=user_email, name=user_name))
		session.commit()


def _base64url_encode(data: bytes) -> str:
	return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _base64url_decode(data: str) -> bytes:
	padding = "=" * (-len(data) % 4)
	return base64.urlsafe_b64decode(data + padding)


def create_signed_token(user_email: str) -> str:
	if not SECRET_KEY:
		raise HTTPException(status_code=500, detail="SECRET_KEY is not configured")

	payload = {
		"email": user_email,
		"exp": int(time.time()) + TOKEN_TTL_SECONDS,
	}
	payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
	payload_b64 = _base64url_encode(payload_bytes)
	signature = hmac.new(
		SECRET_KEY.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256
	).digest()
	signature_b64 = _base64url_encode(signature)
	return f"{payload_b64}.{signature_b64}"


def decode_signed_token(token: str) -> dict:
	if not SECRET_KEY:
		raise HTTPException(status_code=500, detail="SECRET_KEY is not configured")

	try:
		payload_b64, signature_b64 = token.split(".", 1)
	except ValueError as exc:
		raise HTTPException(status_code=401, detail="Invalid token format") from exc

	expected_signature = hmac.new(
		SECRET_KEY.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256
	).digest()
	provided_signature = _base64url_decode(signature_b64)

	if not hmac.compare_digest(expected_signature, provided_signature):
		raise HTTPException(status_code=401, detail="Invalid token signature")

	try:
		payload = json.loads(_base64url_decode(payload_b64).decode("utf-8"))
	except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
		raise HTTPException(status_code=401, detail="Invalid token payload") from exc

	exp = payload.get("exp")
	if not isinstance(exp, int) or exp < int(time.time()):
		raise HTTPException(status_code=401, detail="Token expired")

	if not payload.get("email"):
		raise HTTPException(status_code=401, detail="Token missing email")

	return payload


def get_current_user_email(
	authorization: Annotated[Optional[str], Header()] = None,
	token: Optional[str] = Query(default=None),
) -> str:
	bearer_token = None
	if authorization and authorization.lower().startswith("bearer "):
		bearer_token = authorization.split(" ", 1)[1]

	signed_token = bearer_token or token
	if not signed_token:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Missing token. Pass bearer token or ?token=...",
		)

	payload = decode_signed_token(signed_token)
	return str(payload["email"])


def get_google_redirect_uri() -> str:
	# Keep callback URL predictable and configurable via API_BASE_URL when deployed.
	api_base_url = os.getenv("API_BASE_URL", "http://localhost:8000")
	return f"{api_base_url.rstrip('/')}/auth/callback"


def fetch_google_token(code: str) -> dict:
	token_url = "https://oauth2.googleapis.com/token"
	data = urllib.parse.urlencode(
		{
			"code": code,
			"client_id": GOOGLE_CLIENT_ID,
			"client_secret": GOOGLE_CLIENT_SECRET,
			"redirect_uri": get_google_redirect_uri(),
			"grant_type": "authorization_code",
		}
	).encode("utf-8")

	request = urllib.request.Request(
		token_url,
		data=data,
		method="POST",
		headers={"Content-Type": "application/x-www-form-urlencoded"},
	)

	try:
		with urllib.request.urlopen(request) as response:
			return json.loads(response.read().decode("utf-8"))
	except urllib.error.HTTPError as exc:
		body = exc.read().decode("utf-8", errors="ignore")
		raise HTTPException(status_code=400, detail=f"Google token error: {body}") from exc


def fetch_google_user_email(access_token: str) -> str:
	user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
	request = urllib.request.Request(
		user_info_url,
		method="GET",
		headers={"Authorization": f"Bearer {access_token}"},
	)

	try:
		with urllib.request.urlopen(request) as response:
			data = json.loads(response.read().decode("utf-8"))
	except urllib.error.HTTPError as exc:
		body = exc.read().decode("utf-8", errors="ignore")
		raise HTTPException(status_code=400, detail=f"Google userinfo error: {body}") from exc

	email = data.get("email")
	if not email:
		raise HTTPException(status_code=400, detail="Google account email not found")
	return email


app = FastAPI(title="Habit Tracker Backend")

app.add_middleware(
	CORSMiddleware,
	allow_origins=["*"],
	allow_credentials=True,
	allow_methods=["*"],
	allow_headers=["*"],
)


@app.on_event("startup")
def startup_event() -> None:
	init_db()


@app.get("/auth/login")
def auth_login() -> RedirectResponse:
	"""
	Start Google OAuth login.

	In production, GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET should be set.
	In tests or local dev without secrets, we still return a redirect to a
	Google accounts URL with dummy values so the endpoint is testable.
	"""
	client_id = GOOGLE_CLIENT_ID or "test-client-id"
	_client_secret = GOOGLE_CLIENT_SECRET or "test-client-secret"

	params = {
		"client_id": client_id,
		"redirect_uri": get_google_redirect_uri(),
		"response_type": "code",
		"scope": "openid email profile",
		"access_type": "online",
		"prompt": "select_account",
	}
	google_auth_url = (
		"https://accounts.google.com/o/oauth2/v2/auth?"
		f"{urllib.parse.urlencode(params)}"
	)
	return RedirectResponse(url=google_auth_url)


@app.get("/auth/callback")
def auth_callback(code: str) -> RedirectResponse:
	token_data = fetch_google_token(code)
	access_token = token_data.get("access_token")
	if not access_token:
		raise HTTPException(status_code=400, detail="Missing access token from Google")

	email = fetch_google_user_email(access_token)
	signed_token = create_signed_token(email)
	redirect_url = f"{FRONTEND_URL.rstrip('/')}/?token={signed_token}"
	return RedirectResponse(url=redirect_url)


@app.get("/auth/me")
def auth_me(user_email: Annotated[str, Depends(get_current_user_email)]) -> dict:
	return {"email": user_email}


@app.get("/user/name")
def get_user_name(user_email: Annotated[str, Depends(get_current_user_email)]) -> dict:
	with closing(get_db_connection()) as conn:
		row = conn.execute(
			"SELECT name FROM users WHERE email = ?",
			(user_email,),
		).fetchone()

	if row:
		return {"name": row["name"]}

	return {"name": None}


@app.post("/user/name")
def upsert_user_name(
	data: UserName,
	user_email: Annotated[str, Depends(get_current_user_email)],
) -> dict:
	ensure_analytics_user_exists(user_email=user_email, user_name=data.name)

	with closing(get_db_connection()) as conn:
		conn.execute(
			"""
			INSERT INTO users (email, name)
			VALUES (?, ?)
			ON CONFLICT(email) DO UPDATE SET name = excluded.name
			""",
			(user_email, data.name),
		)
		conn.commit()

	return {"email": user_email, "name": data.name}


@app.get("/n8n/users")
def n8n_get_users() -> list[dict]:
	with Session(engine) as session:
		rows = session.execute(select(AnalyticsUser).order_by(AnalyticsUser.id.asc())).scalars().all()

	return [
		{
			"id": row.id,
			"name": row.name,
			"email": row.email,
			"created_at": row.created_at,
		}
		for row in rows
	]


@app.get("/habits")
def get_habits(user_email: Annotated[str, Depends(get_current_user_email)]) -> dict:
	with closing(get_db_connection()) as conn:
		rows = conn.execute(
			"SELECT id, name, time, location, preposition, frequency, customDays, createdDay, user_email "
			"FROM habits WHERE user_email = ? ORDER BY id DESC",
			(user_email,),
		).fetchall()
	
	habits = []
	for row in rows:
		habit = dict(row)
		custom_days = habit.get('customDays')
		if custom_days:
			habit['customDays'] = json.loads(custom_days)
		else:
			habit['customDays'] = []
		habits.append(habit)
	
	return {"habits": habits}


@app.post("/habits")
def create_habit(
	habit: HabitCreate, user_email: Annotated[str, Depends(get_current_user_email)]
) -> dict:
	with closing(get_db_connection()) as conn:
		cursor = conn.execute(
			"""
			INSERT INTO habits (name, time, location, preposition, frequency, customDays, createdDay, user_email)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			""",
			(
				habit.name,
				habit.time,
				habit.location,
				habit.preposition,
				habit.frequency,
				json.dumps(habit.customDays) if habit.customDays else None,
				habit.createdDay,
				user_email,
			),
		)
		conn.commit()
		habit_id = cursor.lastrowid

	return {
		"habit": {
			"id": habit_id,
			"name": habit.name,
			"time": habit.time,
			"location": habit.location,
			"preposition": habit.preposition,
			"frequency": habit.frequency,
			"customDays": habit.customDays,
			"createdDay": habit.createdDay,
			"user_email": user_email,
		}
	}


@app.delete("/habits/{id}")
def delete_habit(id: int, user_email: Annotated[str, Depends(get_current_user_email)]) -> dict:
	with closing(get_db_connection()) as conn:
		cursor = conn.execute(
			"DELETE FROM habits WHERE id = ? AND user_email = ?",
			(id, user_email),
		)
		conn.execute(
			"DELETE FROM completions WHERE habit_id = ? AND user_email = ?",
			(id, user_email),
		)
		conn.commit()

	if cursor.rowcount == 0:
		raise HTTPException(status_code=404, detail="Habit not found")

	return {"deleted": True, "id": id}


@app.get("/completions/{date}")
def get_completions(
	date: str, user_email: Annotated[str, Depends(get_current_user_email)]
) -> dict:
	with closing(get_db_connection()) as conn:
		rows = conn.execute(
			"SELECT id, habit_id, date, user_email FROM completions "
			"WHERE user_email = ? AND date = ? ORDER BY id DESC",
			(user_email, date),
		).fetchall()
	return {
		"completions": [
			{"habit_id": row["habit_id"], "completed": True} for row in rows
		]
	}


@app.post("/completions")
def create_completion(
	completion: CompletionCreate,
	user_email: Annotated[str, Depends(get_current_user_email)],
) -> dict:
	with closing(get_db_connection()) as conn:
		habit = conn.execute(
			"SELECT id FROM habits WHERE id = ? AND user_email = ?",
			(completion.habit_id, user_email),
		).fetchone()

		if not habit:
			raise HTTPException(status_code=404, detail="Habit not found for this user")

		cursor = conn.execute(
			"INSERT INTO completions (habit_id, date, user_email) VALUES (?, ?, ?)",
			(completion.habit_id, completion.date, user_email),
		)
		conn.commit()
		completion_id = cursor.lastrowid

	return {
		"completion": {
			"id": completion_id,
			"habit_id": completion.habit_id,
			"date": completion.date,
			"user_email": user_email,
		}
	}
@app.get("/n8n/habits")
def n8n_get_all_habits() -> dict:
	"""
	Simple export endpoint for n8n:
	Returns all habits for all users, with user_email.
	"""
	with closing(get_db_connection()) as conn:
		rows = conn.execute(
			"""
			SELECT
				h.id,
				h.name,
				h.time,
				h.location,
				h.preposition,
				h.frequency,
				h.customDays,
				h.createdDay,
				h.user_email,
				u.name AS user_name
			FROM habits h
			LEFT JOIN users u ON h.user_email = u.email
			ORDER BY h.id DESC
			"""
		).fetchall()

	return {"habits": [dict(row) for row in rows]}