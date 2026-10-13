import os
import re
import secrets
import socket
import time
import ipaddress
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field, HttpUrl, ConfigDict
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import DuplicateKeyError
from bson import ObjectId
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from pwdlib import PasswordHash


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MONGODB_URI = os.getenv("MONGODB_URI", "").strip()
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "healthy_api").strip()
SESSION_SECRET = os.getenv("SESSION_SECRET", "").strip()
FRONTEND_ORIGINS = [
    "https://healthyapi.netlify.app"
]
COOKIE_NAME = "healthy_api_session"
SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 7
LIVE_TEST_TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 512 * 1024  # 512 KiB
MAX_WORKERS_PER_USER = 100

if not MONGODB_URI:
    raise RuntimeError("Set the MONGODB_URI environment variable.")
if len(SESSION_SECRET) < 32:
    raise RuntimeError(
        "Set SESSION_SECRET to a random secret of at least 32 characters."
    )

app = FastAPI(
    title="Healthy API",
    description="API testing and monitoring backend",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type"],
)

mongo_client = MongoClient(
    MONGODB_URI,
    serverSelectionTimeoutMS=5000,
    connectTimeoutMS=5000,
)
db = mongo_client[MONGODB_DATABASE]
users = db["users"]
workers = db["workers"]
probe_results = db["probe_results"]

# Unique account email; worker indexes support ownership and listing.
users.create_index([("email", ASCENDING)], unique=True)
workers.create_index([("owner_id", ASCENDING), ("created_at", DESCENDING)])
probe_results.create_index([("worker_id", ASCENDING), ("checked_at", DESCENDING)])

password_hash = PasswordHash.recommended()
session_serializer = URLSafeTimedSerializer(SESSION_SECRET, salt="healthy-api-session")


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class AccountCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class WorkerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    url: HttpUrl
    interval_seconds: int = Field(default=300, ge=60, le=86400)
    expected_status: int = Field(default=200, ge=100, le=599)


class LiveTestRequest(BaseModel):
    url: HttpUrl
    method: str = Field(default="GET", pattern=r"^(GET|HEAD)$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(user["_id"]),
        "email": user["email"],
        "created_at": user["created_at"].isoformat(),
    }


def set_session_cookie(response: Response, user_id: ObjectId) -> None:
    token = session_serializer.dumps({"uid": str(user_id), "nonce": secrets.token_urlsafe(12)})
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=SESSION_MAX_AGE_SECONDS,
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "true").lower() == "true",
        samesite="lax",
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=COOKIE_NAME,
        path="/",
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "true").lower() == "true",
        samesite="lax",
    )


def current_user(request: Request) -> dict[str, Any]:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="Please log in.")

    try:
        data = session_serializer.loads(
            token, max_age=SESSION_MAX_AGE_SECONDS
        )
        user_id = ObjectId(data["uid"])
    except (BadSignature, SignatureExpired, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Session is invalid or expired.")

    user = users.find_one({"_id": user_id})
    if not user:
        raise HTTPException(status_code=401, detail="Account no longer exists.")
    return user


def validate_public_http_url(url: str) -> str:
    """
    Basic SSRF protection for user-supplied probe URLs.
    Production deployments should additionally enforce outbound network rules
    and use a DNS-pinning/egress proxy to mitigate DNS rebinding.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Only HTTP and HTTPS URLs are allowed.")
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="URL must include a hostname.")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="Credentials in URLs are not allowed.")
    if parsed.port and not (1 <= parsed.port <= 65535):
        raise HTTPException(status_code=400, detail="Invalid port.")

    hostname = parsed.hostname.rstrip(".").lower()
    if hostname in {"localhost", "localhost.localdomain", "metadata.google.internal"}:
        raise HTTPException(status_code=400, detail="This destination is not allowed.")

    try:
        answers = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Hostname could not be resolved.")

    if not answers:
        raise HTTPException(status_code=400, detail="Hostname could not be resolved.")

    for answer in answers:
        ip = ipaddress.ip_address(answer[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise HTTPException(
                status_code=400,
                detail="URLs resolving to private or reserved IP addresses are not allowed.",
            )

    return url


async def live_test(url: str, method: str = "GET") -> dict[str, Any]:
    """
    Shared probe function for manual tests and the future monitor scheduler.
    Only GET/HEAD are supported here; redirects are disabled to reduce SSRF risk.
    """
    safe_url = validate_public_http_url(url)
    started = time.perf_counter()

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(LIVE_TEST_TIMEOUT_SECONDS),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            async with client.stream(method, safe_url) as resp:
                body_preview = bytearray()
                if method != "HEAD":
                    async for chunk in resp.aiter_bytes():
                        remaining = MAX_RESPONSE_BYTES - len(body_preview)
                        if remaining <= 0:
                            break
                        body_preview.extend(chunk[:remaining])
                        if len(body_preview) >= MAX_RESPONSE_BYTES:
                            break

                elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
                content_type = resp.headers.get("content-type", "")
                preview_text = body_preview.decode("utf-8", errors="replace")

                # Avoid returning arbitrary large/binary response bodies.
                if "text/" not in content_type and "json" not in content_type:
                    preview_text = f"[Body omitted: {content_type or 'unknown content type'}]"

                return {
                    "ok": 200 <= resp.status_code < 400,
                    "status_code": resp.status_code,
                    "latency_ms": elapsed_ms,
                    "final_url": str(resp.url),
                    "content_type": content_type,
                    "body_preview": preview_text[:MAX_RESPONSE_BYTES],
                    "checked_at": utc_now().isoformat(),
                }

    except httpx.TimeoutException:
        return {
            "ok": False,
            "status_code": None,
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "error": "Request timed out.",
            "checked_at": utc_now().isoformat(),
        }
    except httpx.RequestError:
        # Avoid exposing internal exception details or environment information.
        return {
            "ok": False,
            "status_code": None,
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "error": "Connection failed or the target could not be reached.",
            "checked_at": utc_now().isoformat(),
        }


def serialize_worker(worker: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(worker["_id"]),
        "name": worker["name"],
        "url": worker["url"],
        "interval_seconds": worker["interval_seconds"],
        "expected_status": worker["expected_status"],
        "enabled": worker["enabled"],
        "created_at": worker["created_at"].isoformat(),
        "last_test": worker.get("last_test"),
    }


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> dict[str, str]:
    mongo_client.admin.command("ping")
    return {"status": "ok", "service": "Healthy API"}


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
def create_account(payload: AccountCreate, response: Response) -> dict[str, Any]:
    email = str(payload.email).strip().lower()

    try:
        result = users.insert_one(
            {
                "email": email,
                "password_hash": password_hash.hash(payload.password),
                "created_at": utc_now(),
            }
        )
    except DuplicateKeyError:
        # Generic response avoids disclosing whether an email is registered.
        raise HTTPException(status_code=409, detail="Unable to create account with these details.")

    user = users.find_one({"_id": result.inserted_id})
    set_session_cookie(response, result.inserted_id)
    return {"user": public_user(user)}


@app.post("/auth/login")
def login(payload: LoginRequest, response: Response) -> dict[str, Any]:
    email = str(payload.email).strip().lower()
    user = users.find_one({"email": email})

    if not user or not password_hash.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    set_session_cookie(response, user["_id"])
    return {"user": public_user(user)}


@app.post("/auth/logout")
def logout(response: Response) -> dict[str, str]:
    clear_session_cookie(response)
    return {"message": "Logged out."}


@app.get("/auth/me")
def get_current_account(request: Request) -> dict[str, Any]:
    return {"user": public_user(current_user(request))}


# ---------------------------------------------------------------------------
# Live testing
# ---------------------------------------------------------------------------

@app.post("/tests/live")
async def run_live_test(
    payload: LiveTestRequest,
    request: Request,
) -> dict[str, Any]:
    # Require login to prevent anonymous abuse of the server as a proxy.
    current_user(request)
    result = await live_test(str(payload.url), payload.method)
    return result


# ---------------------------------------------------------------------------
# Workers (monitors)
# ---------------------------------------------------------------------------

@app.post("/workers", status_code=status.HTTP_201_CREATED)
async def create_worker(
    payload: WorkerCreate,
    request: Request,
) -> dict[str, Any]:
    user = current_user(request)
    url = validate_public_http_url(str(payload.url))

    count = workers.count_documents({"owner_id": user["_id"]})
    if count >= MAX_WORKERS_PER_USER:
        raise HTTPException(
            status_code=429,
            detail=f"Worker limit reached ({MAX_WORKERS_PER_USER}).",
        )

    now = utc_now()
    worker_doc = {
        "owner_id": user["_id"],
        "name": payload.name.strip(),
        "url": url,
        "interval_seconds": payload.interval_seconds,
        "expected_status": payload.expected_status,
        "enabled": True,
        "created_at": now,
        "next_check_at": now,
        "last_test": None,
    }
    result = workers.insert_one(worker_doc)
    worker_doc["_id"] = result.inserted_id

    # Initial live test to provide immediate feedback.
    test_result = await live_test(url, "GET")
    test_result["expected_status"] = payload.expected_status
    test_result["healthy"] = test_result.get("status_code") == payload.expected_status

    workers.update_one(
        {"_id": result.inserted_id, "owner_id": user["_id"]},
        {
            "$set": {
                "last_test": test_result,
                "next_check_at": utc_now() + timedelta(seconds=payload.interval_seconds),
            }
        },
    )
    probe_results.insert_one(
        {
            "worker_id": result.inserted_id,
            "owner_id": user["_id"],
            **test_result,
        }
    )
    worker_doc["last_test"] = test_result
    return {"worker": serialize_worker(worker_doc)}


@app.get("/workers")
def list_workers(request: Request) -> dict[str, Any]:
    user = current_user(request)
    items = workers.find({"owner_id": user["_id"]}).sort("created_at", DESCENDING)
    return {"workers": [serialize_worker(item) for item in items]}


@app.get("/workers/{worker_id}")
def get_worker(worker_id: str, request: Request) -> dict[str, Any]:
    user = current_user(request)
    try:
        oid = ObjectId(worker_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Worker not found.")

    worker = workers.find_one({"_id": oid, "owner_id": user["_id"]})
    if not worker:
        raise HTTPException(status_code=404, detail="Worker not found.")
    return {"worker": serialize_worker(worker)}


@app.delete("/workers/{worker_id}")
def delete_worker(worker_id: str, request: Request) -> dict[str, str]:
    user = current_user(request)
    try:
        oid = ObjectId(worker_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Worker not found.")

    result = workers.delete_one({"_id": oid, "owner_id": user["_id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Worker not found.")

    probe_results.delete_many({"worker_id": oid, "owner_id": user["_id"]})
    return {"message": "Worker deleted."}


@app.get("/workers/{worker_id}/history")
def worker_history(
    worker_id: str,
    request: Request,
    limit: int = 50,
) -> dict[str, Any]:
    user = current_user(request)
    try:
        oid = ObjectId(worker_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Worker not found.")

    worker = workers.find_one({"_id": oid, "owner_id": user["_id"]})
    if not worker:
        raise HTTPException(status_code=404, detail="Worker not found.")

    safe_limit = max(1, min(limit, 200))
    history = probe_results.find(
        {"worker_id": oid, "owner_id": user["_id"]}
    ).sort("checked_at", DESCENDING).limit(safe_limit)

    records = []
    for item in history:
        records.append({
            "ok": item.get("ok", False),
            "status_code": item.get("status_code"),
            "latency_ms": item.get("latency_ms"),
            "healthy": item.get("healthy"),
            "error": item.get("error"),
            "checked_at": item["checked_at"].isoformat()
            if isinstance(item.get("checked_at"), datetime)
            else item.get("checked_at"),
        })
    return {"history": records}
