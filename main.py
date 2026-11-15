"""
Misr Engineering Studio — Auth Backend
متوافق مع صفحة الهبوط على Vercel
"""
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from urllib.parse import urlencode

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

# ============================================================
# Config
# ============================================================
FRONTEND_URL     = os.getenv("FRONTEND_URL", "https://misrpcbplceditor.vercel.app").rstrip("/")
POST_LOGIN_PATH  = os.getenv("POST_LOGIN_PATH", "/editor")   # وجهة ما بعد الدخول
SECRET_KEY       = os.getenv("SECRET_KEY", secrets.token_urlsafe(48))
COOKIE_SECURE    = os.getenv("COOKIE_SECURE", "true").lower() == "true"
DATABASE_URL     = os.getenv("DATABASE_URL", "sqlite:///./circuitforge.db")

SESSION_COOKIE   = "cf_session"
SESSION_MAX_AGE  = 60 * 60 * 24 * 7   # 7 أيام
HTTP_TIMEOUT     = httpx.Timeout(15.0, connect=10.0)

# OAuth — Google
GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI  = os.getenv("GOOGLE_REDIRECT_URI",
                                 f"{FRONTEND_URL}/auth/google/callback")

# OAuth — GitHub
GITHUB_CLIENT_ID     = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_REDIRECT_URI  = os.getenv("GITHUB_REDIRECT_URI",
                                 f"{FRONTEND_URL}/auth/github/callback")

# OAuth — GitLab
GITLAB_CLIENT_ID     = os.getenv("GITLAB_CLIENT_ID")
GITLAB_CLIENT_SECRET = os.getenv("GITLAB_CLIENT_SECRET")
GITLAB_REDIRECT_URI  = os.getenv("GITLAB_REDIRECT_URI",
                                 f"{FRONTEND_URL}/auth/gitlab/callback")
GITLAB_BASE_URL      = os.getenv("GITLAB_BASE_URL", "https://gitlab.com").rstrip("/")

# OAuth — LinkedIn
LINKEDIN_CLIENT_ID     = os.getenv("LINKEDIN_CLIENT_ID")
LINKEDIN_CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET")
LINKEDIN_REDIRECT_URI  = os.getenv("LINKEDIN_REDIRECT_URI",
                                   f"{FRONTEND_URL}/auth/linkedin/callback")

# OAuth — Facebook
FACEBOOK_CLIENT_ID     = os.getenv("FACEBOOK_CLIENT_ID")
FACEBOOK_CLIENT_SECRET = os.getenv("FACEBOOK_CLIENT_SECRET")
FACEBOOK_REDIRECT_URI  = os.getenv("FACEBOOK_REDIRECT_URI",
                                   f"{FRONTEND_URL}/auth/facebook/callback")

serializer = URLSafeTimedSerializer(SECRET_KEY, salt="cf-session-v1")


# ============================================================
# Database
# ============================================================
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def _utcnow():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id          = Column(Integer, primary_key=True, index=True)
    email       = Column(String(255), unique=True, index=True, nullable=False)
    name        = Column(String(255))
    google_id   = Column(String(64), nullable=True)
    github_id   = Column(String(64), nullable=True)
    gitlab_id   = Column(String(64), nullable=True)
    linkedin_id = Column(String(64), nullable=True)
    facebook_id = Column(String(64), nullable=True)
    created_at  = Column(DateTime(timezone=True), default=_utcnow, nullable=False)


def init_db():
    Base.metadata.create_all(bind=engine)


# ============================================================
# Lifespan + App
# ============================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Misr Engineering Studio — Auth API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ============================================================
# Helpers
# ============================================================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _require(value, name):
    if not value:
        raise HTTPException(500, f"{name} is not configured")
    return value


def _state_cookie(provider):
    return f"oauth_state_{provider}"


def _redirect_with_state(url, provider, state):
    r = RedirectResponse(url=url)
    r.set_cookie(
        key=_state_cookie(provider),
        value=state,
        max_age=600,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
    )
    return r


def _verify_state(request, provider, received):
    cookie = request.cookies.get(_state_cookie(provider))
    if not cookie or not received:
        raise HTTPException(400, "Missing OAuth state")
    if not secrets.compare_digest(cookie, received):
        raise HTTPException(400, "Invalid OAuth state")


def _upsert_user(db, *, email, name, provider, provider_id):
    user = db.query(User).filter(User.email == email).first()
    id_field = f"{provider}_id"
    if user is None:
        user = User(email=email, name=name or email.split("@")[0])
        setattr(user, id_field, provider_id)
        db.add(user)
    else:
        if name and not user.name:
            user.name = name
        if provider_id and getattr(user, id_field) is None:
            setattr(user, id_field, provider_id)
    db.commit()
    db.refresh(user)
    return user


def _issue_session(user, provider):
    token = serializer.dumps({"uid": user.id, "email": user.email})
    r = RedirectResponse(url=f"{FRONTEND_URL}{POST_LOGIN_PATH}")
    r.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )
    r.delete_cookie(_state_cookie(provider), path="/")
    return r


def _read_session(request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(401, "Not authenticated")
    try:
        return serializer.loads(token, max_age=SESSION_MAX_AGE)
    except SignatureExpired:
        raise HTTPException(401, "Session expired")
    except BadSignature:
        raise HTTPException(401, "Invalid session")


# ============================================================
# Basic
# ============================================================
@app.get("/")
def root():
    return {"message": "Misr Engineering Studio Auth API", "status": "running"}


@app.get("/health")
def health():
    return {"status": "healthy"}


# ============================================================
# Session endpoints
# ============================================================
@app.get("/api/auth/me")
def auth_me(request: Request, db: Session = Depends(get_db)):
    data = _read_session(request)
    user = db.query(User).filter(User.id == data["uid"]).first()
    if not user:
        raise HTTPException(401, "User not found")
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "google_id": user.google_id,
        "github_id": user.github_id,
        "gitlab_id": user.gitlab_id,
        "linkedin_id": user.linkedin_id,
        "facebook_id": user.facebook_id,
    }


@app.post("/api/auth/logout")
def auth_logout():
    r = Response(content='{"ok": true}', media_type="application/json")
    r.delete_cookie(SESSION_COOKIE, path="/")
    return r


# ============================================================
# Google OAuth
# ============================================================
@app.get("/auth/google/login")
def google_login():
    cid = _require(GOOGLE_CLIENT_ID, "GOOGLE_CLIENT_ID")
    uri = _require(GOOGLE_REDIRECT_URI, "GOOGLE_REDIRECT_URI")
    state = secrets.token_urlsafe(32)
    params = {
        "client_id": cid,
        "redirect_uri": uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    }
    url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
    return _redirect_with_state(url, "google", state)


@app.get("/auth/google/callback")
async def google_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db),
):
    if error:
        raise HTTPException(400, f"Google error: {error}")
    if not code:
        raise HTTPException(400, "Authorization code missing")
    _verify_state(request, "google", state)

    cid = _require(GOOGLE_CLIENT_ID, "GOOGLE_CLIENT_ID")
    sec = _require(GOOGLE_CLIENT_SECRET, "GOOGLE_CLIENT_SECRET")
    uri = _require(GOOGLE_REDIRECT_URI, "GOOGLE_REDIRECT_URI")

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        token_res = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": cid,
                "client_secret": sec,
                "redirect_uri": uri,
                "grant_type": "authorization_code",
            },
        )
        if token_res.status_code != 200:
            raise HTTPException(401, f"Google token failed: {token_res.text}")
        access_token = token_res.json().get("access_token")

        info_res = await client.get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if info_res.status_code != 200:
            raise HTTPException(400, f"Google userinfo failed: {info_res.text}")
        info = info_res.json()

    email = info.get("email")
    if not email:
        raise HTTPException(400, "Google did not return email")

    user = _upsert_user(
        db,
        email=email,
        name=info.get("name"),
        provider="google",
        provider_id=info.get("sub"),
    )
    return _issue_session(user, "google")


# ============================================================
# GitHub OAuth
# ============================================================
@app.get("/auth/github/login")
def github_login():
    cid = _require(GITHUB_CLIENT_ID, "GITHUB_CLIENT_ID")
    uri = _require(GITHUB_REDIRECT_URI, "GITHUB_REDIRECT_URI")
    state = secrets.token_urlsafe(32)
    params = {
        "client_id": cid,
        "redirect_uri": uri,
        "scope": "user:email",
        "state": state,
        "allow_signup": "true",
    }
    url = "https://github.com/login/oauth/authorize?" + urlencode(params)
    return _redirect_with_state(url, "github", state)


@app.get("/auth/github/callback")
async def github_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db),
):
    if error:
        raise HTTPException(400, f"GitHub error: {error}")
    if not code:
        raise HTTPException(400, "Authorization code missing")
    _verify_state(request, "github", state)

    cid = _require(GITHUB_CLIENT_ID, "GITHUB_CLIENT_ID")
    sec = _require(GITHUB_CLIENT_SECRET, "GITHUB_CLIENT_SECRET")
    uri = _require(GITHUB_REDIRECT_URI, "GITHUB_REDIRECT_URI")

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        token_res = await client.post(
            "https://github.com/login/oauth/access_token",
            json={"client_id": cid, "client_secret": sec, "code": code, "redirect_uri": uri},
            headers={"Accept": "application/json"},
        )
        if token_res.status_code != 200:
            raise HTTPException(401, f"GitHub token failed: {token_res.text}")
        access_token = token_res.json().get("access_token")

        h = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
        user_res = await client.get("https://api.github.com/user", headers=h)
        if user_res.status_code != 200:
            raise HTTPException(400, f"GitHub user failed: {user_res.text}")
        user_data = user_res.json()

        email = user_data.get("email")
        if not email:
            em = await client.get("https://api.github.com/user/emails", headers=h)
            if em.status_code == 200:
                for e in em.json():
                    if e.get("primary") and e.get("verified"):
                        email = e["email"]
                        break
                if not email and em.json():
                    email = em.json()[0].get("email")

    if not email:
        email = f"{user_data.get('id')}@users.noreply.github.com"
    name = user_data.get("name") or user_data.get("login") or email.split("@")[0]

    user = _upsert_user(
        db,
        email=email,
        name=name,
        provider="github",
        provider_id=str(user_data.get("id")) if user_data.get("id") else None,
    )
    return _issue_session(user, "github")


# ============================================================
# GitLab OAuth
# ============================================================
@app.get("/auth/gitlab/login")
def gitlab_login():
    cid = _require(GITLAB_CLIENT_ID, "GITLAB_CLIENT_ID")
    uri = _require(GITLAB_REDIRECT_URI, "GITLAB_REDIRECT_URI")
    state = secrets.token_urlsafe(32)
    params = {
        "client_id": cid,
        "redirect_uri": uri,
        "response_type": "code",
        "state": state,
        "scope": "read_user",
    }
    url = f"{GITLAB_BASE_URL}/oauth/authorize?" + urlencode(params)
    return _redirect_with_state(url, "gitlab", state)


@app.get("/auth/gitlab/callback")
async def gitlab_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db),
):
    if error:
        raise HTTPException(400, f"GitLab error: {error}")
    if not code:
        raise HTTPException(400, "Authorization code missing")
    _verify_state(request, "gitlab", state)

    cid = _require(GITLAB_CLIENT_ID, "GITLAB_CLIENT_ID")
    sec = _require(GITLAB_CLIENT_SECRET, "GITLAB_CLIENT_SECRET")
    uri = _require(GITLAB_REDIRECT_URI, "GITLAB_REDIRECT_URI")

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        token_res = await client.post(
            f"{GITLAB_BASE_URL}/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": cid,
                "client_secret": sec,
                "redirect_uri": uri,
            },
            headers={"Accept": "application/json"},
        )
        if token_res.status_code != 200:
            raise HTTPException(401, f"GitLab token failed: {token_res.text}")
        access_token = token_res.json().get("access_token")

        user_res = await client.get(
            f"{GITLAB_BASE_URL}/api/v4/user",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if user_res.status_code != 200:
            raise HTTPException(400, f"GitLab user failed: {user_res.text}")
        user_data = user_res.json()

    email = user_data.get("email") or user_data.get("public_email")
    if not email:
        raise HTTPException(400, "GitLab did not return an email")

    name = user_data.get("name") or user_data.get("username") or email.split("@")[0]
    gitlab_id = str(user_data.get("id")) if user_data.get("id") else None

    user = _upsert_user(
        db,
        email=email,
        name=name,
        provider="gitlab",
        provider_id=gitlab_id,
    )
    return _issue_session(user, "gitlab")


# ============================================================
# LinkedIn OAuth
# ============================================================
@app.get("/auth/linkedin/login")
def linkedin_login():
    cid = _require(LINKEDIN_CLIENT_ID, "LINKEDIN_CLIENT_ID")
    uri = _require(LINKEDIN_REDIRECT_URI, "LINKEDIN_REDIRECT_URI")
    state = secrets.token_urlsafe(32)
    params = {
        "response_type": "code",
        "client_id": cid,
        "redirect_uri": uri,
        "state": state,
        "scope": "openid profile email",
    }
    url = "https://www.linkedin.com/oauth/v2/authorization?" + urlencode(params)
    return _redirect_with_state(url, "linkedin", state)


@app.get("/auth/linkedin/callback")
async def linkedin_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db),
):
    if error:
        raise HTTPException(400, f"LinkedIn error: {error}")
    if not code:
        raise HTTPException(400, "Authorization code missing")
    _verify_state(request, "linkedin", state)

    cid = _require(LINKEDIN_CLIENT_ID, "LINKEDIN_CLIENT_ID")
    sec = _require(LINKEDIN_CLIENT_SECRET, "LINKEDIN_CLIENT_SECRET")
    uri = _require(LINKEDIN_REDIRECT_URI, "LINKEDIN_REDIRECT_URI")

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        token_res = await client.post(
            "https://www.linkedin.com/oauth/v2/accessToken",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": uri,
                "client_id": cid,
                "client_secret": sec,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if token_res.status_code != 200:
            raise HTTPException(401, f"LinkedIn token failed: {token_res.text}")
        access_token = token_res.json().get("access_token")

        info_res = await client.get(
            "https://api.linkedin.com/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if info_res.status_code != 200:
            raise HTTPException(400, f"LinkedIn userinfo failed: {info_res.text}")
        info = info_res.json()

    email = info.get("email")
    if not email:
        raise HTTPException(400, "LinkedIn did not return email")

    user = _upsert_user(
        db,
        email=email,
        name=info.get("name"),
        provider="linkedin",
        provider_id=info.get("sub"),
    )
    return _issue_session(user, "linkedin")


# ============================================================
# Facebook OAuth
# ============================================================
@app.get("/auth/facebook/login")
def facebook_login():
    cid = _require(FACEBOOK_CLIENT_ID, "FACEBOOK_CLIENT_ID")
    uri = _require(FACEBOOK_REDIRECT_URI, "FACEBOOK_REDIRECT_URI")
    state = secrets.token_urlsafe(32)
    params = {
        "client_id": cid,
        "redirect_uri": uri,
        "state": state,
        "scope": "email,public_profile",
        "response_type": "code",
    }
    url = "https://www.facebook.com/v18.0/dialog/oauth?" + urlencode(params)
    return _redirect_with_state(url, "facebook", state)


@app.get("/auth/facebook/callback")
async def facebook_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db),
):
    if error:
        raise HTTPException(400, f"Facebook error: {error}")
    if not code:
        raise HTTPException(400, "Authorization code missing")
    _verify_state(request, "facebook", state)

    cid = _require(FACEBOOK_CLIENT_ID, "FACEBOOK_CLIENT_ID")
    sec = _require(FACEBOOK_CLIENT_SECRET, "FACEBOOK_CLIENT_SECRET")
    uri = _require(FACEBOOK_REDIRECT_URI, "FACEBOOK_REDIRECT_URI")

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        token_res = await client.get(
            "https://graph.facebook.com/v18.0/oauth/access_token",
            params={
                "client_id": cid,
                "client_secret": sec,
                "redirect_uri": uri,
                "code": code,
            },
        )
        if token_res.status_code != 200:
            raise HTTPException(400, f"Facebook token failed: {token_res.text}")
        access_token = token_res.json().get("access_token")

        user_res = await client.get(
            "https://graph.facebook.com/v18.0/me",
            params={"fields": "id,name,email", "access_token": access_token},
        )
        if user_res.status_code != 200:
            raise HTTPException(400, f"Facebook user failed: {user_res.text}")
        info = user_res.json()

    fb_id = str(info.get("id") or "")
    email = info.get("email") or f"{fb_id}@facebook-user.local"
    name = info.get("name") or "Facebook User"

    user = _upsert_user(
        db,
        email=email,
        name=name,
        provider="facebook",
        provider_id=fb_id or None,
    )
    return _issue_session(user, "facebook")