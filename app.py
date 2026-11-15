import os
import secrets
from contextlib import asynccontextmanager
from urllib.parse import urlencode

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from database import SessionLocal, User, init_db

# ============================================================
# إعدادات عامة
# ============================================================
FRONTEND_URL  = os.getenv("FRONTEND_URL", "https://misrpcbplceditor.vercel.app").rstrip("/")
EDITOR_PATH   = os.getenv("EDITOR_PATH", "/editor")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"

# samesite=lax يعمل عبر Vercel proxy. لو رجعت للاتصال المباشر استخدم "none"
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax").lower()
if COOKIE_SAMESITE not in ("lax", "strict", "none"):
    COOKIE_SAMESITE = "lax"

# ============================================================
# إعدادات الجلسة
# ============================================================
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_urlsafe(48)
    print("⚠️  WARNING: SECRET_KEY not set — using random. Sessions reset on restart!")

SESSION_COOKIE   = "cf_session"
SESSION_MAX_AGE  = 60 * 60 * 24 * 7  # 7 أيام
serializer = URLSafeTimedSerializer(SECRET_KEY, salt="cf-session-v1")

# ============================================================
# Google OAuth
# ============================================================
GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI  = os.getenv(
    "GOOGLE_REDIRECT_URI",
    f"{FRONTEND_URL}/auth/google/callback",
)

# ============================================================
# LinkedIn OAuth
# ============================================================
LINKEDIN_CLIENT_ID     = os.getenv("LINKEDIN_CLIENT_ID", "788auwtd0set09")
LINKEDIN_CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET")
LINKEDIN_REDIRECT_URI  = os.getenv(
    "LINKEDIN_REDIRECT_URI",
    os.getenv("REDIRECT_URI", f"{FRONTEND_URL}/auth/linkedin/callback"),
)

# ============================================================
# GitHub OAuth
# ============================================================
GITHUB_CLIENT_ID     = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_REDIRECT_URI  = os.getenv(
    "GITHUB_REDIRECT_URI",
    f"{FRONTEND_URL}/auth/github/callback",
)

# ============================================================
# GitLab OAuth
# ============================================================
GITLAB_CLIENT_ID     = os.getenv("GITLAB_CLIENT_ID")
GITLAB_CLIENT_SECRET = os.getenv("GITLAB_CLIENT_SECRET")
GITLAB_REDIRECT_URI  = os.getenv(
    "GITLAB_REDIRECT_URI",
    f"{FRONTEND_URL}/auth/gitlab/callback",
)
GITLAB_BASE_URL = os.getenv("GITLAB_BASE_URL", "https://gitlab.com").rstrip("/")

# ============================================================
# Facebook OAuth
# ============================================================
FACEBOOK_CLIENT_ID     = os.getenv("CLIENT_ID") or os.getenv("FACEBOOK_CLIENT_ID")
FACEBOOK_CLIENT_SECRET = os.getenv("CLIENT_SECRET") or os.getenv("FACEBOOK_CLIENT_SECRET")
FACEBOOK_REDIRECT_URI  = os.getenv("CALLBACK_URL") or os.getenv(
    "FACEBOOK_REDIRECT_URI",
    f"{FRONTEND_URL}/auth/facebook/callback",
)

HTTP_TIMEOUT = httpx.Timeout(15.0, connect=10.0)


# ============================================================
# Lifespan + App + Exception Handlers
# ============================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="CircuitForge Auth API", lifespan=lifespan)

# عبر Vercel proxy كل شيء same-origin، لذلك allow_credentials=False كافٍ وآمن
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.exception_handler(IntegrityError)
async def integrity_error_handler(request: Request, exc: IntegrityError):
    return JSONResponse(
        status_code=400,
        content={"detail": "Database conflict: This email or account is already linked to another provider."},
    )


@app.exception_handler(httpx.RequestError)
async def httpx_error_handler(request: Request, exc: httpx.RequestError):
    return JSONResponse(
        status_code=502,
        content={"detail": f"External provider network error: {str(exc)}"},
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


def _require(value, name: str) -> str:
    if not value:
        raise HTTPException(status_code=500, detail=f"{name} is not configured")
    return value


def _state_cookie_name(provider: str) -> str:
    return f"oauth_state_{provider}"


def _redirect_with_state(auth_url: str, provider: str, state: str) -> RedirectResponse:
    response = RedirectResponse(url=auth_url)
    response.set_cookie(
        key=_state_cookie_name(provider),
        value=state,
        max_age=600,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/",
    )
    return response


def _verify_state(request: Request, provider: str, received_state: str | None) -> None:
    cookie_state = request.cookies.get(_state_cookie_name(provider))
    if not cookie_state or not received_state:
        raise HTTPException(status_code=400, detail=f"[{provider}] Missing OAuth state")
    if not secrets.compare_digest(cookie_state, received_state):
        raise HTTPException(status_code=400, detail=f"[{provider}] Invalid OAuth state")


def _issue_session(user: User, provider: str) -> RedirectResponse:
    """إنشاء جلسة آمنة + توجيه إلى الواجهة (بلا بيانات حساسة في URL)."""
    token = serializer.dumps({"uid": user.id, "email": user.email})
    response = RedirectResponse(url=f"{FRONTEND_URL}{EDITOR_PATH}")
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/",
    )
    # احذف كوكي الحالة
    response.delete_cookie(_state_cookie_name(provider), path="/")
    return response


def _read_session(request: Request) -> dict:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        return serializer.loads(token, max_age=SESSION_MAX_AGE)
    except SignatureExpired:
        raise HTTPException(status_code=401, detail="Session expired")
    except BadSignature:
        raise HTTPException(status_code=401, detail="Invalid session")


def _assert_provider_unique(db: Session, *, provider: str, provider_id: str | None, email: str) -> None:
    """يمنع ربط نفس حساب المزود بأكثر من مستخدم (لأنه لا يوجد unique constraint في DB)."""
    if not provider_id:
        return
    id_field = f"{provider}_id"
    if not hasattr(User, id_field):
        return
    conflict = db.query(User).filter(getattr(User, id_field) == provider_id).first()
    if conflict and conflict.email != email:
        raise HTTPException(
            status_code=400,
            detail=f"[{provider}] This account is already linked to another user.",
        )


def _upsert_user(db: Session, *, email: str, name: str | None,
                 provider: str, provider_id: str | None) -> User:
    """إدراج/تحديث المستخدم مع التعامل المرن مع الـ provider_id."""
    db_user = db.query(User).filter(User.email == email).first()
    id_field = f"{provider}_id"

    if db_user is None:
        db_user = User(email=email, name=name or email.split("@")[0])
        if provider_id and hasattr(db_user, id_field):
            setattr(db_user, id_field, provider_id)
        db.add(db_user)
    else:
        if name and not db_user.name:
            db_user.name = name
        if provider_id and hasattr(db_user, id_field) and getattr(db_user, id_field) is None:
            setattr(db_user, id_field, provider_id)

    db.commit()
    db.refresh(db_user)
    return db_user


# ============================================================
# Basic
# ============================================================
@app.get("/")
def root():
    return {"message": "CircuitForge Auth API is running", "status": "ok"}


@app.get("/health")
def health():
    return {"status": "healthy"}


# ============================================================
# Session endpoints (جديد)
# ============================================================
@app.get("/api/auth/me")
def auth_me(request: Request, db: Session = Depends(get_db)):
    data = _read_session(request)
    user = db.query(User).filter(User.id == data["uid"]).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "google_id":   getattr(user, "google_id", None),
        "github_id":   getattr(user, "github_id", None),
        "gitlab_id":   getattr(user, "gitlab_id", None),
        "linkedin_id": getattr(user, "linkedin_id", None),
        "facebook_id": getattr(user, "facebook_id", None),
    }


@app.post("/api/auth/logout")
def auth_logout():
    resp = JSONResponse(content={"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


# ============================================================
# Google OAuth
# ============================================================
@app.get("/auth/google/login")
def google_login():
    client_id    = _require(GOOGLE_CLIENT_ID, "GOOGLE_CLIENT_ID")
    redirect_uri = _require(GOOGLE_REDIRECT_URI, "GOOGLE_REDIRECT_URI")

    state = secrets.token_urlsafe(32)
    params = {
        "client_id":     client_id,
        "redirect_uri":  redirect_uri,
        "response_type": "code",
        "scope":         "openid email profile",
        "state":         state,
        "access_type":   "online",
        "prompt":        "select_account",
    }
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
    return _redirect_with_state(auth_url, "google", state)


@app.get("/auth/google/callback")
async def google_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    db: Session = Depends(get_db),
):
    if error:
        raise HTTPException(status_code=400, detail=f"[google] {error}: {error_description or ''}")
    if not code:
        raise HTTPException(status_code=400, detail="[google] Authorization code missing")

    _verify_state(request, "google", state)

    client_id     = _require(GOOGLE_CLIENT_ID, "GOOGLE_CLIENT_ID")
    client_secret = _require(GOOGLE_CLIENT_SECRET, "GOOGLE_CLIENT_SECRET")
    redirect_uri  = _require(GOOGLE_REDIRECT_URI, "GOOGLE_REDIRECT_URI")

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        token_res = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code":          code,
                "client_id":     client_id,
                "client_secret": client_secret,
                "redirect_uri":  redirect_uri,
                "grant_type":    "authorization_code",
            },
        )
        if token_res.status_code != 200:
            raise HTTPException(status_code=401, detail=f"[google] token failed: {token_res.text}")

        access_token = token_res.json().get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail=f"[google] no access_token: {token_res.text}")

        info_res = await client.get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if info_res.status_code != 200:
            raise HTTPException(status_code=400, detail=f"[google] userinfo failed: {info_res.text}")
        info = info_res.json()

    email = info.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="[google] no email returned")

    google_sub = str(info.get("sub") or "")
    if not google_sub:
        raise HTTPException(status_code=400, detail="[google] no subject identifier returned")

    _assert_provider_unique(db, provider="google", provider_id=google_sub, email=email)
    user = _upsert_user(db, email=email, name=info.get("name"),
                        provider="google", provider_id=google_sub)
    return _issue_session(user, "google")


# ============================================================
# LinkedIn OAuth
# ============================================================
@app.get("/auth/linkedin/login")
def linkedin_login():
    client_id    = _require(LINKEDIN_CLIENT_ID, "LINKEDIN_CLIENT_ID")
    redirect_uri = _require(LINKEDIN_REDIRECT_URI, "LINKEDIN_REDIRECT_URI")

    state = secrets.token_urlsafe(32)
    params = {
        "response_type": "code",
        "client_id":     client_id,
        "redirect_uri":  redirect_uri,
        "state":         state,
        "scope":         "openid profile email",
    }
    auth_url = "https://www.linkedin.com/oauth/v2/authorization?" + urlencode(params)
    return _redirect_with_state(auth_url, "linkedin", state)


@app.get("/auth/linkedin/callback")
async def linkedin_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    db: Session = Depends(get_db),
):
    if error:
        raise HTTPException(status_code=400, detail=f"[linkedin] {error}: {error_description or ''}")
    if not code:
        raise HTTPException(status_code=400, detail="[linkedin] Authorization code missing")

    _verify_state(request, "linkedin", state)

    client_id     = _require(LINKEDIN_CLIENT_ID, "LINKEDIN_CLIENT_ID")
    client_secret = _require(LINKEDIN_CLIENT_SECRET, "LINKEDIN_CLIENT_SECRET")
    redirect_uri  = _require(LINKEDIN_REDIRECT_URI, "LINKEDIN_REDIRECT_URI")

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        token_res = await client.post(
            "https://www.linkedin.com/oauth/v2/accessToken",
            data={
                "grant_type":    "authorization_code",
                "code":          code,
                "redirect_uri":  redirect_uri,
                "client_id":     client_id,
                "client_secret": client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if token_res.status_code != 200:
            raise HTTPException(status_code=401,
                                detail=f"[linkedin] token exchange failed ({token_res.status_code}): {token_res.text}")

        access_token = token_res.json().get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail=f"[linkedin] no access_token: {token_res.text}")

        user_res = await client.get(
            "https://api.linkedin.com/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if user_res.status_code != 200:
            raise HTTPException(status_code=400, detail=f"[linkedin] userinfo failed: {user_res.text}")
        info = user_res.json()

    email = info.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="[linkedin] no email returned")

    linkedin_sub = str(info.get("sub") or "")
    if not linkedin_sub:
        raise HTTPException(status_code=400, detail="[linkedin] no subject identifier returned")

    _assert_provider_unique(db, provider="linkedin", provider_id=linkedin_sub, email=email)
    user = _upsert_user(db, email=email, name=info.get("name"),
                        provider="linkedin", provider_id=linkedin_sub)
    return _issue_session(user, "linkedin")


# ============================================================
# GitHub OAuth
# ============================================================
@app.get("/auth/github/login")
def github_login():
    client_id    = _require(GITHUB_CLIENT_ID, "GITHUB_CLIENT_ID")
    redirect_uri = _require(GITHUB_REDIRECT_URI, "GITHUB_REDIRECT_URI")

    state = secrets.token_urlsafe(32)
    params = {
        "client_id":    client_id,
        "redirect_uri": redirect_uri,
        "scope":        "user:email",
        "state":        state,
        "allow_signup": "true",
    }
    auth_url = "https://github.com/login/oauth/authorize?" + urlencode(params)
    return _redirect_with_state(auth_url, "github", state)


@app.get("/auth/github/callback")
async def github_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    db: Session = Depends(get_db),
):
    if error:
        raise HTTPException(status_code=400, detail=f"[github] {error}: {error_description or ''}")
    if not code:
        raise HTTPException(status_code=400, detail="[github] Authorization code missing")

    _verify_state(request, "github", state)

    client_id     = _require(GITHUB_CLIENT_ID, "GITHUB_CLIENT_ID")
    client_secret = _require(GITHUB_CLIENT_SECRET, "GITHUB_CLIENT_SECRET")
    redirect_uri  = _require(GITHUB_REDIRECT_URI, "GITHUB_REDIRECT_URI")

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        token_res = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id":     client_id,
                "client_secret": client_secret,
                "code":          code,
                "redirect_uri":  redirect_uri,
            },
            headers={
                "Accept":       "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        if token_res.status_code != 200:
            raise HTTPException(status_code=401,
                                detail=f"[github] token endpoint returned {token_res.status_code}: {token_res.text}")

        try:
            token_data = token_res.json()
        except Exception:
            raise HTTPException(status_code=401, detail=f"[github] invalid JSON response: {token_res.text}")

        if token_data.get("error"):
            raise HTTPException(status_code=401,
                                detail=f"[github] {token_data.get('error')} - {token_data.get('error_description', '')}")

        access_token = token_data.get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail=f"[github] no access_token returned: {token_data}")

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept":        "application/json",
        }

        user_res = await client.get("https://api.github.com/user", headers=headers)
        if user_res.status_code != 200:
            raise HTTPException(status_code=400, detail=f"[github] user failed: {user_res.text}")
        user_data = user_res.json()

        email = user_data.get("email")
        if not email:
            emails_res = await client.get("https://api.github.com/user/emails", headers=headers)
            if emails_res.status_code == 200:
                emails = emails_res.json()
                for entry in emails:
                    if entry.get("primary") and entry.get("verified"):
                        email = entry["email"]
                        break
                if not email and emails:
                    email = emails[0].get("email")

    if not email:
        email = f"{user_data.get('id')}@users.noreply.github.com"

    name = user_data.get("name") or user_data.get("login") or email.split("@")[0]
    provider_id = str(user_data.get("id")) if user_data.get("id") else None

    _assert_provider_unique(db, provider="github", provider_id=provider_id, email=email)
    user = _upsert_user(db, email=email, name=name,
                        provider="github", provider_id=provider_id)
    return _issue_session(user, "github")


# ============================================================
# GitLab OAuth
# ============================================================
@app.get("/auth/gitlab/login")
def gitlab_login():
    client_id    = _require(GITLAB_CLIENT_ID, "GITLAB_CLIENT_ID")
    redirect_uri = _require(GITLAB_REDIRECT_URI, "GITLAB_REDIRECT_URI")

    state = secrets.token_urlsafe(32)
    params = {
        "client_id":     client_id,
        "redirect_uri":  redirect_uri,
        "response_type": "code",
        "state":         state,
        "scope":         "read_user",
    }
    auth_url = f"{GITLAB_BASE_URL}/oauth/authorize?" + urlencode(params)
    return _redirect_with_state(auth_url, "gitlab", state)


@app.get("/auth/gitlab/callback")
async def gitlab_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    db: Session = Depends(get_db),
):
    if error:
        raise HTTPException(status_code=400, detail=f"[gitlab] {error}: {error_description or ''}")
    if not code:
        raise HTTPException(status_code=400, detail="[gitlab] Authorization code missing")

    _verify_state(request, "gitlab", state)

    client_id     = _require(GITLAB_CLIENT_ID, "GITLAB_CLIENT_ID")
    client_secret = _require(GITLAB_CLIENT_SECRET, "GITLAB_CLIENT_SECRET")
    redirect_uri  = _require(GITLAB_REDIRECT_URI, "GITLAB_REDIRECT_URI")

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        token_res = await client.post(
            f"{GITLAB_BASE_URL}/oauth/token",
            data={
                "grant_type":    "authorization_code",
                "code":          code,
                "client_id":     client_id,
                "client_secret": client_secret,
                "redirect_uri":  redirect_uri,
            },
            headers={"Accept": "application/json"},
        )
        if token_res.status_code != 200:
            raise HTTPException(status_code=401, detail=f"[gitlab] token failed: {token_res.text}")

        access_token = token_res.json().get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail=f"[gitlab] no access_token: {token_res.text}")

        user_res = await client.get(
            f"{GITLAB_BASE_URL}/api/v4/user",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if user_res.status_code != 200:
            raise HTTPException(status_code=400, detail=f"[gitlab] user failed: {user_res.text}")
        user_data = user_res.json()

    email = user_data.get("email") or user_data.get("public_email")
    if not email:
        raise HTTPException(status_code=400, detail="[gitlab] no email returned")

    name = user_data.get("name") or user_data.get("username") or email.split("@")[0]
    provider_id = str(user_data.get("id")) if user_data.get("id") else None

    _assert_provider_unique(db, provider="gitlab", provider_id=provider_id, email=email)
    user = _upsert_user(db, email=email, name=name,
                        provider="gitlab", provider_id=provider_id)
    return _issue_session(user, "gitlab")


# ============================================================
# Facebook OAuth
# ============================================================
@app.get("/auth/facebook/login")
def facebook_login():
    client_id    = _require(FACEBOOK_CLIENT_ID, "FACEBOOK_CLIENT_ID")
    redirect_uri = _require(FACEBOOK_REDIRECT_URI, "FACEBOOK_REDIRECT_URI")

    state = secrets.token_urlsafe(32)
    params = {
        "client_id":     client_id,
        "redirect_uri":  redirect_uri,
        "state":         state,
        "scope":         "email,public_profile",
        "response_type": "code",
    }
    auth_url = "https://www.facebook.com/v18.0/dialog/oauth?" + urlencode(params)
    return _redirect_with_state(auth_url, "facebook", state)


@app.get("/auth/facebook/callback")
async def facebook_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    db: Session = Depends(get_db),
):
    if error:
        raise HTTPException(status_code=400, detail=f"[facebook] {error}: {error_description or ''}")
    if not code:
        raise HTTPException(status_code=400, detail="[facebook] Authorization code missing")

    _verify_state(request, "facebook", state)

    client_id     = _require(FACEBOOK_CLIENT_ID, "FACEBOOK_CLIENT_ID")
    client_secret = _require(FACEBOOK_CLIENT_SECRET, "FACEBOOK_CLIENT_SECRET")
    redirect_uri  = _require(FACEBOOK_REDIRECT_URI, "FACEBOOK_REDIRECT_URI")

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        token_res = await client.get(
            "https://graph.facebook.com/v18.0/oauth/access_token",
            params={
                "client_id":     client_id,
                "client_secret": client_secret,
                "redirect_uri":  redirect_uri,
                "code":          code,
            },
        )
        if token_res.status_code != 200:
            raise HTTPException(status_code=400, detail=f"[facebook] token failed: {token_res.text}")

        access_token = token_res.json().get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail=f"[facebook] no access_token: {token_res.text}")

        user_res = await client.get(
            "https://graph.facebook.com/v18.0/me",
            params={"fields": "id,name,email", "access_token": access_token},
        )
        if user_res.status_code != 200:
            raise HTTPException(status_code=400, detail=f"[facebook] profile failed: {user_res.text}")
        info = user_res.json()

    fb_id = str(info.get("id") or "")
    email = info.get("email") or f"{fb_id}@facebook-user.local"
    name  = info.get("name") or "Facebook User"

    _assert_provider_unique(db, provider="facebook", provider_id=fb_id or None, email=email)
    user = _upsert_user(db, email=email, name=name,
                        provider="facebook", provider_id=fb_id or None)
    return _issue_session(user, "facebook")