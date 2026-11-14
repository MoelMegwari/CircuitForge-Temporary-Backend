import os
import secrets
from contextlib import asynccontextmanager
from urllib.parse import urlencode

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from database import SessionLocal, User, init_db

# ============================================================
# إعدادات (قيم افتراضية تحافظ على السلوك الشغّال)
# ============================================================
FRONTEND_URL  = os.getenv("FRONTEND_URL", "https://misrpcbplceditor.vercel.app").rstrip("/")
EDITOR_PATH   = os.getenv("EDITOR_PATH", "/editor")   # اجعلها "" لو تطبيقك بلا /editor
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"

# LinkedIn
LINKEDIN_CLIENT_ID     = os.getenv("LINKEDIN_CLIENT_ID", "788auwtd0set09")
LINKEDIN_CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET", "WPL_AP1.Bbmma9ynZ5LIV23T.dUAy7w==")
LINKEDIN_REDIRECT_URI  = os.getenv(
    "REDIRECT_URI",
    "https://web-production-598c28d9.up.railway.app/auth/linkedin/callback",
)

# GitHub
GITHUB_CLIENT_ID     = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_REDIRECT_URI  = os.getenv(
    "GITHUB_REDIRECT_URI",
    "https://web-production-598c28d9.up.railway.app/auth/github/callback",
)

# Facebook
FACEBOOK_CLIENT_ID     = os.getenv("CLIENT_ID") or os.getenv("FACEBOOK_CLIENT_ID")
FACEBOOK_CLIENT_SECRET = os.getenv("CLIENT_SECRET") or os.getenv("FACEBOOK_CLIENT_SECRET")
FACEBOOK_REDIRECT_URI  = os.getenv("CALLBACK_URL") or os.getenv(
    "FACEBOOK_REDIRECT_URI",
    "https://web-production-598c28d9.up.railway.app/auth/facebook/callback",
)

HTTP_TIMEOUT = httpx.Timeout(15.0, connect=10.0)


# ============================================================
# Lifespan + App
# ============================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="CircuitForge Auth API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
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


def _require(value, name: str) -> str:
    if not value:
        raise HTTPException(status_code=500, detail=f"{name} is not configured")
    return value


def _state_cookie_name(provider: str) -> str:
    return f"oauth_state_{provider}"


def _redirect_with_state(auth_url: str, provider: str, state: str) -> RedirectResponse:
    """توجيه إلى المزوّد + تعيين كوكي الحالة (CSRF protection)."""
    response = RedirectResponse(url=auth_url)
    response.set_cookie(
        key=_state_cookie_name(provider),
        value=state,
        max_age=600,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
    )
    return response


def _verify_state(request: Request, provider: str, received_state: str | None) -> None:
    cookie_state = request.cookies.get(_state_cookie_name(provider))
    if not cookie_state or not received_state:
        raise HTTPException(status_code=400, detail="Missing OAuth state")
    if not secrets.compare_digest(cookie_state, received_state):
        raise HTTPException(status_code=400, detail="Invalid OAuth state")


def _frontend_redirect(email: str, name: str) -> RedirectResponse:
    """توجيه آمن إلى الواجهة مع URL-encoding صحيح."""
    query = urlencode({"email": email, "name": name or ""})
    return RedirectResponse(url=f"{FRONTEND_URL}{EDITOR_PATH}?{query}")


def _upsert_user(db: Session, *, email: str, name: str | None,
                 provider: str, provider_id: str | None) -> User:
    """إدراج/تحديث المستخدم مع ربط الـ provider_id."""
    db_user = db.query(User).filter(User.email == email).first()
    id_field = f"{provider}_id"

    if db_user is None:
        db_user = User(email=email, name=name or email.split("@")[0])
        setattr(db_user, id_field, provider_id)
        db.add(db_user)
    else:
        if name and not db_user.name:
            db_user.name = name
        if provider_id and getattr(db_user, id_field) is None:
            setattr(db_user, id_field, provider_id)

    db.commit()
    db.refresh(db_user)
    return db_user


# ============================================================
# Basic
# ============================================================
@app.get("/")
def root():
    return {"message": "CircuitForge Auth API is running"}


@app.get("/health")
def health():
    return {"status": "healthy"}


# ============================================================
# LinkedIn OAuth
# ============================================================
@app.get("/auth/linkedin/login")
def linkedin_login():
    client_id    = _require(LINKEDIN_CLIENT_ID, "LINKEDIN_CLIENT_ID")
    redirect_uri = _require(LINKEDIN_REDIRECT_URI, "REDIRECT_URI")

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
    db: Session = Depends(get_db),
):
    if error:
        raise HTTPException(status_code=400, detail=f"LinkedIn error: {error}")
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code missing")

    _verify_state(request, "linkedin", state)

    client_id     = _require(LINKEDIN_CLIENT_ID, "LINKEDIN_CLIENT_ID")
    client_secret = _require(LINKEDIN_CLIENT_SECRET, "LINKEDIN_CLIENT_SECRET")
    redirect_uri  = _require(LINKEDIN_REDIRECT_URI, "REDIRECT_URI")

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
            raise HTTPException(status_code=401, detail=f"Token exchange failed: {token_res.text}")

        access_token = token_res.json().get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="No access_token returned by LinkedIn")

        user_res = await client.get(
            "https://api.linkedin.com/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if user_res.status_code != 200:
            raise HTTPException(status_code=400, detail=f"Userinfo failed: {user_res.text}")
        info = user_res.json()

    email = info.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="LinkedIn did not return an email")

    _upsert_user(db, email=email, name=info.get("name"),
                 provider="linkedin", provider_id=info.get("sub"))
    return _frontend_redirect(email, info.get("name") or "")


# ============================================================
# GitHub OAuth  ⭐ جديد
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
    db: Session = Depends(get_db),
):
    if error:
        raise HTTPException(status_code=400, detail=f"GitHub error: {error}")
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code missing")

    _verify_state(request, "github", state)

    client_id     = _require(GITHUB_CLIENT_ID, "GITHUB_CLIENT_ID")
    client_secret = _require(GITHUB_CLIENT_SECRET, "GITHUB_CLIENT_SECRET")
    redirect_uri  = _require(GITHUB_REDIRECT_URI, "GITHUB_REDIRECT_URI")

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        # 1) تبديل الكود بـ access_token
        token_res = await client.post(
            "https://github.com/login/oauth/access_token",
            json={
                "client_id":     client_id,
                "client_secret": client_secret,
                "code":          code,
                "redirect_uri":  redirect_uri,
            },
            headers={"Accept": "application/json"},
        )
        if token_res.status_code != 200:
            raise HTTPException(status_code=401, detail=f"GitHub token failed: {token_res.text}")

        access_token = token_res.json().get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="No access_token returned by GitHub")

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept":        "application/json",
        }

        # 2) جلب المستخدم
        user_res = await client.get("https://api.github.com/user", headers=headers)
        if user_res.status_code != 200:
            raise HTTPException(status_code=400, detail=f"GitHub user failed: {user_res.text}")
        user_data = user_res.json()

        # 3) البريد (قد يكون مخفياً — نستخدم /user/emails)
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

    _upsert_user(db, email=email, name=name,
                 provider="github", provider_id=provider_id)
    return _frontend_redirect(email, name)


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
    db: Session = Depends(get_db),
):
    if error:
        raise HTTPException(status_code=400, detail=f"Facebook error: {error}")
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code missing")

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
            raise HTTPException(status_code=400, detail=f"Facebook token failed: {token_res.text}")

        access_token = token_res.json().get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="No access_token returned by Facebook")

        user_res = await client.get(
            "https://graph.facebook.com/v18.0/me",
            params={"fields": "id,name,email", "access_token": access_token},
        )
        if user_res.status_code != 200:
            raise HTTPException(status_code=400, detail=f"Facebook profile failed: {user_res.text}")
        info = user_res.json()

    fb_id = str(info.get("id") or "")
    email = info.get("email") or f"{fb_id}@facebook-user.local"
    name  = info.get("name") or "Facebook User"

    _upsert_user(db, email=email, name=name,
                 provider="facebook", provider_id=fb_id or None)
    return _frontend_redirect(email, name)