import os
import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

# 1. إنشاء تطبيق FastAPI أولاً
app = FastAPI(title="CircuitForge Temporary API")

# 2. إعداد الـ CORS Middleware
ALLOWED_ORIGINS = ["*"] # أو يمكنك تعديلها حسب الحاجة
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if ALLOWED_ORIGINS == ["*"] else ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# قراءة المتغيرات البيئية
LINKEDIN_CLIENT_ID = os.getenv("LINKEDIN_CLIENT_ID")
LINKEDIN_CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", "https://web-production-598c28d9.up.railway.app/auth/linkedin/callback")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://web-production-598c28d9.up.railway.app")

# 3. المسارات الأساسية (MVP / Health)
@app.get("/")
def root():
    return {"message": "CircuitForge Temporary API is running"}

@app.get("/health")
def health():
    return {"status": "healthy"}

# 4. مسارات LinkedIn OAuth
@app.get("/auth/linkedin/login")
def linkedin_login():
    if not LINKEDIN_CLIENT_ID:
        raise HTTPException(status_code=500, detail="LinkedIn Client ID is not configured")
    
    scope = "openid profile email"
    state = "random_secure_state_string"
    
    auth_url = (
        f"https://www.linkedin.com/oauth/v2/authorization"
        f"?response_type=code"
        f"&client_id={LINKEDIN_CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&state={state}"
        f"&scope={scope}"
    )
    return RedirectResponse(url=auth_url)

@app.get("/auth/linkedin/callback")
async def linkedin_callback(code: str = None, error: str = None):
    if error:
        raise HTTPException(status_code=400, detail=f"LinkedIn Auth Error: {error}")
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code not found")

    token_url = "https://www.linkedin.com/oauth/v2/token"
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": LINKEDIN_CLIENT_ID,
        "client_secret": LINKEDIN_CLIENT_SECRET,
    }
    
    async with httpx.AsyncClient() as client:
        token_response = await client.post(token_url, data=payload)
        if token_response.status_code != 200:
            raise HTTPException(status_code=400, detail=f"Failed to fetch token: {token_response.text}")
        
        token_data = token_response.json()
        access_token = token_data.get("access_token")

        userinfo_url = "https://api.linkedin.com/v2/userinfo"
        headers = {"Authorization": f"Bearer {access_token}"}
        
        user_response = await client.get(userinfo_url, headers=headers)
        if user_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch user profile")
        
        user_info = user_response.json()

    return {
        "status": "success",
        "message": "LinkedIn authentication successful",
        "user_profile": user_info
    }
