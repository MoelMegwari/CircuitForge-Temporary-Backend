import os
import requests
import httpx
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from database import SessionLocal, User, init_db

app = FastAPI(title="CircuitForge Temporary API")

ALLOWED_ORIGINS = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if ALLOWED_ORIGINS == ["*"] else ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    init_db()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

LINKEDIN_CLIENT_ID = os.getenv("LINKEDIN_CLIENT_ID", "788auwtd0set09")
LINKEDIN_CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET", "WPL_AP1.Bbmma9ynZ5LIV23T.dUAy7w==")
REDIRECT_URI = os.getenv("REDIRECT_URI", "https://web-production-598c28d9.up.railway.app/auth/linkedin/callback")

FACEBOOK_CLIENT_ID = os.getenv("CLIENT_ID")
FACEBOOK_CLIENT_SECRET = os.getenv("CLIENT_SECRET")
FACEBOOK_REDIRECT_URI = os.getenv("CALLBACK_URL", "https://web-production-598c28d9.up.railway.app/auth/facebook/callback")

@app.get("/")
def root():
    return {"message": "CircuitForge Temporary API is running"}

@app.get("/health")
def health():
    return {"status": "healthy"}

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
def linkedin_callback(code: str = None, error: str = None, db: Session = Depends(get_db)):
    if error or not code:
        raise HTTPException(status_code=400, detail=f"Auth error: {error} or code missing")

    try:
        token_res = requests.post(
            "https://www.linkedin.com/oauth/v2/accessToken",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": LINKEDIN_CLIENT_ID,
                "client_secret": LINKEDIN_CLIENT_SECRET,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        
        if token_res.status_code != 200:
            raise HTTPException(status_code=401, detail=f"Token failed: {token_res.text}")
        
        access_token = token_res.json().get("access_token")

        user_res = requests.get(
            "https://api.linkedin.com/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        if user_res.status_code != 200:
            raise HTTPException(status_code=400, detail=f"Userinfo failed: {user_res.text}")
        
        user_info = user_res.json()
        email = user_info.get("email")
        name = user_info.get("name")
        linkedin_id = user_info.get("sub")

        if not email:
            raise HTTPException(status_code=400, detail="Email not provided by LinkedIn profile.")

        db_user = db.query(User).filter(User.email == email).first()
        if not db_user:
            db_user = User(linkedin_id=linkedin_id, name=name, email=email)
            db.add(db_user)
            db.commit()
            db.refresh(db_user)

        # ✅ التعديل: تم استبدال الرابط القديم بالجديد
        frontend_editor_url = f"https://misrpcbplceditor.vercel.app?email={email}&name={name}"
        return RedirectResponse(url=frontend_editor_url)

    except Exception as e:
        print(f"CRITICAL ERROR IN CALLBACK: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/auth/facebook/login")
def facebook_login():
    if not FACEBOOK_CLIENT_ID:
        raise HTTPException(status_code=500, detail="Facebook Client ID is not configured")
    
    scope = "email,public_profile"
    state = "random_facebook_secure_state"
    
    auth_url = (
        f"https://www.facebook.com/v18.0/dialog/oauth"
        f"?client_id={FACEBOOK_CLIENT_ID}"
        f"&redirect_uri={FACEBOOK_REDIRECT_URI}"
        f"&state={state}"
        f"&scope={scope}"
    )
    return RedirectResponse(url=auth_url)

@app.get("/auth/facebook/callback")
async def facebook_callback(code: str = None, error: str = None):
    if error:
        raise HTTPException(status_code=400, detail=f"Facebook Auth Error: {error}")
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code not found")

    token_url = "https://graph.facebook.com/v18.0/oauth/access_token"
    params = {
        "client_id": FACEBOOK_CLIENT_ID,
        "client_secret": FACEBOOK_CLIENT_SECRET,
        "redirect_uri": FACEBOOK_REDIRECT_URI,
        "code": code
    }
    
    async with httpx.AsyncClient() as client:
        token_response = await client.get(token_url, params=params)
        if token_response.status_code != 200:
            raise HTTPException(status_code=400, detail=f"Failed to fetch Facebook token: {token_response.text}")
        
        token_data = token_response.json()
        access_token = token_data.get("access_token")

        userinfo_url = "https://graph.facebook.com/v18.0/me"
        user_params = {
            "fields": "id,name,email",
            "access_token": access_token
        }
        
        user_response = await client.get(userinfo_url, params=user_params)
        if user_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch Facebook user profile")
        
        user_info = user_response.json()

    return {
        "status": "success",
        "message": "Facebook authentication successful",
        "user_profile": user_info
}