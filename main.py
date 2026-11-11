import os
import httpx
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from jose import jwt
from datetime import datetime, timedelta

# ==========================================
# 1. إعداد قاعدة البيانات (حل مشكلة Railway)
# ==========================================
# Railway توفر متغير DATABASE_URL أو MYSQL_URL تلقائياً
# نستخدم MYSQL_URL أولاً لأنه الرابط العام (Public) الذي يعمل من خارج الشبكة الداخلية
DATABASE_URL = os.getenv("MYSQL_URL") or os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("Database URL is not set. Please set MYSQL_URL or DATABASE_URL in Railway variables.")

# إصلاح بسيط: إذا كان الرابط يبدأ بـ mysql:// (وهو ما تفعله Railway غالباً) 
# نحوله إلى mysql+pymysql:// ليعمل مع SQLAlchemy
if DATABASE_URL.startswith("mysql://"):
    DATABASE_URL = DATABASE_URL.replace("mysql://", "mysql+pymysql://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# تعريف جدول المستخدمين (مثال بسيط، يمكنك تعديله حسب حقولك)
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True)
    name = Column(String(255))
    provider = Column(String(50)) # linkedin أو facebook

# إنشاء الجداول عند بدء التشغيل
Base.metadata.create_all(bind=engine)

# دالة للحصول على جلسة قاعدة البيانات
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==========================================
# 2. إعداد التطبيق والـ CORS
# ==========================================
app = FastAPI(title="CircuitForge Temporary API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # يفضل تعديلها لاحقاً لدومين الفرونت إند فقط
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# 3. متغيرات البيئة
# ==========================================
LINKEDIN_CLIENT_ID = os.getenv("LINKEDIN_CLIENT_ID")
LINKEDIN_CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET")
LINKEDIN_REDIRECT_URI = os.getenv("REDIRECT_URI", "https://web-production-598c28d9.up.railway.app/auth/linkedin/callback")

FACEBOOK_CLIENT_ID = os.getenv("CLIENT_ID")
FACEBOOK_CLIENT_SECRET = os.getenv("CLIENT_SECRET")
FACEBOOK_REDIRECT_URI = os.getenv("CALLBACK_URL", "https://web-production-598c28d9.up.railway.app/auth/facebook/callback")

# رابط الفرونت إند (يجب تعيينه في Railway)
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://your-frontend-domain.up.railway.app")

# مفتاح JWT (يجب تعيينه في Railway)
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-me")
ALGORITHM = "HS256"

# ==========================================
# 4. دوال مساعدة لإنشاء التوكن
# ==========================================
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# ==========================================
# 5. المسارات الأساسية
# ==========================================
@app.get("/")
def root():
    return {"message": "CircuitForge Temporary API is running"}

@app.get("/health")
def health():
    return {"status": "healthy"}

# ==========================================
# 6. مسارات LinkedIn OAuth
# ==========================================
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
        f"&redirect_uri={LINKEDIN_REDIRECT_URI}"
        f"&state={state}"
        f"&scope={scope}"
    )
    return RedirectResponse(url=auth_url)

@app.get("/auth/linkedin/callback")
async def linkedin_callback(code: str = None, error: str = None, db: Session = Depends(get_db)):
    if error:
        raise HTTPException(status_code=400, detail=f"LinkedIn Auth Error: {error}")
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code not found")

    token_url = "https://www.linkedin.com/oauth/v2/token"
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": LINKEDIN_REDIRECT_URI,
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

    # --- حفظ المستخدم في قاعدة البيانات (مثال) ---
    email = user_info.get("email")
    name = user_info.get("name")
    if email:
        db_user = db.query(User).filter(User.email == email).first()
        if not db_user:
            db_user = User(email=email, name=name, provider="linkedin")
            db.add(db_user)
            db.commit()
            db.refresh(db_user)
    
    # --- إنشاء توكن JWT وإعادة التوجيه للفرونت إند ---
    jwt_token = create_access_token(data={"sub": email or "unknown", "provider": "linkedin"})
    
    # إعادة التوجيه إلى صفحة لوحة التحكم مع تمرير التوكن
    redirect_url = f"{FRONTEND_URL}/dashboard?token={jwt_token}"
    return RedirectResponse(url=redirect_url)

# ==========================================
# 7. مسارات Facebook OAuth
# ==========================================
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
async def facebook_callback(code: str = None, error: str = None, db: Session = Depends(get_db)):
    if error:
        raise HTTPException(status_code=400, detail=f"Facebook Auth Error: {error}")
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code not found")

    token_url = "https://graph.facebook.com/v18.0/oauth/access_token"
    params = {
        "client_id": FACEBOOK_CLIENT_ID,
        "client_secret": FACEBOOK_CLIENT_SECRET,
        "redirect_uri": FACEBOOK_REDIRECT_URI,
        "code": code,
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

    # --- حفظ المستخدم في قاعدة البيانات (مثال) ---
    email = user_info.get("email")
    name = user_info.get("name")
    if email:
        db_user = db.query(User).filter(User.email == email).first()
        if not db_user:
            db_user = User(email=email, name=name, provider="facebook")
            db.add(db_user)
            db.commit()
            db.refresh(db_user)
    
    # --- إنشاء توكن JWT وإعادة التوجيه للفرونت إند ---
    jwt_token = create_access_token(data={"sub": email or "unknown", "provider": "facebook"})
    
    redirect_url = f"{FRONTEND_URL}/dashboard?token={jwt_token}"
    return RedirectResponse(url=redirect_url)