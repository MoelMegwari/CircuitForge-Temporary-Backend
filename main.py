import os
import uuid
import tempfile
from pathlib import Path
from datetime import datetime, timezone

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

APP_NAME = "CircuitForge Temporary API"
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_MB", "20")) * 1024 * 1024
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("FRONTEND_ORIGINS", "*").split(",")
    if origin.strip()
]

app = FastAPI(
    title=APP_NAME,
    version="0.1.0",
    description="Temporary API for testing CircuitForge AI uploads. No fabrication engine is enabled."
)
import os
import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse

# قراءة المتغيرات البيئية المعرفة مسبقاً على Railway
LINKEDIN_CLIENT_ID = os.getenv("LINKEDIN_CLIENT_ID")
LINKEDIN_CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", "https://web-production-598c28d9.up.railway.app/auth/linkedin/callback")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://web-production-598c28d9.up.railway.app")

@app.get("/auth/linkedin/login")
def linkedin_login():
    """توجيه المستخدم إلى صفحة المصادقة الرسمية لـ LinkedIn"""
    if not LINKEDIN_CLIENT_ID:
        raise HTTPException(status_code=500, detail="LinkedIn Client ID is not configured")
    
    scope = "openid profile email"
    state = "random_secure_state_string"  # يمكن جعله ديناميكياً للأمان العالي
    
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
    """استقبال الكود من LinkedIn ومقايضته بـ Access Token وجلب البيانات"""
    if error:
        raise HTTPException(status_code=400, detail=f"LinkedIn Auth Error: {error}")
    if not code:
        raise HTTPException(status_code=400, detail="Authorization code not found")

    # 1. طلب الـ Access Token باستخدام الـ Code
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

        # 2. جلب بيانات المستخدم من بروتوكول OpenID / UserInfo
        userinfo_url = "https://api.linkedin.com/v2/userinfo"
        headers = {"Authorization": f"Bearer {access_token}"}
        
        user_response = await client.get(userinfo_url, headers=headers)
        if user_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch user profile")
        
        user_info = user_response.json()

    # هنا يمكنك حفظ بيانات المستخدم في القاعدة أو توجيهه للواجهة الأمامية مع التوكن
    # كمثال مبدئي، سنقوم بإعادة توجيهه للـ Frontend مع عرض بياناته أو تمريرها
    return {
        "status": "success",
        "message": "LinkedIn authentication successful",
        "user_profile": user_info
    }

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if ALLOWED_ORIGINS == ["*"] else ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Temporary, non-persistent storage. Render Free may erase this on restart/sleep/redeploy.
UPLOAD_DIR = Path(tempfile.gettempdir()) / "circuitforge_uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# In-memory job index: intentionally temporary and reset when the service restarts.
JOBS = {}

@app.get("/")
def root():
    return {
        "service": APP_NAME,
        "status": "online",
        "mode": "temporary-upload-test",
        "fabrication_engine": "not_configured"
    }

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": APP_NAME,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "kicad_cli": "not_configured",
        "freerouting": "not_configured"
    }

@app.get("/api/v1/status")
def api_status():
    return {
        "api": "ready",
        "upload": "enabled",
        "kicad_processing": "disabled",
        "gerber_export": "disabled",
        "drill_export": "disabled",
        "freerouting": "disabled",
        "warning": "Uploaded files are temporary and may be deleted when the service restarts or sleeps."
    }

@app.post("/api/v1/boards/upload")
async def upload_board(file: UploadFile = File(...)):
    filename = Path(file.filename or "").name
    if not filename.lower().endswith(".kicad_pcb"):
        raise HTTPException(status_code=415, detail="Only .kicad_pcb files are accepted.")

    job_id = str(uuid.uuid4())
    destination = UPLOAD_DIR / f"{job_id}.kicad_pcb"
    total = 0

    try:
        with destination.open("wb") as output:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    output.close()
                    destination.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit."
                    )
                output.write(chunk)
    finally:
        await file.close()

    if total == 0:
        destination.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    JOBS[job_id] = {
        "job_id": job_id,
        "original_filename": filename,
        "size_bytes": total,
        "status": "uploaded",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "processing": "not_started",
        "message": "Upload received. KiCad CLI is not installed/configured in this temporary service."
    }

    return JOBS[job_id]

@app.get("/api/v1/jobs/{job_id}")
def get_job(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found. Temporary job records may be lost after restart.")
    return job

@app.get("/docs-status")
def docs_status():
    return {"openapi_docs": "/docs", "redoc": "/redoc"}
