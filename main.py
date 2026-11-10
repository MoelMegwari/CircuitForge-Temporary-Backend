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
