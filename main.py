from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from pathlib import Path

from app.core.config import settings
from app.api.routes import router
from app.db.models import Database
from app.utils.logging import AuditLogger

# Create required directories
Path("storage/files").mkdir(parents=True, exist_ok=True)
Path("storage/logs").mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Secure Cloud File Storage with Automatic Key Rotation and Auditing"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routes
app.include_router(router, prefix=settings.API_V1_STR)

# Startup event
@app.on_event("startup")
async def startup_event():
    # Initialize database
    db = Database(settings.SQLITE_URL)
    await db.init_db()
    
    # Initialize audit logger
    AuditLogger(db)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True) 