from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import honeypots, credentials, events, auth, notifications
from app.core.config import settings
from contextlib import asynccontextmanager
import subprocess
import sys

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        print("Running database migrations...")
        result = subprocess.run(
            ["alembic", "upgrade", "head"],
            cwd="/app",
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print("Database migrations completed successfully")
        else:
            print(f"Migration warning: {result.stderr}", file=sys.stderr)
    except Exception as e:
        print(f"Migration error: {e}", file=sys.stderr)
    
    yield

app = FastAPI(
    title="Honey Potter",
    description="Service for early attack detection",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    expose_headers=["*"],
)

app.include_router(auth.router, prefix="/api", tags=["auth"])
app.include_router(honeypots.router, prefix="/api", tags=["honeypots"])
app.include_router(credentials.router, prefix="/api", tags=["credentials"])
app.include_router(events.router, prefix="/api", tags=["events"])
app.include_router(notifications.router, prefix="/api", tags=["notifications"])

@app.get("/")
async def root():
    return {
        "message": "HPM API"
    }

@app.get("/health")
async def health():
    return {"status": "ok"}