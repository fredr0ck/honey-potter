from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import honeypots, credentials, events, auth, notifications
from app.core.config import settings

app = FastAPI(
    title="Honey Potter",
    description="Service for early attack detection",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
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