"""FastAPI entry point. Bind the server to loopback; this MVP has no auth."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .api import router
from .db import connect, initialize
from .seed import seed_demo

_ALLOWED_ORIGINS = {
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "http://127.0.0.1:8000",
}


def database_path() -> Path:
    configured = os.environ.get("VULNFLOW_DB_PATH")
    if configured:
        return Path(configured).expanduser()
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return root / "VulnFlow" / "vulnflow.sqlite3"
    return Path.home() / ".local" / "share" / "vulnflow" / "vulnflow.sqlite3"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    app.state.db_path = path
    initialize(path)
    conn = connect(path)
    try:
        seed_demo(conn)
    finally:
        conn.close()
    yield


app = FastAPI(
    title="VulnFlow local API",
    version="0.1.0",
    description="Single-user local review for imported findings; approvals never execute actions.",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url=None,
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["127.0.0.1", "localhost", "testserver"],
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(_ALLOWED_ORIGINS),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Request-Id"],
    max_age=300,
)


@app.middleware("http")
async def browser_origin_guard(request: Request, call_next):
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        origin = request.headers.get("origin")
        if origin is not None and origin not in _ALLOWED_ORIGINS:
            return JSONResponse(status_code=403, content={"detail": "Browser origin is not allowed"})
    return await call_next(request)


app.include_router(router)


@app.get("/")
def root() -> dict[str, str]:
    return {"name": "VulnFlow", "api": "/api", "mode": "trusted-single-user-local"}
