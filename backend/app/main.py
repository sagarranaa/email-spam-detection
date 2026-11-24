from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from . import ml, security, storage
from .config import PROJECT_ROOT
from .email_parser import parse_raw_email
from .schemas import AnalyzeRequest


@asynccontextmanager
async def lifespan(_: FastAPI):
    storage.initialize_database()
    yield


app = FastAPI(
    title="AI Email Spam & Threat Detection System",
    description="Local, read-only email analysis dashboard.",
    version="1.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3778",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type"],
)


@app.get("/api/health")
async def health() -> dict[str, object]:
    return {
        "status": "ok",
        "hf_model": {"configured": True, "model": ml.HF_MODEL_ID},
        "storage": "sqlite",
    }


@app.post("/api/analyze")
async def analyze(request: AnalyzeRequest) -> dict[str, Any]:
    if request.raw_email is None and not (request.subject.strip() or request.body.strip()):
        raise HTTPException(status_code=422, detail="Provide an email subject/body or a raw .eml message.")

    parsed: dict[str, Any] = {}
    if request.raw_email:
        parsed = parse_raw_email(request.raw_email)
    subject = request.subject or parsed.get("subject", "")
    sender = request.sender or parsed.get("sender", "")
    reply_to = parsed.get("reply_to", "")
    body = request.body or parsed.get("body", "")

    analysis = await asyncio.to_thread(
        security.analyze_content,
        subject,
        body,
        sender,
        reply_to,
        request.raw_email or "",
        request.check_dns,
    )
    model_result: dict[str, Any] = await asyncio.to_thread(ml.score_email, subject, body)

    spam_score = model_result.get("spam_score")
    risk_score, risk_level = security.calculate_risk(analysis["findings"], spam_score)
    if spam_score is None:
        classification = "Needs review"
    elif spam_score >= 0.5:
        classification = "Likely spam"
    else:
        classification = "Not flagged as spam"
    result: dict[str, Any] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "subject": subject or "(no subject)",
        "sender": sender or "Unknown sender",
        "risk_score": risk_score,
        "risk_level": risk_level,
        "classification": classification,
        "findings": analysis["findings"],
        "urls": analysis["urls"],
        "authentication": analysis["authentication"],
        "model": model_result,
        "privacy_note": "Email body and raw headers are not saved in scan history.",
    }
    return storage.save_scan(result)


@app.get("/api/history")
async def history(limit: int = Query(default=20, ge=1, le=100)) -> dict[str, object]:
    return {"items": storage.list_scans(limit)}


@app.get("/api/history/{scan_id}")
async def history_item(scan_id: int) -> dict[str, Any]:
    result = storage.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return result


@app.delete("/api/history/{scan_id}")
async def remove_history_item(scan_id: int) -> dict[str, bool]:
    if not storage.delete_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found.")
    return {"deleted": True}


@app.get("/api/stats")
async def stats() -> dict[str, int]:
    return storage.get_stats()


frontend_dist = Path(PROJECT_ROOT / "frontend" / "dist")
if frontend_dist.is_dir():
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")

