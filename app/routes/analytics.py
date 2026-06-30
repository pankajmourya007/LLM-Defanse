import os
import json
import logging
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func, desc

from app.database.db import get_db
from app.models.logs import AuditLog
from app.models.user import User
from app.services.auth import get_current_user
from app.services.pii_scanner import ACTIVE_ENTITIES, PII_POLICY
import app.services.pii_scanner as pii_module
import app.services.prompt_guard as pg_module
import os

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/analytics", tags=["analytics"])

@router.get("/summary")
async def get_summary(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    # 1. Total Requests
    total_res = await db.execute(select(func.count(AuditLog.id)))
    total_count = total_res.scalar() or 0

    # 2. Status Counts
    allowed_res = await db.execute(select(func.count(AuditLog.id)).filter(AuditLog.status == "allowed"))
    allowed_count = allowed_res.scalar() or 0
    blocked_count = total_count - allowed_count

    # 3. Block Reasons
    pii_blocked_res = await db.execute(select(func.count(AuditLog.id)).filter(AuditLog.block_reason == "pii"))
    pii_blocked_count = pii_blocked_res.scalar() or 0

    inj_blocked_res = await db.execute(select(func.count(AuditLog.id)).filter(AuditLog.block_reason == "prompt_injection"))
    inj_blocked_count = inj_blocked_res.scalar() or 0

    rl_blocked_res = await db.execute(select(func.count(AuditLog.id)).filter(AuditLog.block_reason == "rate_limit"))
    rl_blocked_count = rl_blocked_res.scalar() or 0

    # 4. Average Latency
    latency_res = await db.execute(select(func.avg(AuditLog.latency_ms)))
    avg_latency = latency_res.scalar() or 0.0

    # 5. Redacted PII count (AuditLog with allowed status and pii_detected = True in details)
    # We can fetch recent allowed logs to count redactions or do it simply. Let's do a simple count.
    # We'll fetch logs from past 30 days
    cutoff = datetime.utcnow() - timedelta(days=30)
    recent_res = await db.execute(select(AuditLog).filter(AuditLog.timestamp >= cutoff))
    recent_logs = recent_res.scalars().all()
    
    redacted_count = 0
    for log in recent_logs:
        if log.status == "allowed" and log.violation_details:
            try:
                details = json.loads(log.violation_details)
                if details.get("pii_detected"):
                    redacted_count += 1
            except Exception:
                pass

    return {
        "total_requests": total_count,
        "allowed_requests": allowed_count,
        "blocked_requests": blocked_count,
        "pii_blocks": pii_blocked_count,
        "pii_redactions": redacted_count,
        "prompt_injection_blocks": inj_blocked_count,
        "rate_limit_blocks": rl_blocked_count,
        "average_latency_ms": round(float(avg_latency), 2)
    }

@router.get("/logs")
async def get_logs(
    db: AsyncSession = Depends(get_db),
    status: str = Query(None),
    block_reason: str = Query(None),
    search: str = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(25, ge=1, le=100),
    current_user: User = Depends(get_current_user)
):
    offset = (page - 1) * limit
    query = select(AuditLog)

    # Apply filters
    if status:
        query = query.filter(AuditLog.status == status)
    if block_reason:
        query = query.filter(AuditLog.block_reason == block_reason)
    if search:
        query = query.filter(
            AuditLog.prompt.contains(search) | 
            AuditLog.response.contains(search) |
            AuditLog.username.contains(search)
        )

    # Get total count for pagination
    count_query = select(func.count()).select_from(query.subquery())
    count_res = await db.execute(count_query)
    total_count = count_res.scalar() or 0

    # Retrieve page of logs
    query = query.order_by(desc(AuditLog.timestamp)).offset(offset).limit(limit)
    logs_res = await db.execute(query)
    logs = logs_res.scalars().all()

    # Parse JSON detail strings
    parsed_logs = []
    for log in logs:
        violation_details = None
        if log.violation_details:
            try:
                violation_details = json.loads(log.violation_details)
            except Exception:
                violation_details = log.violation_details
        
        parsed_logs.append({
            "id": log.id,
            "timestamp": log.timestamp,
            "user_id": log.user_id,
            "username": log.username,
            "prompt": log.prompt,
            "redacted_prompt": log.redacted_prompt,
            "response": log.response,
            "status": log.status,
            "block_reason": log.block_reason,
            "violation_details": violation_details,
            "latency_ms": log.latency_ms
        })

    return {
        "logs": parsed_logs,
        "total": total_count,
        "page": page,
        "limit": limit,
        "pages": (total_count + limit - 1) // limit
    }

@router.get("/trends")
async def get_trends(db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Retrieve logs from last 7 days to aggregate in Python (database-agnostic)
    cutoff = datetime.utcnow() - timedelta(days=7)
    res = await db.execute(
        select(AuditLog)
        .filter(AuditLog.timestamp >= cutoff)
        .order_by(AuditLog.timestamp.asc())
    )
    logs = res.scalars().all()

    # Initialize last 7 days map
    trends_map = {}
    for i in range(7):
        day = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
        trends_map[day] = {"date": day, "allowed": 0, "blocked": 0, "pii": 0, "injection": 0}

    # Aggregate
    for log in logs:
        day = log.timestamp.strftime("%Y-%m-%d")
        if day in trends_map:
            if log.status == "allowed":
                trends_map[day]["allowed"] += 1
            else:
                trends_map[day]["blocked"] += 1
                if log.block_reason == "pii":
                    trends_map[day]["pii"] += 1
                elif log.block_reason == "prompt_injection":
                    trends_map[day]["injection"] += 1

    # Format list sorted chronologically
    trends_list = sorted(trends_map.values(), key=lambda x: x["date"])
    return trends_list

@router.get("/rules")
async def get_rules(current_user: User = Depends(get_current_user)):
    return {
        "pii_policy": pii_module.PII_POLICY,
        "pii_entities": pii_module.ACTIVE_ENTITIES,
        "prompt_injection_threshold": pg_module.THRESHOLD,
        "rate_limit_per_minute": int(os.getenv("RATE_LIMIT_PER_MINUTE", "30")),
        "llm_provider": os.getenv("LLM_PROVIDER", "mock")
    }

@router.post("/rules")
async def update_rules(config: dict, current_user: User = Depends(get_current_user)):
    # Support dynamic update of configuration in-memory for testing
    if "pii_policy" in config:
        pii_module.PII_POLICY = config["pii_policy"].lower()
    if "pii_entities" in config:
        pii_module.ACTIVE_ENTITIES = config["pii_entities"]
    if "prompt_injection_threshold" in config:
        pg_module.THRESHOLD = float(config["prompt_injection_threshold"])
    if "rate_limit_per_minute" in config:
        os.environ["RATE_LIMIT_PER_MINUTE"] = str(config["rate_limit_per_minute"])
    if "llm_provider" in config:
        os.environ["LLM_PROVIDER"] = config["llm_provider"]
        
    return {
        "status": "success",
        "message": "Gateway configuration updated successfully",
        "rules": {
            "pii_policy": pii_module.PII_POLICY,
            "pii_entities": pii_module.ACTIVE_ENTITIES,
            "prompt_injection_threshold": pg_module.THRESHOLD,
            "rate_limit_per_minute": int(os.getenv("RATE_LIMIT_PER_MINUTE", "30")),
            "llm_provider": os.getenv("LLM_PROVIDER", "mock")
        }
    }
