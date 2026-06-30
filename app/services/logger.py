import json
import logging
from app.database.db import AsyncSessionLocal
from app.models.logs import AuditLog

logger = logging.getLogger(__name__)

async def save_audit_log(
    user_id: int | None,
    username: str | None,
    prompt: str,
    redacted_prompt: str | None,
    response: str | None,
    status: str,
    block_reason: str | None,
    violation_details: dict | list | None,
    latency_ms: float
):
    """
    Saves an audit log entry in the background. Opens its own database session
    to prevent conflicts with request-scoped sessions that might close early.
    """
    async with AsyncSessionLocal() as db:
        try:
            log_entry = AuditLog(
                user_id=user_id,
                username=username,
                prompt=prompt,
                redacted_prompt=redacted_prompt,
                response=response,
                status=status,
                block_reason=block_reason,
                violation_details=json.dumps(violation_details) if violation_details else None,
                latency_ms=latency_ms
            )
            db.add(log_entry)
            await db.commit()
            logger.info(f"Audit log saved successfully: Status={status}, BlockReason={block_reason}")
        except Exception as e:
            logger.error(f"Failed to write audit log to database: {e}")
