from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from app.database.db import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    username = Column(String, index=True, nullable=True)
    prompt = Column(String, nullable=False)
    redacted_prompt = Column(String, nullable=True)
    response = Column(String, nullable=True)
    status = Column(String, index=True, nullable=False)  # "allowed", "blocked"
    block_reason = Column(String, index=True, nullable=True)  # "pii", "prompt_injection", "rate_limit", "policy"
    violation_details = Column(String, nullable=True)  # JSON details of entities/scores
    latency_ms = Column(Float, default=0.0)
