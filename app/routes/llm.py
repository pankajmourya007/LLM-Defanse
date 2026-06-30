import os
import time
import logging
import httpx
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from pydantic import BaseModel
from dotenv import load_dotenv

from app.models.user import User
from app.services.auth import get_current_user
from app.services.pii_scanner import PIIScanner, PII_POLICY
from app.services.prompt_guard import PromptGuard
from app.services.rate_limiter import RateLimiter
from app.services.logger import save_audit_log

load_dotenv()
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/llm", tags=["llm"])

class ChatRequest(BaseModel):
    prompt: str

class ChatResponse(BaseModel):
    status: str
    prompt: str
    redacted_prompt: str
    response: str
    pii_detected: bool
    pii_violations: list
    injection_detected: bool
    injection_score: float
    latency_ms: float

# Helper to call LLM or Mock
async def call_llm_provider(prompt: str) -> str:
    provider = os.getenv("LLM_PROVIDER", "mock").lower()
    api_key = os.getenv("LLM_API_KEY", "")
    
    if provider == "openai" and api_key:
        try:
            async with httpx.AsyncClient() as client:
                res = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                    json={
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.7
                    },
                    timeout=15.0
                )
                if res.status_code == 200:
                    return res.json()["choices"][0]["message"]["content"]
                else:
                    logger.error(f"OpenAI error: {res.text}")
                    return f"Error from OpenAI API (HTTP {res.status_code})"
        except Exception as e:
            logger.error(f"Failed to call OpenAI: {e}")
            return f"OpenAI connection error: {str(e)}"
            
    elif provider == "gemini" and api_key:
        try:
            # Standard Gemini API v1beta
            async with httpx.AsyncClient() as client:
                res = await client.post(
                    f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}",
                    headers={"Content-Type": "application/json"},
                    json={
                        "contents": [{"parts": [{"text": prompt}]}]
                    },
                    timeout=15.0
                )
                if res.status_code == 200:
                    return res.json()["candidates"][0]["content"]["parts"][0]["text"]
                else:
                    logger.error(f"Gemini error: {res.text}")
                    return f"Error from Gemini API (HTTP {res.status_code})"
        except Exception as e:
            logger.error(f"Failed to call Gemini: {e}")
            return f"Gemini connection error: {str(e)}"
            
    # Mock fallback (default)
    # Give a dynamic mock response based on the query for a premium interactive feel
    if "sql injection" in prompt.lower():
        return (
            "SQL Injection (SQLi) is a common vulnerability where an attacker manipulates SQL queries by "
            "injecting malicious input. In a secure enterprise environment, you should protect against this by "
            "using parameterized queries (prepared statements), validating inputs, and using ORMs like SQLAlchemy."
        )
    elif "cross-site scripting" in prompt.lower() or "xss" in prompt.lower():
        return (
            "Cross-Site Scripting (XSS) is a vulnerability where malicious scripts are injected into trusted web pages. "
            "To prevent XSS, you should escape user inputs before rendering them in HTML, enforce a Content Security Policy (CSP), "
            "and use modern web frameworks like React which sanitize variables automatically."
        )
    else:
        return (
            f"Greetings! This is a secure response from the LLM-Defanc proxy gateway.\n\n"
            f"We analyzed your prompt, certified it clean of sensitive data (PII) and injection vectors, and passed it along. "
            f"Here is your AI response simulating standard assistance:\n\n"
            f"Query: \"{prompt[:60]}{'...' if len(prompt) > 60 else ''}\"\n\n"
            f"If you'd like to test the gateway's defenses, try prompting with an email address (e.g. hello@example.com) "
            f"or typing a system override attempt (e.g. 'ignore previous instructions')."
        )

@router.post("/chat", response_model=ChatResponse)
async def chat_gateway(
    request: ChatRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    start_time = time.time()
    prompt = request.prompt
    
    # 1. Rate Limiting
    # Check rate limit using username
    rate_limit_max = int(os.getenv("RATE_LIMIT_PER_MINUTE", "30"))
    is_limited = await RateLimiter.is_rate_limited(f"usr:{current_user.username}", limit=rate_limit_max)
    if is_limited:
        latency = (time.time() - start_time) * 1000
        background_tasks.add_task(
            save_audit_log,
            user_id=current_user.id,
            username=current_user.username,
            prompt=prompt,
            redacted_prompt=None,
            response=None,
            status="blocked",
            block_reason="rate_limit",
            violation_details={"max_requests": rate_limit_max, "window_seconds": 60},
            latency_ms=latency
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again in a minute."
        )

    # 2. PII Detection
    redacted_prompt, pii_detected, pii_violations = PIIScanner.scan_and_redact(prompt)
    if pii_detected and PII_POLICY == "block":
        latency = (time.time() - start_time) * 1000
        background_tasks.add_task(
            save_audit_log,
            user_id=current_user.id,
            username=current_user.username,
            prompt=prompt,
            redacted_prompt=None,
            response=None,
            status="blocked",
            block_reason="pii",
            violation_details=pii_violations,
            latency_ms=latency
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "blocked_by_policy",
                "reason": "pii",
                "message": "Request blocked: Prompt contains sensitive PII data.",
                "violations": pii_violations
            }
        )

    # 3. Prompt Injection Detection
    injection_detected, injection_score, triggered_rules = PromptGuard.analyze(prompt)
    if injection_detected:
        latency = (time.time() - start_time) * 1000
        background_tasks.add_task(
            save_audit_log,
            user_id=current_user.id,
            username=current_user.username,
            prompt=prompt,
            redacted_prompt=None,
            response=None,
            status="blocked",
            block_reason="prompt_injection",
            violation_details={"score": injection_score, "triggered_rules": triggered_rules},
            latency_ms=latency
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "blocked_by_policy",
                "reason": "prompt_injection",
                "message": "Request blocked: Prompt injection attempt detected.",
                "score": injection_score,
                "violations": triggered_rules
            }
        )

    # 4. LLM Call
    # If policy is redact, call LLM with the redacted version. Otherwise, call with original.
    llm_input_prompt = redacted_prompt if PII_POLICY == "redact" else prompt
    llm_response = await call_llm_provider(llm_input_prompt)
    
    latency = (time.time() - start_time) * 1000
    
    # 5. Log Success (in background)
    background_tasks.add_task(
        save_audit_log,
        user_id=current_user.id,
        username=current_user.username,
        prompt=prompt,
        redacted_prompt=redacted_prompt,
        response=llm_response,
        status="allowed",
        block_reason=None,
        violation_details={"pii_detected": pii_detected, "pii_violations_count": len(pii_violations)},
        latency_ms=latency
    )
    
    return ChatResponse(
        status="allowed",
        prompt=prompt,
        redacted_prompt=redacted_prompt,
        response=llm_response,
        pii_detected=pii_detected,
        pii_violations=pii_violations,
        injection_detected=False,
        injection_score=injection_score,
        latency_ms=latency
    )
