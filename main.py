# ================================================================
#  CodeReview AI — FastAPI Backend  (main.py)
#  Powered by GROQ AI  ⚡ (Free + Ultra Fast)
#
#  SETUP STEPS:
#
#  1. Install all dependencies:
#       pip install fastapi uvicorn pymysql sqlalchemy bcrypt \
#                   "python-jose[cryptography]" "pydantic[email]" \
#                   groq python-dotenv
#
#  2. Get your FREE Groq API key:
#       → Go to: https://console.groq.com/
#       → Sign up (free)
#       → Click "API Keys" → "Create API Key"
#       → Copy the key
#
#  3. Create a .env file in the same folder as main.py:
#       GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
#       MYSQL_PASSWORD=your_mysql_password
#       JWT_SECRET=any-long-random-string-at-least-32-chars
#
#  4. Make sure your database is created:
#       mysql -u root -p < schema.sql
#
#  5. Run the server:
#       uvicorn main:app --reload --port 8000
#
#  ── Groq Models (all FREE) ──────────────────────────────────
#  "llama-3.3-70b-versatile"   ← BEST quality  (recommended)
#  "llama-3.1-8b-instant"      ← Fastest
#  "mixtral-8x7b-32768"        ← Good for long code
#  "gemma2-9b-it"              ← Google Gemma
# ================================================================

from __future__ import annotations

import logging
import os
import re
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from groq import Groq
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, text

# ── Logging ────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# ── Load .env ──────────────────────────────────────────────────
load_dotenv()

# ── Configuration ──────────────────────────────────────────────
MYSQL_USER     = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "root")
MYSQL_HOST     = os.getenv("MYSQL_HOST", "localhost")
MYSQL_PORT     = os.getenv("MYSQL_PORT", "3306")
MYSQL_DB       = os.getenv("MYSQL_DB", "codereview_ai")
DB_URL         = f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}"

JWT_SECRET   = os.getenv("JWT_SECRET", "change-this-to-a-long-random-secret-in-production")
JWT_ALGO     = "HS256"
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

# ── Groq model ─────────────────────────────────────────────────
GROQ_MODEL = "llama-3.3-70b-versatile"   # Best quality (free)
# GROQ_MODEL = "llama-3.1-8b-instant"    # Fastest (free)
# GROQ_MODEL = "mixtral-8x7b-32768"      # Good for long files (free)

# ── Groq client ────────────────────────────────────────────────
groq_client = Groq(api_key=GROQ_API_KEY)

# ── App & DB setup ─────────────────────────────────────────────
engine = create_engine(
    DB_URL,
    pool_pre_ping=True,
    pool_recycle=3600,
    pool_size=10,
    max_overflow=20,
)
app    = FastAPI(title="CodeReview AI — Groq Edition", version="3.2.0")
bearer = HTTPBearer()

# ── CORS — allow all origins for local dev ─────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Covers file://, Live Server (5500), localhost variants
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# ── DB dependency ──────────────────────────────────────────────
def get_db():
    with engine.connect() as conn:
        yield conn

# ── Password helpers ───────────────────────────────────────────
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

# ── JWT helpers ────────────────────────────────────────────────
def create_jwt(user_id: int, days: int = 1) -> str:
    exp = datetime.now(timezone.utc) + timedelta(days=days)
    return jwt.encode({"sub": str(user_id), "exp": exp}, JWT_SECRET, algorithm=JWT_ALGO)

def require_auth(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> int:
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALGO])
        return int(payload["sub"])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")


# ================================================================
#  REQUEST SCHEMAS
# ================================================================
class RegisterBody(BaseModel):
    name:     str
    email:    EmailStr
    password: str

class LoginBody(BaseModel):
    email:    EmailStr
    password: str
    remember: bool = False

class ForgotBody(BaseModel):
    email: EmailStr

class ReviewBody(BaseModel):
    language: str
    code:     str
    focus_areas: list[str] = []

class RewriteBody(BaseModel):
    language:        str
    code:            str
    review_feedback: str = ""


# ================================================================
#  HEALTH CHECK  (used by code-review.html to check API status)
# ================================================================

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "api_configured": bool(GROQ_API_KEY),
        "model": GROQ_MODEL,
    }


# ================================================================
#  AUTH ENDPOINTS
# ================================================================

@app.post("/api/auth/register", status_code=201)
def register(body: RegisterBody, db=Depends(get_db)):
    if len(body.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")

    existing = db.execute(
        text("SELECT id FROM users WHERE email = :e"),
        {"e": body.email}
    ).first()
    if existing:
        raise HTTPException(409, "An account with that email already exists.")

    db.execute(
        text("INSERT INTO users (name, email, password_hash) VALUES (:n, :e, :h)"),
        {"n": body.name.strip(), "e": body.email, "h": hash_password(body.password)}
    )
    db.commit()
    return {"message": "Account created successfully."}


@app.post("/api/auth/login")
def login(body: LoginBody, db=Depends(get_db)):
    row = db.execute(
        text("SELECT id, name, email, password_hash FROM users WHERE email = :e AND is_active = 1"),
        {"e": body.email}
    ).first()

    if not row or not verify_password(body.password, row.password_hash):
        raise HTTPException(401, "Invalid email or password.")

    days  = 30 if body.remember else 1
    token = create_jwt(row.id, days=days)
    return {
        "token": token,
        "user":  {"id": row.id, "name": row.name, "email": row.email}
    }


@app.post("/api/auth/forgot-password")
def forgot_password(body: ForgotBody, db=Depends(get_db)):
    row = db.execute(
        text("SELECT id FROM users WHERE email = :e AND is_active = 1"),
        {"e": body.email}
    ).first()

    if row:
        db.execute(
            text("DELETE FROM password_reset_tokens WHERE user_id = :u AND used = 0"),
            {"u": row.id}
        )
        token  = secrets.token_urlsafe(48)
        expiry = datetime.now(timezone.utc) + timedelta(hours=2)
        db.execute(
            text("INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (:u, :t, :x)"),
            {"u": row.id, "t": token, "x": expiry}
        )
        db.commit()
        log.info(f"[DEV] Password reset link: http://localhost:8000/reset?token={token}")

    return {"message": "If that email is registered, a reset link has been sent."}


# ================================================================
#  DASHBOARD
# ================================================================

@app.get("/api/dashboard")
def dashboard(user_id: int = Depends(require_auth), db=Depends(get_db)):
    total_reviews = db.execute(
        text("SELECT COUNT(*) FROM code_reviews WHERE user_id = :u"), {"u": user_id}
    ).scalar() or 0

    total_rewrites = db.execute(
        text("SELECT COUNT(*) FROM code_rewrites WHERE user_id = :u"), {"u": user_id}
    ).scalar() or 0

    today_count = db.execute(
        text("SELECT COUNT(*) FROM code_reviews WHERE user_id = :u AND DATE(created_at) = CURDATE()"),
        {"u": user_id}
    ).scalar() or 0

    avg_score = db.execute(
        text("SELECT ROUND(AVG(score), 1) FROM code_reviews WHERE user_id = :u AND score IS NOT NULL"),
        {"u": user_id}
    ).scalar()

    recent_rows = db.execute(text("""
        SELECT language, LEFT(code, 80) AS snippet, score, created_at
        FROM   code_reviews
        WHERE  user_id = :u
        ORDER  BY created_at DESC
        LIMIT  5
    """), {"u": user_id}).mappings().all()

    return {
        "total_reviews":  total_reviews,
        "total_rewrites": total_rewrites,
        "today_count":    today_count,
        "avg_score":      float(avg_score) if avg_score else None,
        "recent_reviews": [dict(r) for r in recent_rows],
    }


# ================================================================
#  GROQ AI HELPERS
# ================================================================

REVIEW_SYSTEM = """You are a senior software engineer and expert code reviewer with 15+ years of experience.

## GOLDEN RULE — SIMPLICITY IS A VIRTUE
Simple code that correctly solves a simple problem is PERFECT code.
Do NOT penalise code for lacking functions, classes, error handling, or comments
when the problem does not require them. A one-liner addition is better than
a 30-line class that does the same thing.

## SCORING RULES
- Award HIGH scores (8-10) to code that is correct, clear, and appropriately simple.
- PENALISE over-engineering: unnecessary functions/classes/abstractions cost 1-2 points each.
- PENALISE under-engineering only when the problem is complex enough to warrant it.
- NEVER reward added complexity unless it genuinely reduces risk or improves maintainability
  for a non-trivial problem.

When given code, provide a structured review with these sections:

1. 📋 OVERVIEW
   - What the code does and its purpose
   - Whether its complexity level is appropriate for the problem

2. ✅ STRENGTHS
   - What is done well (including praising simplicity when it is appropriate)

3. 🐛 BUGS & ISSUES
   - Actual logic errors, edge cases, potential crashes only
   - Include line numbers where possible
   - Do NOT list missing abstractions as bugs for simple programs

4. ⚡ PERFORMANCE
   - Real inefficiencies only (e.g. O(n²) where O(n) is possible)
   - Do NOT flag simple code as slow just because it lacks caching or async

5. 🔒 SECURITY
   - Vulnerabilities relevant to the code's actual use case only

6. 📐 CODE QUALITY
   - Readability and naming — judge relative to problem complexity
   - A simple problem with simple code is high quality

7. 💡 IMPROVEMENTS
   - Only suggest changes that provide genuine value for THIS problem's complexity
   - If nothing meaningful needs changing, say so explicitly

8. 📊 OVERALL SCORE
   - End with exactly this format: Overall Score: X/10
   - Be honest — do not inflate scores because code looks "enterprise-ready"

At the very end, after the score, add:
SEVERITY_COUNTS: critical=N high=N medium=N low=N"""


REWRITE_SYSTEM = """You are a senior software engineer specializing in writing clean, efficient, production-ready code.

## CRITICAL RULE — MATCH COMPLEXITY TO THE PROBLEM
Before rewriting, assess whether the code actually needs changes.

- If the code is already CORRECT, CLEAR, and APPROPRIATELY SIMPLE → make MINIMAL or NO changes.
  Do not add functions, classes, type hints, docstrings, or error handling that the problem
  does not justify. A simple addition script does NOT need a function, a class, or try/except.
  
- Only add abstraction, error handling, or structure when the code is complex enough to benefit.
  Ask yourself: "Does adding this genuinely help, or am I just making it look more impressive?"
  
- Simple problems deserve simple solutions. Over-engineering is a bug, not a feature.

## WHAT TO ACTUALLY FIX
- Real bugs and logic errors
- Genuinely misleading or unclear variable names (only in non-trivial code)
- Actual performance problems (e.g. nested loops that can be simplified)
- Security issues (only when relevant to what the code does)

## WHAT NOT TO ADD
- Do NOT wrap simple expressions in unnecessary functions
- Do NOT add try/except blocks where errors are not realistically possible
- Do NOT add type hints, docstrings, or comments to trivially obvious code
- Do NOT restructure code that is already readable and correct

After the rewritten code, add these sections EXACTLY:

IMPROVEMENTS_LIST:
- what you changed and WHY (if you changed nothing meaningful, say "No significant changes needed — original code was already optimal")

EXPLANATION:
One honest sentence: did the original code need changes? What was the most important fix, if any?

IMPORTANT: Put the raw rewritten code FIRST, then IMPROVEMENTS_LIST and EXPLANATION after."""


COMPARE_SYSTEM = """You are an honest, senior software engineer doing a side-by-side comparison of two code versions.

## YOUR ONLY JOB: Be Brutally Honest
Do NOT automatically favour the rewritten version. The original may be better.

## SCORING RULES — READ CAREFULLY
- Simple code that correctly solves a simple problem scores 9-10. It does not need functions or error handling.
- PENALISE the rewritten version if it added unnecessary functions, wrappers, classes, or abstractions.
- PENALISE over-engineering. Every unnecessary line of code is a liability, not an asset.
- If the original and rewrite are functionally identical, the SIMPLER one wins.
- Only favour the rewrite if it fixed a real bug, removed a real inefficiency, or improved clarity
  in a way that genuinely matters for the problem's complexity.

## OUTPUT FORMAT — use exactly this structure:

### 📊 Comparison Verdict

**Original Code Score: X/10**
(one line justification)

**Rewritten Code Score: X/10**
(one line justification)

**✅ Winner: [Original | Rewritten | Tie]**
(one honest sentence explaining why)

### 🔍 Key Differences
- List actual meaningful differences only (not cosmetic ones)
- Call out any unnecessary complexity added by the rewrite

### 💡 Recommendation
One clear, direct recommendation: which version should the user actually use and why."""


def call_groq(system_prompt: str, user_message: str, max_tokens: int = 2048) -> str:
    if not GROQ_API_KEY:
        raise HTTPException(
            500,
            "GROQ_API_KEY is not set. Add it to your .env file. "
            "Get a free key at https://console.groq.com/"
        )
    try:
        response = groq_client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_message}
            ],
            max_tokens=max_tokens,
            temperature=0.3,
            top_p=0.9,
        )
        return response.choices[0].message.content

    except Exception as e:
        err = str(e).lower()
        if "authentication" in err or "api key" in err or "invalid" in err:
            raise HTTPException(401, "Invalid Groq API key. Check your .env file.")
        elif "rate limit" in err or "rate_limit" in err:
            raise HTTPException(429, "Groq rate limit reached. Please wait a moment and try again.")
        elif "model" in err and "not found" in err:
            raise HTTPException(500, f"Model '{GROQ_MODEL}' not found. Check the model name in main.py.")
        else:
            raise HTTPException(500, f"Groq API error: {str(e)}")


# ================================================================
#  CODE REVIEW  ⚡ Powered by Groq AI
# ================================================================

@app.post("/api/review")
def review_code(
    body:    ReviewBody,
    user_id: int = Depends(require_auth),
    db=Depends(get_db),
):
    if not body.code.strip():
        raise HTTPException(400, "Code cannot be empty.")

    focus_str = ""
    if body.focus_areas:
        focus_str = f"\n\nFocus especially on: {', '.join(body.focus_areas)}."

    user_msg = (
        f"Please review the following {body.language} code:\n\n"
        f"```{body.language.lower()}\n"
        f"{body.code}\n"
        f"```\n\n"
        f"Provide a thorough review following your structured format.{focus_str}"
    )

    review_text = call_groq(REVIEW_SYSTEM, user_msg, max_tokens=2500)

    # Extract overall score
    m = re.search(r'Overall Score:\s*(\d+)\s*/\s*10', review_text, re.IGNORECASE)
    score = int(m.group(1)) if m else None

    # Extract severity counts
    sev_match = re.search(
        r'SEVERITY_COUNTS:\s*critical=(\d+)\s+high=(\d+)\s+medium=(\d+)\s+low=(\d+)',
        review_text, re.IGNORECASE
    )
    critical_count = int(sev_match.group(1)) if sev_match else 0
    high_count     = int(sev_match.group(2)) if sev_match else 0
    medium_count   = int(sev_match.group(3)) if sev_match else 0
    low_count      = int(sev_match.group(4)) if sev_match else 0

    # Clean up the severity line from the review text before returning
    clean_review = re.sub(
        r'\nSEVERITY_COUNTS:.*', '', review_text, flags=re.IGNORECASE | re.DOTALL
    ).strip()

    # Build a suggestions section from the review (everything from 💡 IMPROVEMENTS)
    suggestions = ""
    imp_match = re.search(r'(💡\s*IMPROVEMENTS.*)', clean_review, re.IGNORECASE | re.DOTALL)
    if imp_match:
        suggestions = imp_match.group(1)

    db.execute(
        text("""
            INSERT INTO code_reviews (user_id, language, code, review, score)
            VALUES (:u, :l, :c, :r, :s)
        """),
        {"u": user_id, "l": body.language, "c": body.code, "r": clean_review, "s": score}
    )
    db.commit()

    return {
        "review":          clean_review,
        "suggestions":     suggestions,
        "score":           score,
        "critical_count":  critical_count,
        "high_count":      high_count,
        "medium_count":    medium_count,
        "low_count":       low_count,
    }


# ================================================================
#  CODE REWRITE  ⚡ Powered by Groq AI
# ================================================================

@app.post("/api/rewrite")
def rewrite_code(
    body:    RewriteBody,
    user_id: int = Depends(require_auth),
    db=Depends(get_db),
):
    if not body.code.strip():
        raise HTTPException(400, "Code cannot be empty.")

    feedback_str = ""
    if body.review_feedback:
        feedback_str = f"\n\nContext from prior review:\n{body.review_feedback[:800]}"

    user_msg = (
        f"Rewrite and improve the following {body.language} code:\n\n"
        f"```{body.language.lower()}\n"
        f"{body.code}\n"
        f"```\n\n"
        f"Remember: if the code is already simple and correct, make minimal or no changes. "
        f"Return the rewritten code first, then IMPROVEMENTS_LIST and EXPLANATION.{feedback_str}"
    )

    raw = call_groq(REWRITE_SYSTEM, user_msg, max_tokens=2500)

    # Split out code vs improvements/explanation
    imp_split = re.split(r'\nIMPROVEMENTS_LIST:', raw, maxsplit=1, flags=re.IGNORECASE)
    code_part = imp_split[0].strip()
    meta_part = imp_split[1] if len(imp_split) > 1 else ""

    # Clean any accidental markdown fences from code part
    code_part = re.sub(r'^```[\w]*\n?', '', code_part)
    code_part = re.sub(r'\n?```$', '',   code_part).strip()

    # Parse improvements list
    improvements = []
    explanation  = ""
    if meta_part:
        exp_split = re.split(r'\nEXPLANATION:', meta_part, maxsplit=1, flags=re.IGNORECASE)
        imp_text = exp_split[0]
        improvements = [
            line.lstrip('-• ').strip()
            for line in imp_text.strip().splitlines()
            if line.strip().startswith(('-', '•')) and line.strip()[1:].strip()
        ]
        if len(exp_split) > 1:
            explanation = exp_split[1].strip()

    if not improvements:
        improvements = ["No significant changes needed — original code was already optimal"]

    # ── Honest side-by-side comparison ────────────────────────
    compare_msg = (
        f"Compare these two {body.language} code versions:\n\n"
        f"ORIGINAL (written by user):\n"
        f"```{body.language.lower()}\n{body.code}\n```\n\n"
        f"REWRITTEN (by AI):\n"
        f"```{body.language.lower()}\n{code_part}\n```\n\n"
        f"Be completely honest. If the original is simpler and equally correct, say so. "
        f"Penalise the rewrite if it added unnecessary complexity."
    )
    comparison = call_groq(COMPARE_SYSTEM, compare_msg, max_tokens=800)

    db.execute(
        text("""
            INSERT INTO code_rewrites (user_id, language, original_code, rewritten_code)
            VALUES (:u, :l, :o, :r)
        """),
        {"u": user_id, "l": body.language, "o": body.code, "r": code_part}
    )
    db.commit()

    return {
        "rewritten_code": code_part,
        "improvements":   improvements,
        "explanation":    explanation,
        "comparison":     comparison,
    }


# ── Dev entry point ────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)