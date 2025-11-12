import os
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Literal, Any

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field

from database import db, create_document, get_documents
from schemas import User as UserSchema, Task as TaskSchema

# Auth & Security
import jwt
from passlib.context import CryptContext
from bson import ObjectId

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
JWT_SECRET = os.getenv("SECRET_KEY", "dev_secret_change_me")
JWT_ALGO = "HS256"
JWT_EXPIRE_DAYS = 7

app = FastAPI(title="Decipline API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Helpers

def serialize_doc(doc: dict) -> dict:
    d = dict(doc)
    if d.get("_id"):
        d["id"] = str(d.pop("_id"))
    for k, v in list(d.items()):
        if isinstance(v, ObjectId):
            d[k] = str(v)
        if isinstance(v, datetime):
            d[k] = v.isoformat()
    return d


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_token(user_id: str, email: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRE_DAYS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1]
    data = decode_token(token)
    user_id = data.get("sub")
    user = db["user"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return serialize_doc(user)


# Request/Response Models

class SignUpRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class AuthResponse(BaseModel):
    token: str
    user: dict

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ProfileUpdate(BaseModel):
    role: Optional[Literal["student", "professional", "other"]] = None
    subject: Optional[str] = None
    goal: Optional[str] = None

class CreateTaskRequest(BaseModel):
    title: str
    description: Optional[str] = None
    category: Optional[str] = None
    frequency: Literal["daily", "weekly"] = "daily"

class UpdateTaskRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    completed: Optional[bool] = None
    progress: Optional[int] = Field(None, ge=0, le=100)


# Routes

@app.get("/")
def root():
    return {"message": "Decipline API is running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            try:
                response["collections"] = db.list_collection_names()
                response["database"] = "✅ Connected & Working"
                response["connection_status"] = "Connected"
            except Exception as e:
                response["database"] = f"⚠️ Connected but error: {str(e)[:80]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


@app.post("/auth/signup", response_model=AuthResponse)
def signup(payload: SignUpRequest):
    existing = db["user"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already in use")

    user = UserSchema(
        name=payload.name,
        email=payload.email,
        password_hash=hash_password(payload.password),
        premium=False,
    )
    user_id = create_document("user", user)
    doc = db["user"].find_one({"_id": ObjectId(user_id)})
    user_doc = serialize_doc(doc)
    token = create_token(user_doc["id"], user_doc["email"])
    # Hide hash
    user_doc.pop("password_hash", None)
    return {"token": token, "user": user_doc}


@app.post("/auth/login", response_model=AuthResponse)
def login(payload: LoginRequest):
    doc = db["user"].find_one({"email": payload.email})
    if not doc:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if not verify_password(payload.password, doc.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    user_doc = serialize_doc(doc)
    token = create_token(user_doc["id"], user_doc["email"])
    user_doc.pop("password_hash", None)
    return {"token": token, "user": user_doc}


@app.get("/me")
async def get_me(user: dict = Depends(get_current_user)):
    u = dict(user)
    u.pop("password_hash", None)
    return u


@app.put("/me/profile")
async def update_profile(update: ProfileUpdate, user: dict = Depends(get_current_user)):
    update_data = {k: v for k, v in update.model_dump().items() if v is not None}
    update_data["updated_at"] = datetime.now(timezone.utc)
    db["user"].update_one({"_id": ObjectId(user["id"])}, {"$set": update_data})
    refreshed = db["user"].find_one({"_id": ObjectId(user["id"])})
    u = serialize_doc(refreshed)
    u.pop("password_hash", None)
    return u


def generate_plan_suggestions(role: Optional[str], subject: Optional[str], goal: Optional[str]) -> List[dict]:
    base_daily = [
        {"title": "Focused study session (45 min)", "category": "Study", "frequency": "daily"},
        {"title": "Spaced repetition review", "category": "Review", "frequency": "daily"},
    ]
    weekly = [
        {"title": "Weekly progress reflection", "category": "Planning", "frequency": "weekly"},
        {"title": "Practice test / project", "category": "Practice", "frequency": "weekly"},
    ]
    extras = []
    if goal and "ielts" in goal.lower():
        extras += [
            {"title": "IELTS listening practice", "category": "Listening", "frequency": "daily"},
            {"title": "IELTS speaking practice", "category": "Speaking", "frequency": "weekly"},
        ]
    if subject and any(k in subject.lower() for k in ["code", "program", "dev"]):
        extras += [
            {"title": "Solve two coding problems", "category": "Practice", "frequency": "daily"},
            {"title": "Build feature for mini project", "category": "Project", "frequency": "weekly"},
        ]
    if role == "student":
        extras.append({"title": "Revise class notes", "category": "Review", "frequency": "daily"})
    if role == "professional":
        extras.append({"title": "Apply learning at work (15 min)", "category": "Application", "frequency": "weekly"})
    return base_daily + weekly + extras


@app.post("/tasks/generate")
async def generate_tasks(user: dict = Depends(get_current_user)):
    suggestions = generate_plan_suggestions(user.get("role"), user.get("subject"), user.get("goal"))
    created: List[dict] = []
    for s in suggestions:
        task = TaskSchema(
            user_id=user["id"],
            title=s["title"],
            description=None,
            category=s.get("category"),
            frequency=s.get("frequency", "daily"),
        )
        tid = create_document("task", task)
        doc = db["task"].find_one({"_id": ObjectId(tid)})
        created.append(serialize_doc(doc))
    return {"created": created, "count": len(created)}


@app.get("/tasks")
async def list_tasks(user: dict = Depends(get_current_user)):
    docs = db["task"].find({"user_id": user["id"]}).sort("created_at", -1)
    return [serialize_doc(d) for d in docs]


@app.post("/tasks")
async def create_task(payload: CreateTaskRequest, user: dict = Depends(get_current_user)):
    task = TaskSchema(
        user_id=user["id"],
        title=payload.title,
        description=payload.description,
        category=payload.category,
        frequency=payload.frequency,
    )
    tid = create_document("task", task)
    doc = db["task"].find_one({"_id": ObjectId(tid)})
    return serialize_doc(doc)


@app.patch("/tasks/{task_id}")
async def update_task(task_id: str, payload: UpdateTaskRequest, user: dict = Depends(get_current_user)):
    try:
        oid = ObjectId(task_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid task id")
    doc = db["task"].find_one({"_id": oid, "user_id": user["id"]})
    if not doc:
        raise HTTPException(status_code=404, detail="Task not found")
    update_data = {k: v for k, v in payload.model_dump().items() if v is not None}
    update_data["updated_at"] = datetime.now(timezone.utc)
    db["task"].update_one({"_id": oid}, {"$set": update_data})
    new_doc = db["task"].find_one({"_id": oid})
    return serialize_doc(new_doc)


@app.post("/billing/upgrade")
async def upgrade_to_premium(user: dict = Depends(get_current_user)):
    db["user"].update_one({"_id": ObjectId(user["id"])}, {"$set": {"premium": True, "updated_at": datetime.now(timezone.utc)}})
    refreshed = db["user"].find_one({"_id": ObjectId(user["id"])})
    u = serialize_doc(refreshed)
    u.pop("password_hash", None)
    return u


@app.get("/ai/advice")
async def ai_advice(user: dict = Depends(get_current_user)):
    if not user.get("premium"):
        raise HTTPException(status_code=403, detail="Premium required for AI advice")
    subject = user.get("subject") or "your subject"
    goal = user.get("goal") or "your goal"

    # Try OpenAI if key present, else fallback heuristic advice
    advice: str
    if os.getenv("OPENAI_API_KEY"):
        try:
            import openai
            openai.api_key = os.getenv("OPENAI_API_KEY")
            prompt = (
                "You are a study coach. Create a concise, actionable study advice list "
                f"for a learner working on {subject} towards {goal}. Include 5 bullet points with a daily and weekly cadence."
            )
            resp = openai.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
                max_tokens=220,
            )
            advice = resp.choices[0].message.content.strip()
        except Exception as e:
            advice = (
                "- Focus on one 45-minute deep work block daily\n"
                "- Alternate learning and practice sessions\n"
                "- Use spaced repetition for key concepts\n"
                "- Complete one weekly project/task aligned to your goal\n"
                "- Reflect every Sunday and adjust next week's plan"
            )
    else:
        advice = (
            "- Focus on one 45-minute deep work block daily\n"
            "- Alternate learning and practice sessions\n"
            "- Use spaced repetition for key concepts\n"
            "- Complete one weekly project/task aligned to your goal\n"
            "- Reflect every Sunday and adjust next week's plan"
        )

    return {"advice": advice, "subject": subject, "goal": goal}


# Optional: simple schema listing for tooling
@app.get("/schema")
def get_schema():
    return {
        "collections": [
            {
                "name": "user",
                "fields": [
                    "name", "email", "password_hash", "role", "subject", "goal", "premium", "created_at", "updated_at"
                ],
            },
            {
                "name": "task",
                "fields": [
                    "user_id", "title", "description", "category", "frequency", "completed", "progress", "created_at", "updated_at"
                ],
            },
        ]
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
