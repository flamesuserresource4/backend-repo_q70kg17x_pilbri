"""
Database Schemas for Decipline

Each Pydantic model represents a collection in MongoDB.
Collection name is the lowercase of the class name.

- User -> "user"
- Task -> "task"
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import datetime

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Unique email address")
    password_hash: str = Field(..., description="Hashed password")
    role: Optional[Literal["student", "professional", "other"]] = Field(None, description="Who they are")
    subject: Optional[str] = Field(None, description="Subject or skill currently learning")
    goal: Optional[str] = Field(None, description="Goal or exam (IELTS, coding, etc.)")
    premium: bool = Field(False, description="Premium plan flag")
    created_at: Optional[datetime] = Field(None, description="Creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")

class Task(BaseModel):
    user_id: str = Field(..., description="Owner user id (string ObjectId)")
    title: str = Field(..., description="Task title")
    description: Optional[str] = Field(None, description="Task details")
    category: Optional[str] = Field(None, description="Reading, Practice, Review, etc.")
    frequency: Literal["daily", "weekly"] = Field("daily", description="Task cadence")
    due_date: Optional[datetime] = Field(None, description="Due date if applicable")
    completed: bool = Field(False, description="Completion status")
    progress: int = Field(0, ge=0, le=100, description="Progress percent")
    created_at: Optional[datetime] = Field(None)
    updated_at: Optional[datetime] = Field(None)
