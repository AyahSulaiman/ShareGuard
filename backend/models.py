from pydantic import EmailStr
from datetime import datetime, timezone
from sqlmodel import SQLModel, Field

class UserBase(SQLModel):
    email: EmailStr


class UserCreate(UserBase):
    password: str = Field(min_length=8, description="Password must be at least 8 characters long")

class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: EmailStr = Field(unique=True)
    password_hash: str
    totp_secret: str | None = Field(default=None, description="TOTP secret for two-factor authentication")
    totp_enabled: bool = Field(default=False, description="Indicates if TOTP is enabled for the user")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), nullable=False )

class UserPublic(UserBase):
    id: int
    totp_enabled: bool
    created_at: datetime