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


class Token(SQLModel):
    access_token: str
    token_type: str

class File(SQLModel, table=True):
    id: int | None = Field(primary_key=True, default=None)
    original_name: str
    stored_name: str = Field(unique=True)
    content_type: str
    size_bytes: int
    uploaded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), nullable=False)
    owner_id: int = Field(foreign_key="user.id")

class FilePublic(SQLModel):
    id : int
    original_name : str
    content_type : str
    size_bytes: int
    uploaded_at: datetime


class ShareLinkCreate(SQLModel):
    recipients: list[EmailStr] = Field(min_length=1, max_length=20)
    expires_in_hours: int = Field(ge=1, le=720, description="The time limit must be between 1 and 720 hours")
    max_downloads: int = Field(ge=1, description="maximum downloads must be at least 1")


class ShareLink(SQLModel, table=True):
    id: int | None = Field(primary_key=True, default=None)
    file_id: int = Field(foreign_key="file.id")
    token: str = Field(unique=True)
    expires_at: datetime 
    max_downloads: int
    download_count: int = Field(default=0)
    revoked: bool = Field(default=False)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))    


class ShareLinkPublic(SQLModel):
    id: int
    token: str 
    expires_at: datetime
    max_downloads: int
    download_count: int 
    revoked: bool 
    created_at: datetime  


class LinkRecipient(SQLModel, table=True):
    id: int | None = Field(primary_key=True,default=None)
    link_id: int = Field(foreign_key="sharelink.id")
    email: EmailStr