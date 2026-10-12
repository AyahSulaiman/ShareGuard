from datetime import datetime, timedelta, timezone
from os import getenv
from typing import Annotated
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from sqlmodel import Session, select
from models import User
from database import SessionDep



password_hash = PasswordHash.recommended()
DUMMY_HASH = password_hash.hash("dummypassword")
ALGORITHM = "HS256"
load_dotenv()
SECRET_KEY = getenv("SECRET_KEY")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

if not SECRET_KEY:
    raise ValueError("SECRET_KEY variable is not set")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hash.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return password_hash.hash(password)


def get_user(session: Session, email: str) -> User | None:
    return session.exec(select(User).where(User.email == email.lower())).first()


def authenticate_user(session: Session, email: str, password: str) -> User | None:
    user = get_user(session, email)
    if not user:
        verify_password(password, DUMMY_HASH)
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], session: SessionDep)-> User:
    credentials_exception = HTTPException(
        status_code = status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        user_id = int(user_id)
    except (InvalidTokenError, ValueError):
        raise credentials_exception
    user = session.get(User, user_id)
    if user is None:
        raise credentials_exception
    return user

CurrentUserDep = Annotated[User, Depends(get_current_user)]