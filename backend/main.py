import secrets
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, UploadFile, status
from contextlib import asynccontextmanager
from fastapi.security import OAuth2PasswordRequestForm
from database import SessionDep, create_db_and_tables
from models import FilePublic, Token, User, UserCreate,UserPublic,File
from security import create_access_token, get_user, authenticate_user, get_password_hash, CurrentUserDep
from pathlib import Path


UPLOADS_DIR = Path("uploads")
MAX_FILE_SIZE = 10*1024*1024
CHUNK_SIZE = 1*1024*1024

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield


app = FastAPI(lifespan=lifespan)


# @app.get("/")
# async def root():
#     return {"message": "Hello World"}


@app.post("/users/", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
def create_user(user: UserCreate, session: SessionDep):
    existing_user = get_user(session, user.email)
    if existing_user:
        raise HTTPException(status_code=409, detail="Email already registered")
    extra_data = {"password_hash": get_password_hash(user.password), "email": user.email.lower()}
    db_user = User.model_validate(user, update=extra_data)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user

@app.post("/auth/token")
def login_for_access_token(session: SessionDep,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(session,form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": str(user.id)})
    return Token(access_token=access_token, token_type="bearer")


@app.get("/users/me/", response_model=UserPublic)
def read_current_user(current_user: CurrentUserDep) -> User:
    return current_user


@app.post("/files/", response_model=FilePublic, status_code=status.HTTP_201_CREATED)
def create_file(file: UploadFile, current_user: CurrentUserDep, session: SessionDep):
    stored_name = secrets.token_hex(16)
    file_path = UPLOADS_DIR / stored_name

    with open(file_path,"wb") as dest:
        total = 0
        while True:
            chunk = file.file.read(CHUNK_SIZE)
            total += len(chunk)
            if total > MAX_FILE_SIZE or not chunk:
                break
            dest.write(chunk)

    if total > MAX_FILE_SIZE:
        file_path.unlink()
        raise HTTPException(status_code=413, detail="The request body is larger than max limit")
    
    db_file = File(
                owner_id=current_user.id,
                original_name=file.filename or "unnamed",
                stored_name=stored_name,
                content_type=file.content_type,
                size_bytes=total
    )
    session.add(db_file)
    session.commit()
    session.refresh(db_file)
    return db_file

