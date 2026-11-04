from datetime import datetime, timedelta, timezone
import secrets
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, UploadFile, status, Request
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
from fastapi.security import OAuth2PasswordRequestForm
from database import SessionDep, create_db_and_tables
from models import FilePublic, LinkRecipient, ShareLink, ShareLinkCreate, ShareLinkPublic, Token, User, UserCreate,UserPublic,File,AccessResult
from security import create_access_token, get_user, authenticate_user, get_password_hash, CurrentUserDep
from pathlib import Path
from sqlmodel import select
from audit import log_access


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

@app.get("/files/", response_model=list[FilePublic])
def get_user_files(current_user: CurrentUserDep, session: SessionDep):
    statement = select(File).where(File.owner_id == current_user.id)
    file_list = session.exec(statement).all()
    return file_list

@app.post("/files/{file_id}/links/",response_model=ShareLinkPublic, status_code=status.HTTP_201_CREATED)
def create_share_link(file_id: int, link_in: ShareLinkCreate, current_user: CurrentUserDep, session: SessionDep):
    file = session.get(File, file_id)
    if file is None or file.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="file does not exist")
    generated_token = secrets.token_urlsafe(32)
    expire =  datetime.now(timezone.utc) + timedelta(hours=link_in.expires_in_hours)
    db_sharelink = ShareLink(file_id=file.id, token=generated_token, expires_at=expire, max_downloads=link_in.max_downloads)
    session.add(db_sharelink)
    session.flush()
    session.refresh(db_sharelink)
    unique_emails = set()
    for email in link_in.recipients:
        unique_emails.add(email.lower())
    for user_email in unique_emails:
        recipient = LinkRecipient(link_id=db_sharelink.id, email=user_email)
        session.add(recipient)
    session.commit()
    session.refresh(db_sharelink)
    return db_sharelink

@app.post("/links/{link_id}/revoke/", response_model=ShareLinkPublic)
def revoke_link(link_id: int, current_user: CurrentUserDep, session: SessionDep):
    link = session.get(ShareLink, link_id)
    if link is None:
        raise HTTPException(status_code=404, detail="Link not found")
    file = session.get(File, link.file_id)
    if file is None or file.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Link not found")
    link.revoked = True
    session.add(link)
    session.commit()
    session.refresh(link)
    return link


@app.get("/links/{token}/download/")
def download_file(token: str, current_user: CurrentUserDep, session: SessionDep, request: Request):
    link = session.exec(select(ShareLink).where(ShareLink.token == token)).first()
    if link is None:
        raise HTTPException(status_code=404, detail="Link not found")
    recipient = session.exec(select(LinkRecipient).where(LinkRecipient.link_id == link.id, LinkRecipient.email == current_user.email)).first()
    if recipient is None:
        log_access(session=session, link=link, user=current_user, request=request, result=AccessResult.NOT_RECIPIENT)
        raise HTTPException(status_code=403, detail="You Do Not Have Access To This Link")
    if link.revoked:
        log_access(session=session, link=link, user=current_user, request=request, result=AccessResult.REVOKED)
        raise HTTPException(status_code=410, detail="Link revoked")
    expiry = link.expires_at.replace(tzinfo=timezone.utc)
    if expiry <= datetime.now(timezone.utc):
        log_access(session=session, link=link, user=current_user, request=request, result=AccessResult.EXPIRED)
        raise HTTPException(status_code=410, detail="Link expired")
    if link.max_downloads <= link.download_count:
        log_access(session=session, link=link, user=current_user, request=request, result=AccessResult.LIMIT_REACHED)
        raise HTTPException(status_code=410, detail="Download limit reached")

    file = session.get(File, link.file_id)
    file_path = UPLOADS_DIR / file.stored_name
    link.download_count += 1
    log_access(session=session, link=link, user=current_user, request=request, result=AccessResult.SUCCESS)

    return FileResponse(path=file_path, media_type=file.content_type, filename=file.original_name)
