from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, status
from contextlib import asynccontextmanager
from fastapi.security import OAuth2PasswordRequestForm
from database import SessionDep, create_db_and_tables
from models import Token, User, UserCreate,UserPublic
from security import create_access_token, get_user, authenticate_user, get_password_hash



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
