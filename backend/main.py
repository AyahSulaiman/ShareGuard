from fastapi import FastAPI, HTTPException, status
from contextlib import asynccontextmanager
from database import SessionDep, create_db_and_tables
from models import User, UserCreate,UserPublic
from security import get_user, authenticate_user, get_password_hash


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield


app = FastAPI(lifespan=lifespan)


@app.get("/")
async def root():
    return {"message": "Hello World"}


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