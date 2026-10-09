from fastapi import FastAPI
from contextlib import asynccontextmanager
from database import create_db_and_tables
from models import User


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield


app = FastAPI(lifespan=lifespan)


@app.get("/")
async def root():
    return {"message": "Hello World"}