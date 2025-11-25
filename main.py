from fastapi import FastAPI
import models
from database import engine, Base
from routers import users, telco
from fastapi.middleware.cors import CORSMiddleware

# create DB tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Telco Automation API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(users.router)
app.include_router(telco.router)

