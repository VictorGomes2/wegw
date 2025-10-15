# app.py
# =============================================================================
# FastAPI + SQLAlchemy + JWT - VERSÃO FINAL CORRIGIDA
# =============================================================================

import os
import sys
import re  # Importado para a regra inteligente de CORS
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from sqlalchemy import String, Integer, DateTime, func, select
from sqlalchemy.orm import Mapped, mapped_column, declarative_base
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
)

from passlib.context import CryptContext
from jose import jwt, JWTError

# =============================================================================
# Configurações de Ambiente
# =============================================================================

DATABASE_URL_RAW = os.getenv("DATABASE_URL", "").strip()
if not DATABASE_URL_RAW:
    raise RuntimeError("A variável de ambiente DATABASE_URL não foi definida.")

JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-key-change-me")
JWT_ALG = "HS256"
JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", "360"))

INIT_ADMIN = os.getenv("INIT_ADMIN", "true").lower() == "true"
INIT_ADMIN_USER = os.getenv("INIT_ADMIN_USER", "admin")
INIT_ADMIN_PASS = os.getenv("INIT_ADMIN_PASS", "123")

# =============================================================================
# Normalização de DATABASE_URL para asyncpg
# =============================================================================

u = urlparse(DATABASE_URL_RAW)
scheme = u.scheme or "postgresql"
if scheme == "postgresql":
    scheme = "postgresql+asyncpg"
elif scheme.startswith("postgresql+") and "asyncpg" not in scheme:
    scheme = "postgresql+asyncpg"

host = (u.hostname or "")
is_external = "." in host

qs = dict(parse_qsl(u.query or "", keep_blank_values=True))
qs.pop("sslmode", None)
qs.pop("ssl", None)

if is_external:
    qs["ssl"] = "true"

DATABASE_URL = urlunparse(u._replace(scheme=scheme, query=urlencode(qs)))

# =============================================================================
# Banco de Dados (SQLAlchemy 2.0 assíncrono)
# =============================================================================

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(150), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

engine_kwargs = dict(echo=False, pool_pre_ping=True)
if is_external:
    engine_kwargs["connect_args"] = {"ssl": True}

engine = create_async_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# =============================================================================
# Utilidades de Autenticação
# =============================================================================

def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    return pwd_ctx.verify(password, password_hash)

def create_access_token(sub: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRES_MIN)
    payload = {"sub": sub, "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def decode_access_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        sub: str = payload.get("sub")
        if sub is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido (sem sub).")
        return sub
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Token inválido: {str(e)}")

# =============================================================================
# Schemas (Pydantic)
# =============================================================================

class LoginIn(BaseModel):
    # Padronizado para username e password
    username: str
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class MeOut(BaseModel):
    id: int
    username: str
    created_at: datetime

# =============================================================================
# App FastAPI
# =============================================================================

app = FastAPI(title="Auth API", version="1.0.0")

# SOLUÇÃO DE CORS DEFINITIVA E INTELIGENTE
CORS_ORIGINS_REGEX = r"https?:\/\/((localhost|127\.0\.0\.1)(:\d+)?|.*\.netlify\.app|.*\.onrender\.com|null)"

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=CORS_ORIGINS_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# Startup / Shutdown
# =============================================================================

@app.on_event("startup")
async def startup() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    if INIT_ADMIN:
        async with SessionLocal() as session:
            res = await session.execute(select(User).where(User.username == INIT_ADMIN_USER))
            user = res.scalar_one_or_none()
            if not user:
                user = User(username=INIT_ADMIN_USER, password_hash=hash_password(INIT_ADMIN_PASS))
                session.add(user)
                await session.commit()
                print(f"[startup] Usuário admin criado: {INIT_ADMIN_USER}/{INIT_ADMIN_PASS}", file=sys.stderr)
            else:
                print("[startup] Usuário admin já existe; pulando criação.", file=sys.stderr)

# =============================================================================
# Dependências
# =============================================================================

async def get_db() -> AsyncSession:
    async with SessionLocal() as session:
        yield session

# =============================================================================
# Rotas
# =============================================================================

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/auth/login", response_model=TokenOut)
async def login(body: LoginIn, db: AsyncSession = Depends(get_db)):
    # CORREÇÃO DO ERRO 500
    res = await db.execute(select(User).where(User.username == body.username))
    user = res.scalar_one_or_none()

    # A verificação agora é segura: primeiro checa se o usuário existe
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário ou senha inválidos."
        )
    
    token = create_access_token(sub=user.username)
    return TokenOut(access_token=token)


@app.get("/me", response_model=MeOut)
async def me(authorization: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    # O Header de autorização é "Authorization", com A maiúsculo.
    # O FastAPI já normaliza para minúsculo, mas é bom pegar o header diretamente.
    from fastapi.requests import Request
    
    async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
        auth_header = request.headers.get("authorization")
        if not auth_header or not auth_header.lower().startswith("bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Header Authorization ausente ou mal formatado.")
        
        token = auth_header.split(" ", 1)[1].strip()
        username = decode_access_token(token)
        
        res = await db.execute(select(User).where(User.username == username))
        user = res.scalar_one_or_none()
        
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário do token não encontrado.")
            
        return user

    current_user = await get_current_user(Request(scope={"type": "http", "headers": [(b"authorization", authorization.encode())]}), db)
    return MeOut(id=current_user.id, username=current_user.username, created_at=current_user.created_at)


@app.get("/")
async def root():
    return {"message": "API no ar. Use /docs para ver a documentação."}

# =============================================================================
# Execução local
# =============================================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=True)