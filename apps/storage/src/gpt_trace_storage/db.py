from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import settings


def _json_dumps(value: Any) -> str:
    """Serialize JSON with control characters escaped for PostgreSQL JSON input."""
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


engine = create_async_engine(
    settings.storage_database_url,
    pool_pre_ping=True,
    json_serializer=_json_dumps,
    json_deserializer=json.loads,
)
SessionFactory = async_sessionmaker(
    engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


async def get_session() -> AsyncIterator[AsyncSession]:
    async with SessionFactory() as session:
        yield session
