from __future__ import annotations

import asyncio
import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class DecoyProtocol(Enum):
    SSH = "ssh"
    TELNET = "telnet"
    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    SMTP = "smtp"
    MYSQL = "mysql"
    POSTGRES = "postgres"
    CUSTOM = "custom"


@dataclass
class DecoyConfig:
    protocol: DecoyProtocol
    host: str = "0.0.0.0"
    port: int = 0
    banner: str = ""
    max_sessions: int = 10
    idle_timeout_s: float = 300.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DecoySession:
    session_id: str = ""
    decoy_id: str = ""
    remote_addr: str = ""
    remote_port: int = 0
    connected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_activity: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    command_count: int = 0
    commands: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class DecoyService(ABC):
    def __init__(self, config: DecoyConfig) -> None:
        self.config = config
        self._id = f"{config.protocol.value}_{config.port}_{uuid.uuid4().hex[:8]}"
        self._sessions: dict[str, DecoySession] = {}
        self._running = False
        self._server: Any = None

    @property
    def service_id(self) -> str:
        return self._id

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def active_sessions(self) -> list[DecoySession]:
        return list(self._sessions.values())

    @abstractmethod
    async def start(self) -> None: ...

    @abstractmethod
    async def stop(self) -> None: ...

    @abstractmethod
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None: ...

    def create_session(self, addr: str, port: int) -> DecoySession:
        session = DecoySession(
            session_id=uuid.uuid4().hex,
            decoy_id=self._id,
            remote_addr=addr,
            remote_port=port,
        )
        self._sessions[session.session_id] = session
        return session

    def close_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def record_command(self, session_id: str, command: str) -> None:
        session = self._sessions.get(session_id)
        if session:
            session.commands.append(command)
            session.command_count += 1
            session.last_activity = datetime.now(timezone.utc)

    def prune_stale_sessions(self) -> int:
        now = datetime.now(timezone.utc)
        stale = [
            sid
            for sid, s in self._sessions.items()
            if (now - s.last_activity).total_seconds() > self.config.idle_timeout_s
        ]
        for sid in stale:
            self._sessions.pop(sid, None)
        if stale:
            logger.debug("Pruned %d stale sessions from %s", len(stale), self._id)
        return len(stale)

    async def send_banner(self, writer: asyncio.StreamWriter) -> None:
        if self.config.banner:
            writer.write(self.config.banner.encode() + b"\r\n")
            await writer.drain()

    async def read_line(self, reader: asyncio.StreamReader) -> str:
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=self.config.idle_timeout_s)
            return data.decode("utf-8", errors="replace").strip()
        except asyncio.TimeoutError:
            return ""

    async def send_response(self, writer: asyncio.StreamWriter, text: str) -> None:
        writer.write(text.encode() + b"\r\n")
        await writer.drain()
