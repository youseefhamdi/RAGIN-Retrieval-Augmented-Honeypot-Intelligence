from __future__ import annotations

import asyncio
import logging

from ragin.decoys.base import DecoyProtocol, DecoyService, DecoySession

logger = logging.getLogger(__name__)


class DecoyManager:
    def __init__(self) -> None:
        self._services: dict[str, DecoyService] = {}
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def active_services(self) -> list[DecoyService]:
        return list(self._services.values())

    def register(self, service: DecoyService) -> None:
        self._services[service.service_id] = service
        logger.info(
            "Registered decoy %s (%s on port %d)",
            service.service_id,
            service.config.protocol.value,
            service.config.port,
        )

    def unregister(self, service_id: str) -> None:
        service = self._services.pop(service_id, None)
        if service:
            logger.info("Unregistered decoy %s", service_id)

    async def start_all(self) -> None:
        self._running = True
        tasks = []
        for service in self._services.values():
            tasks.append(service.start())
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("Started %d decoy services", len(tasks))

    async def stop_all(self) -> None:
        self._running = False
        tasks = []
        for service in self._services.values():
            tasks.append(service.stop())
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("Stopped %d decoy services", len(tasks))

    def get_service(self, protocol: DecoyProtocol, port: int) -> DecoyService | None:
        for service in self._services.values():
            if service.config.protocol == protocol and service.config.port == port:
                return service
        return None

    def get_sessions(self) -> list[DecoySession]:
        sessions = []
        for service in self._services.values():
            sessions.extend(service.active_sessions)
        return sessions

    def prune_all(self) -> int:
        total = 0
        for service in self._services.values():
            total += service.prune_stale_sessions()
        return total
