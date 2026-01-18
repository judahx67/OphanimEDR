"""Agent-to-Server communication module.

Handles:
- Endpoint registration on startup
- Event batching and sending
- Heartbeat mechanism
- Offline queueing with retry
"""

import asyncio
import logging
import platform
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from queue import Queue

import aiohttp

from .config import get_config


logger = logging.getLogger(__name__)


@dataclass
class ExfilConfig:
    """Configuration for server communication."""
    server_url: str = "http://localhost:8000"
    api_key: str = ""
    batch_size: int = 100
    batch_interval: float = 5.0  # seconds
    heartbeat_interval: float = 30.0  # seconds
    retry_count: int = 3
    retry_delay: float = 1.0  # seconds


def get_system_info() -> dict[str, Any]:
    """Gather system information for registration."""
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
    except Exception:
        hostname = platform.node()
        ip_address = "127.0.0.1"
    
    return {
        "hostname": hostname,
        "ip_address": ip_address,
        "os_type": "windows" if platform.system() == "Windows" else platform.system().lower(),
        "os_version": platform.version(),
        "agent_version": "0.1.0",
    }


class ServerExfilHandler:
    """Handles sending events to the management server.
    
    Features:
    - Batch sending (configurable size and interval)
    - Automatic retry with exponential backoff
    - Offline queueing
    - Heartbeat mechanism
    """
    
    def __init__(self, config: Optional[ExfilConfig] = None):
        agent_config = get_config()
        
        self.config = config or ExfilConfig(
            server_url=agent_config.server.url,
            api_key=agent_config.server.api_key,
        )
        
        self.endpoint_id = agent_config.endpoint_id
        self._event_queue: Queue = Queue()
        self._session: Optional[aiohttp.ClientSession] = None
        self._running = False
        self._registered = False
        self._offline_mode = False
        
        # Tasks
        self._batch_task: Optional[asyncio.Task] = None
        self._heartbeat_task: Optional[asyncio.Task] = None
    
    @property
    def headers(self) -> dict[str, str]:
        """Get HTTP headers for API requests."""
        headers = {
            "Content-Type": "application/json",
        }
        if self.config.api_key:
            headers["X-API-Key"] = self.config.api_key
        return headers
    
    async def start(self) -> None:
        """Start the exfil handler - register and start background tasks."""
        self._running = True
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10)
        )
        
        # Register with server
        await self._register()
        
        # Start background tasks
        self._batch_task = asyncio.create_task(self._batch_sender())
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        
        logger.info(f"ServerExfilHandler started (server: {self.config.server_url})")
    
    async def stop(self) -> None:
        """Stop the exfil handler - flush queue and cleanup."""
        self._running = False
        
        # Cancel background tasks
        if self._batch_task:
            self._batch_task.cancel()
            try:
                await self._batch_task
            except asyncio.CancelledError:
                pass
        
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        
        # Flush remaining events
        await self._flush_queue()
        
        # Close session
        if self._session:
            await self._session.close()
        
        logger.info("ServerExfilHandler stopped")
    
    async def _register(self) -> bool:
        """Register this endpoint with the server."""
        if not self._session:
            return False
        
        system_info = get_system_info()
        payload = {
            "endpoint_id": self.endpoint_id,
            **system_info,
        }
        
        url = f"{self.config.server_url}/api/endpoints/register"
        
        for attempt in range(self.config.retry_count):
            try:
                async with self._session.post(url, json=payload, headers=self.headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self._registered = True
                        self._offline_mode = False
                        logger.info(f"Registered with server: {data.get('message', 'OK')}")
                        return True
                    else:
                        logger.warning(f"Registration failed: {resp.status}")
            except aiohttp.ClientError as e:
                logger.warning(f"Registration attempt {attempt + 1} failed: {e}")
                await asyncio.sleep(self.config.retry_delay * (2 ** attempt))
        
        self._offline_mode = True
        logger.warning("Could not register - entering offline mode")
        return False
    
    def queue_events(self, events: list[dict[str, Any]]) -> None:
        """Queue events for batch sending.
        
        This is called synchronously from the event handler.
        """
        for event in events:
            self._event_queue.put(event)
    
    async def _batch_sender(self) -> None:
        """Background task that sends batched events."""
        while self._running:
            try:
                await asyncio.sleep(self.config.batch_interval)
                await self._flush_queue()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in batch sender: {e}")
    
    async def _flush_queue(self) -> None:
        """Send all queued events to server."""
        if self._event_queue.empty():
            return
        
        # Drain queue into batch
        batch = []
        while not self._event_queue.empty() and len(batch) < self.config.batch_size:
            try:
                batch.append(self._event_queue.get_nowait())
            except Exception:
                break
        
        if not batch:
            return
        
        # Convert events to API format
        events = []
        for event in batch:
            events.append({
                "event_type": event.get("event_type", "unknown"),
                "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "endpoint_id": self.endpoint_id,
                "data": event.get("data", {}),
            })
        
        payload = {
            "endpoint_id": self.endpoint_id,
            "events": events,
        }
        
        success = await self._send_events(payload)
        
        if not success:
            # Put events back in queue for retry
            for event in batch:
                self._event_queue.put(event)
            logger.warning(f"Re-queued {len(batch)} events for retry")
    
    async def _send_events(self, payload: dict) -> bool:
        """Send events payload to server."""
        if not self._session or self._offline_mode:
            return False
        
        url = f"{self.config.server_url}/api/events"
        
        for attempt in range(self.config.retry_count):
            try:
                async with self._session.post(url, json=payload, headers=self.headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        count = data.get("received_count", 0)
                        logger.debug(f"Sent {count} events to server")
                        return True
                    else:
                        logger.warning(f"Event send failed: {resp.status}")
            except aiohttp.ClientError as e:
                logger.warning(f"Event send attempt {attempt + 1} failed: {e}")
                await asyncio.sleep(self.config.retry_delay * (2 ** attempt))
        
        return False
    
    async def _heartbeat_loop(self) -> None:
        """Background task that sends periodic heartbeats."""
        while self._running:
            try:
                await asyncio.sleep(self.config.heartbeat_interval)
                await self._send_heartbeat()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in heartbeat: {e}")
    
    async def _send_heartbeat(self) -> bool:
        """Send heartbeat to server."""
        if not self._session:
            return False
        
        url = f"{self.config.server_url}/api/endpoints/{self.endpoint_id}/heartbeat"
        
        try:
            async with self._session.post(url, headers=self.headers) as resp:
                if resp.status == 200:
                    self._offline_mode = False
                    logger.debug("Heartbeat sent")
                    return True
                elif resp.status == 404:
                    # Endpoint not found - re-register
                    logger.warning("Endpoint not found, re-registering...")
                    await self._register()
                    return False
        except aiohttp.ClientError as e:
            if not self._offline_mode:
                logger.warning(f"Heartbeat failed, entering offline mode: {e}")
                self._offline_mode = True
            return False
        
        return False


def create_exfil_event_handler(handler: ServerExfilHandler):
    """Create an event handler function for use with AgentCore.
    
    Returns a synchronous function that queues events for the async handler.
    """
    def event_handler(events):
        # Convert Event objects to dicts
        event_dicts = []
        for event in events:
            event_dicts.append({
                "event_type": event.event_type.value,
                "timestamp": event.timestamp.isoformat(),
                "endpoint_id": event.endpoint_id,
                "data": event.data,
            })
        handler.queue_events(event_dicts)
    
    return event_handler
