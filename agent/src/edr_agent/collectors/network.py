"""Network Connection Collector.

Monitors network connections and tracks changes.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import psutil

from .base import BaseCollector, Event, EventType


logger = logging.getLogger(__name__)


@dataclass
class ConnectionInfo:
    """Structured network connection information."""
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    status: str
    pid: int
    process_name: str


class NetworkCollector(BaseCollector):
    """Collects network connection events.
    
    Tracks:
    - New outbound/inbound connections
    - Closed connections
    - Listening ports
    """
    
    def __init__(
        self,
        endpoint_id: str = "",
        poll_interval: float = 2.0,
        track_listening: bool = True,
    ):
        super().__init__(endpoint_id)
        self.poll_interval = poll_interval
        self.track_listening = track_listening
        
        # Connection tracking
        self._previous_connections: dict[str, ConnectionInfo] = {}
        self._previous_listeners: set[tuple[str, int]] = set()
    
    @property
    def name(self) -> str:
        return "NetworkCollector"
    
    async def start(self) -> None:
        """Initialize collector and capture initial state."""
        self._running = True
        
        # Capture initial state (don't report as new)
        self._previous_connections = self._get_current_connections()
        if self.track_listening:
            self._previous_listeners = self._get_listening_ports()
        
        logger.info(f"NetworkCollector started: {len(self._previous_connections)} active connections")
    
    async def stop(self) -> None:
        """Stop the collector."""
        self._running = False
        self._previous_connections.clear()
        self._previous_listeners.clear()
    
    async def collect(self) -> list[Event]:
        """Collect network connection changes."""
        events: list[Event] = []
        
        # Get current connections
        current_connections = self._get_current_connections()
        current_keys = set(current_connections.keys())
        previous_keys = set(self._previous_connections.keys())
        
        # New connections
        for key in current_keys - previous_keys:
            conn = current_connections[key]
            events.append(self.create_event(
                EventType.NETWORK_CONNECTION,
                {
                    "action": "connected",
                    "local_addr": conn.local_addr,
                    "local_port": conn.local_port,
                    "remote_addr": conn.remote_addr,
                    "remote_port": conn.remote_port,
                    "status": conn.status,
                    "pid": conn.pid,
                    "process_name": conn.process_name,
                }
            ))
        
        # Closed connections
        for key in previous_keys - current_keys:
            conn = self._previous_connections[key]
            events.append(self.create_event(
                EventType.NETWORK_CONNECTION,
                {
                    "action": "disconnected",
                    "local_addr": conn.local_addr,
                    "local_port": conn.local_port,
                    "remote_addr": conn.remote_addr,
                    "remote_port": conn.remote_port,
                    "pid": conn.pid,
                    "process_name": conn.process_name,
                }
            ))
        
        # Track listening ports
        if self.track_listening:
            current_listeners = self._get_listening_ports()
            
            # New listeners
            for addr, port in current_listeners - self._previous_listeners:
                events.append(self.create_event(
                    EventType.NETWORK_CONNECTION,
                    {
                        "action": "listening",
                        "local_addr": addr,
                        "local_port": port,
                    }
                ))
            
            # Stopped listening
            for addr, port in self._previous_listeners - current_listeners:
                events.append(self.create_event(
                    EventType.NETWORK_CONNECTION,
                    {
                        "action": "stopped_listening",
                        "local_addr": addr,
                        "local_port": port,
                    }
                ))
            
            self._previous_listeners = current_listeners
        
        self._previous_connections = current_connections
        return events
    
    def _get_current_connections(self) -> dict[str, ConnectionInfo]:
        """Get all current established connections."""
        connections = {}
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                # Skip connections without remote address (listeners, etc.)
                if not conn.raddr:
                    continue
                
                # Skip TIME_WAIT and other transitional states
                if conn.status not in ('ESTABLISHED', 'SYN_SENT', 'SYN_RECV'):
                    continue
                
                # Get process name
                process_name = ""
                if conn.pid:
                    try:
                        process_name = psutil.Process(conn.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                # Create connection key for tracking
                key = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}"
                
                connections[key] = ConnectionInfo(
                    local_addr=conn.laddr.ip,
                    local_port=conn.laddr.port,
                    remote_addr=conn.raddr.ip,
                    remote_port=conn.raddr.port,
                    status=conn.status,
                    pid=conn.pid or 0,
                    process_name=process_name,
                )
        except (psutil.AccessDenied, OSError) as e:
            logger.warning(f"Failed to get connections: {e}")
        
        return connections
    
    def _get_listening_ports(self) -> set[tuple[str, int]]:
        """Get all listening ports."""
        listeners = set()
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr:
                    listeners.add((conn.laddr.ip, conn.laddr.port))
        except (psutil.AccessDenied, OSError) as e:
            logger.warning(f"Failed to get listening ports: {e}")
        
        return listeners
