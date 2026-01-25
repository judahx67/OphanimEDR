"""Base Collector Abstract Class.

All collectors inherit from this base class to ensure consistent interface.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class EventType(str, Enum):
    """Types of events collected by the agent."""
    PROCESS_SNAPSHOT = "process_snapshot"
    PROCESS_START = "process_start"
    PROCESS_END = "process_end"
    SYSMON_EVENT = "sysmon_event"
    FILE_CREATED = "file_created"
    FILE_MODIFIED = "file_modified"
    FILE_DELETED = "file_deleted"
    FILE_MOVED = "file_moved"
    NETWORK_CONNECTION = "network_connection"


@dataclass
class Event:
    """Base event structure for all collector outputs.
    
    Designed for ML compatibility - can be serialized to JSON for logging
    and later parsed for feature extraction.
    """
    event_type: EventType
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    endpoint_id: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "endpoint_id": self.endpoint_id,
            "data": self.data,
        }


class BaseCollector(ABC):
    """Abstract base class for all data collectors.
    
    Collectors are responsible for gathering system events and converting
    them into Event objects that can be processed by the detection engine.
    """
    
    def __init__(self, endpoint_id: str = ""):
        self.endpoint_id = endpoint_id
        self._running = False
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name for this collector."""
        pass
    
    @abstractmethod
    async def start(self) -> None:
        """Start collecting events.
        
        This method should initialize any resources needed for collection.
        """
        pass
    
    @abstractmethod
    async def stop(self) -> None:
        """Stop collecting events and cleanup resources."""
        pass
    
    @abstractmethod
    async def collect(self) -> list[Event]:
        """Collect and return current events.
        
        For polling collectors (like process), this returns a snapshot.
        For streaming collectors (like filesystem), this drains the buffer.
        
        Returns:
            List of Event objects ready for processing.
        """
        pass
    
    def create_event(
        self,
        event_type: EventType,
        data: dict[str, Any],
        timestamp: datetime | None = None,
    ) -> Event:
        """Helper to create an event with common fields populated."""
        return Event(
            event_type=event_type,
            timestamp=timestamp or datetime.now(timezone.utc),
            endpoint_id=self.endpoint_id,
            data=data,
        )
    
    @property
    def is_running(self) -> bool:
        """Check if collector is currently active."""
        return self._running
