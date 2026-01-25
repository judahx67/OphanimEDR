"""Filesystem Collector using watchdog.

Monitors file system changes in configured directories.
"""

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from queue import Queue, Empty
from typing import Any

from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileModifiedEvent,
    FileDeletedEvent,
    FileMovedEvent,
    DirCreatedEvent,
    DirModifiedEvent,
    DirDeletedEvent,
    DirMovedEvent,
)
from watchdog.observers import Observer

from .base import BaseCollector, Event, EventType


logger = logging.getLogger(__name__)


class FileEventHandler(FileSystemEventHandler):
    """Handler that queues file system events for async processing."""
    
    def __init__(self, event_queue: Queue, endpoint_id: str):
        super().__init__()
        self.event_queue = event_queue
        self.endpoint_id = endpoint_id
    
    def _create_event_data(self, event: Any) -> dict[str, Any]:
        """Create event data dictionary from watchdog event."""
        return {
            "path": event.src_path,
            "is_directory": event.is_directory,
        }
    
    def on_created(self, event: FileCreatedEvent | DirCreatedEvent) -> None:
        self.event_queue.put({
            "type": EventType.FILE_CREATED,
            "data": self._create_event_data(event),
            "timestamp": datetime.now(timezone.utc),
        })
    
    def on_modified(self, event: FileModifiedEvent | DirModifiedEvent) -> None:
        # Skip directory modifications (too noisy)
        if event.is_directory:
            return
        self.event_queue.put({
            "type": EventType.FILE_MODIFIED,
            "data": self._create_event_data(event),
            "timestamp": datetime.now(timezone.utc),
        })
    
    def on_deleted(self, event: FileDeletedEvent | DirDeletedEvent) -> None:
        self.event_queue.put({
            "type": EventType.FILE_DELETED,
            "data": self._create_event_data(event),
            "timestamp": datetime.now(timezone.utc),
        })
    
    def on_moved(self, event: FileMovedEvent | DirMovedEvent) -> None:
        data = self._create_event_data(event)
        data["dest_path"] = event.dest_path
        self.event_queue.put({
            "type": EventType.FILE_MOVED,
            "data": data,
            "timestamp": datetime.now(timezone.utc),
        })


class FilesystemCollector(BaseCollector):
    """Collects file system change events using watchdog.
    
    Monitors configured directories for file creation, modification,
    deletion, and movement events.
    """
    
    def __init__(
        self,
        endpoint_id: str = "",
        watch_paths: list[str] | None = None,
        recursive: bool = True,
        max_queue_size: int = 10000,
    ):
        super().__init__(endpoint_id)
        self.watch_paths = watch_paths or []
        self.recursive = recursive
        self._event_queue: Queue = Queue(maxsize=max_queue_size)
        self._observer: Observer | None = None
        self._handler: FileEventHandler | None = None
    
    @property
    def name(self) -> str:
        return "FilesystemCollector"
    
    async def start(self) -> None:
        """Start watching configured directories."""
        if not self.watch_paths:
            # Default to user home if no paths configured
            self.watch_paths = [str(Path.home())]
        
        self._running = True
        self._handler = FileEventHandler(self._event_queue, self.endpoint_id)
        self._observer = Observer()
        
        watched_count = 0
        for path in self.watch_paths:
            path_obj = Path(path)
            if path_obj.exists() and path_obj.is_dir():
                try:
                    self._observer.schedule(
                        self._handler,
                        path,
                        recursive=self.recursive
                    )
                    watched_count += 1
                    logger.debug(f"Watching: {path}")
                except Exception as e:
                    logger.warning(f"Failed to watch {path}: {e}")
            else:
                logger.warning(f"Path does not exist or is not a directory: {path}")
        
        if watched_count > 0:
            self._observer.start()
            logger.info(f"FilesystemCollector watching {watched_count} paths")
        else:
            logger.warning("FilesystemCollector: No valid paths to watch")
    
    async def stop(self) -> None:
        """Stop watching and cleanup."""
        self._running = False
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5.0)
            self._observer = None
        self._handler = None
        
        # Clear the queue
        while not self._event_queue.empty():
            try:
                self._event_queue.get_nowait()
            except Empty:
                break
    
    async def collect(self) -> list[Event]:
        """Drain the event queue and return collected events."""
        events: list[Event] = []
        
        # Drain queue (non-blocking)
        while not self._event_queue.empty():
            try:
                raw = self._event_queue.get_nowait()
                events.append(self.create_event(
                    raw["type"],
                    raw["data"],
                    timestamp=raw["timestamp"],
                ))
            except Empty:
                break
            
            # Limit batch size to prevent memory issues
            if len(events) >= 1000:
                break
        
        return events
