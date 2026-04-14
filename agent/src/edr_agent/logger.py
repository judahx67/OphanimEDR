"""Local JSON Logger with Rotation.

Writes events to local JSON Lines (.jsonl) files with automatic rotation.
Logs are stored in %APPDATA%/EDR/logs/ on Windows.
"""

import json
import logging
import os
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .collectors.base import Event


logger = logging.getLogger(__name__)


def get_log_directory() -> Path:
    """Get the log directory path.
    
    On Windows: %APPDATA%/EDR/logs/
    On Linux/Mac: ~/.edr/logs/
    """
    if platform.system() == "Windows":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            return Path(appdata) / "EDR" / "logs"
    
    # Fallback for non-Windows or missing APPDATA
    return Path.home() / ".edr" / "logs"


class JSONLogger:
    """Rotating JSON Lines logger for event storage.
    
    Features:
    - JSON Lines format (.jsonl) for streaming/ML compatibility
    - Automatic rotation by file size
    - Configurable rotation size and backup count
    """
    
    def __init__(
        self,
        log_dir: Path | str | None = None,
        max_bytes: int = 10 * 1024 * 1024,  # 10MB default
        backup_count: int = 10,
        filename_prefix: str = "events",
    ):
        self.log_dir = Path(log_dir) if log_dir else get_log_directory()
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.filename_prefix = filename_prefix
        
        self._current_file: Path | None = None
        self._file_handle = None
        self._bytes_written = 0
        self._event_count = 0
        
        # Ensure log directory exists
        self._ensure_log_dir()
    
    def _ensure_log_dir(self) -> None:
        """Create log directory if it doesn't exist."""
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Log directory: {self.log_dir}")
        except Exception as e:
            logger.error(f"Failed to create log directory: {e}")
            raise
    
    def _get_current_filename(self) -> Path:
        """Get the current log file name with date."""
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return self.log_dir / f"{self.filename_prefix}_{date_str}.jsonl"
    
    def _open_file(self) -> None:
        """Open or rotate the current log file."""
        target_file = self._get_current_filename()
        
        # Check if we need to rotate (different day or size exceeded)
        if self._current_file != target_file:
            self._close_file()
            self._current_file = target_file
            self._bytes_written = target_file.stat().st_size if target_file.exists() else 0
        
        # Check size rotation
        if self._bytes_written >= self.max_bytes:
            self._rotate_file()
        
        # Open file for appending
        if self._file_handle is None:
            self._file_handle = open(self._current_file, "a", encoding="utf-8")
    
    def _close_file(self) -> None:
        """Close the current log file."""
        if self._file_handle:
            try:
                self._file_handle.close()
            except Exception:
                pass
            self._file_handle = None
    
    def _rotate_file(self) -> None:
        """Rotate the current log file."""
        self._close_file()
        
        if not self._current_file or not self._current_file.exists():
            return
        
        # Find next available rotation number
        for i in range(1, self.backup_count + 1):
            rotated = self._current_file.with_suffix(f".{i}.jsonl")
            if not rotated.exists():
                self._current_file.rename(rotated)
                logger.info(f"Rotated log to: {rotated.name}")
                break
        else:
            # All rotation slots full, delete oldest
            oldest = self._current_file.with_suffix(f".{self.backup_count}.jsonl")
            if oldest.exists():
                oldest.unlink()
            # Shift all files
            for i in range(self.backup_count - 1, 0, -1):
                src = self._current_file.with_suffix(f".{i}.jsonl")
                dst = self._current_file.with_suffix(f".{i + 1}.jsonl")
                if src.exists():
                    src.rename(dst)
            # Rename current
            self._current_file.rename(self._current_file.with_suffix(".1.jsonl"))
        
        self._bytes_written = 0
    
    def write_event(self, event: Event) -> None:
        """Write a single event to the log file."""
        self._open_file()
        
        try:
            event_dict = {
                "ts": event.timestamp.isoformat(),
                "type": event.event_type.value,
                "endpoint_id": event.endpoint_id,
                "data": event.data,
            }
            
            line = json.dumps(event_dict, default=str) + "\n"
            self._file_handle.write(line)
            self._bytes_written += len(line.encode("utf-8"))
            self._event_count += 1
            
        except Exception as e:
            logger.error(f"Failed to write event: {e}")
    
    def write_events(self, events: list[Event]) -> int:
        """Write multiple events to the log file.
        
        Returns the number of events written.
        """
        count = 0
        for event in events:
            try:
                self.write_event(event)
                count += 1
            except Exception:
                continue
        
        # Flush after batch
        self.flush()
        return count
    
    def flush(self) -> None:
        """Flush the current file to disk."""
        if self._file_handle:
            try:
                self._file_handle.flush()
            except Exception:
                pass
    
    def close(self) -> None:
        """Close the logger and release resources."""
        self._close_file()
        logger.info(f"JSONLogger closed. Total events written: {self._event_count}")
    
    def get_stats(self) -> dict[str, Any]:
        """Get logger statistics."""
        return {
            "log_dir": str(self.log_dir),
            "current_file": str(self._current_file) if self._current_file else None,
            "bytes_written": self._bytes_written,
            "events_written": self._event_count,
        }
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def create_json_logger_handler(json_logger: JSONLogger):
    """Create an event handler function for use with AgentCore.
    
    Returns a synchronous function that writes events to the JSON logger.
    """
    def event_handler(events: list[Event]) -> None:
        json_logger.write_events(events)
    
    return event_handler
