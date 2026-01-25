"""Event Parser/Filter Engine.

Filters noise and normalizes events before storage/exfiltration.
This reduces database bloat by removing routine system activity.
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from .collectors.base import Event, EventType


logger = logging.getLogger(__name__)


@dataclass
class FilterRule:
    """A rule for filtering events."""
    name: str
    event_types: list[EventType] | None = None  # None = all types
    field_path: str = ""  # Dot notation: "data.name"
    pattern: str = ""  # Regex pattern
    action: str = "drop"  # "drop" or "allow"
    
    _compiled: re.Pattern | None = field(default=None, repr=False)
    
    def __post_init__(self):
        if self.pattern:
            self._compiled = re.compile(self.pattern, re.IGNORECASE)
    
    def matches(self, event: Event) -> bool:
        """Check if event matches this rule."""
        # Check event type
        if self.event_types and event.event_type not in self.event_types:
            return False
        
        # Get field value using dot notation
        value = self._get_field_value(event, self.field_path)
        if value is None:
            return False
        
        # Match against pattern
        if self._compiled:
            return bool(self._compiled.search(str(value)))
        return False
    
    def _get_field_value(self, event: Event, field_path: str) -> Any:
        """Get nested field value using dot notation."""
        if not field_path:
            return None
        
        parts = field_path.split(".")
        obj: Any = event
        
        for part in parts:
            if hasattr(obj, part):
                obj = getattr(obj, part)
            elif isinstance(obj, dict) and part in obj:
                obj = obj[part]
            else:
                return None
        
        return obj


# EDR-focused filters - minimal noise reduction, keep all security-relevant events
# These only filter truly noisy system events that have no security value
DEFAULT_NOISE_FILTERS = [
    # Windows Search indexing creates massive file access noise
    FilterRule(
        name="search_indexer",
        event_types=[EventType.FILE_MODIFIED],
        field_path="data.path",
        pattern=r"\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Packages\\.*SearchHost",
        action="drop",
    ),
    # WMI Provider Host routine polling (not process start/end, just routine)
    FilterRule(
        name="wmi_polling",
        event_types=[EventType.NETWORK_CONNECTION],
        field_path="data.process_name",
        pattern=r"^WmiPrvSE\.exe$",
        action="drop",
    ),
    # Prefetch file generation (Windows optimization, not security-relevant)
    FilterRule(
        name="prefetch_files",
        event_types=[EventType.FILE_CREATED, EventType.FILE_MODIFIED],
        field_path="data.path",
        pattern=r"\\Windows\\Prefetch\\.*\.pf$",
        action="drop",
    ),
    # ETL trace files (system performance logs, not security)
    FilterRule(
        name="etl_traces",
        event_types=[EventType.FILE_MODIFIED],
        field_path="data.path",
        pattern=r"\\Windows\\.*\.etl$",
        action="drop",
    ),
]


class EventParser:
    """Parses and filters events before storage.
    
    Features:
    - Noise filtering (system processes, temp files)
    - Deduplication of rapid events
    - Path normalization
    """
    
    def __init__(
        self,
        filters: list[FilterRule] | None = None,
        enable_dedup: bool = True,
        dedup_window_ms: int = 1000,  # Deduplicate within 1 second
    ):
        self.filters = filters if filters is not None else DEFAULT_NOISE_FILTERS
        self.enable_dedup = enable_dedup
        self.dedup_window_ms = dedup_window_ms
        
        # Deduplication cache: hash -> last_seen_timestamp
        self._dedup_cache: dict[str, datetime] = {}
        self._max_cache_size = 10000
        
        # Stats
        self.stats = {
            "total": 0,
            "filtered": 0,
            "deduplicated": 0,
            "passed": 0,
        }
    
    def process(self, events: list[Event]) -> list[Event]:
        """Process a batch of events, returning filtered/cleaned events."""
        result = []
        
        for event in events:
            self.stats["total"] += 1
            
            # Apply noise filters
            if self._should_filter(event):
                self.stats["filtered"] += 1
                continue
            
            # Deduplicate rapid events
            if self.enable_dedup and self._is_duplicate(event):
                self.stats["deduplicated"] += 1
                continue
            
            # Normalize event data
            normalized = self._normalize(event)
            result.append(normalized)
            self.stats["passed"] += 1
        
        # Cleanup old dedup cache entries periodically
        if len(self._dedup_cache) > self._max_cache_size:
            self._cleanup_dedup_cache()
        
        return result
    
    def _should_filter(self, event: Event) -> bool:
        """Check if event should be filtered out."""
        for rule in self.filters:
            if rule.matches(event):
                if rule.action == "drop":
                    logger.debug(f"Filtered event by rule '{rule.name}': {event.event_type}")
                    return True
        return False
    
    def _is_duplicate(self, event: Event) -> bool:
        """Check if this is a duplicate of a recent event."""
        # Create hash from event type + key fields
        event_hash = self._event_hash(event)
        
        now = datetime.now(timezone.utc)
        
        if event_hash in self._dedup_cache:
            last_seen = self._dedup_cache[event_hash]
            delta_ms = (now - last_seen).total_seconds() * 1000
            
            if delta_ms < self.dedup_window_ms:
                return True
        
        self._dedup_cache[event_hash] = now
        return False
    
    def _event_hash(self, event: Event) -> str:
        """Generate a hash for deduplication."""
        # Use event type + key identifying fields
        parts = [event.event_type.value]
        
        if event.event_type in (EventType.PROCESS_START, EventType.PROCESS_END):
            parts.append(str(event.data.get("pid", "")))
            parts.append(str(event.data.get("name", "")))
        elif event.event_type in (EventType.FILE_CREATED, EventType.FILE_MODIFIED):
            parts.append(str(event.data.get("path", "")))
        elif event.event_type == EventType.NETWORK_CONNECTION:
            parts.append(str(event.data.get("remote_addr", "")))
            parts.append(str(event.data.get("local_port", "")))
        else:
            # Generic: use first few data keys
            for key in list(event.data.keys())[:3]:
                parts.append(str(event.data.get(key, "")))
        
        return "|".join(parts)
    
    def _normalize(self, event: Event) -> Event:
        """Normalize event data (paths, usernames, etc.)."""
        # Normalize Windows paths
        if "path" in event.data:
            event.data["path"] = self._normalize_path(event.data["path"])
        if "exe" in event.data and event.data["exe"]:
            event.data["exe"] = self._normalize_path(event.data["exe"])
        
        # Normalize username (remove domain prefix)
        if "username" in event.data and event.data["username"]:
            username = event.data["username"]
            if "\\" in username:
                event.data["username"] = username.split("\\")[-1]
        
        return event
    
    def _normalize_path(self, path: str) -> str:
        """Normalize a Windows path."""
        if not path:
            return path
        
        # Lowercase drive letter for consistency
        if len(path) > 1 and path[1] == ":":
            path = path[0].upper() + path[1:]
        
        # Normalize separators
        path = path.replace("/", "\\")
        
        return path
    
    def _cleanup_dedup_cache(self) -> None:
        """Remove old entries from dedup cache."""
        now = datetime.now(timezone.utc)
        cutoff_ms = self.dedup_window_ms * 10  # Keep 10x the window
        
        to_remove = []
        for hash_key, timestamp in self._dedup_cache.items():
            delta_ms = (now - timestamp).total_seconds() * 1000
            if delta_ms > cutoff_ms:
                to_remove.append(hash_key)
        
        for key in to_remove:
            del self._dedup_cache[key]
        
        logger.debug(f"Cleaned up {len(to_remove)} old dedup cache entries")
    
    def add_filter(self, rule: FilterRule) -> None:
        """Add a custom filter rule."""
        self.filters.append(rule)
    
    def get_stats(self) -> dict[str, int]:
        """Get filtering statistics."""
        return self.stats.copy()
    
    def reset_stats(self) -> None:
        """Reset statistics counters."""
        self.stats = {"total": 0, "filtered": 0, "deduplicated": 0, "passed": 0}
