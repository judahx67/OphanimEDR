"""Sysmon Event Collector for Windows.

Reads Sysmon events from Windows Event Log for security monitoring.
Sysmon must be installed on the endpoint for this collector to work.
"""

import asyncio
from datetime import datetime, timezone
from typing import Any

from .base import BaseCollector, Event, EventType

# Windows-specific imports
try:
    import win32evtlog
    import win32evtlogutil
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False


# Sysmon Event IDs we care about
SYSMON_EVENT_TYPES = {
    1: "ProcessCreate",
    2: "FileCreateTime",
    3: "NetworkConnect",
    5: "ProcessTerminate",
    6: "DriverLoad",
    7: "ImageLoad",
    8: "CreateRemoteThread",
    9: "RawAccessRead",
    10: "ProcessAccess",
    11: "FileCreate",
    12: "RegistryEvent",
    13: "RegistryValueSet",
    15: "FileCreateStreamHash",
    22: "DNSQuery",
    23: "FileDelete",
}


class SysmonCollector(BaseCollector):
    """Collects Sysmon events from Windows Event Log.
    
    Sysmon (System Monitor) is a Windows system service that logs system
    activity to the Windows event log. This collector reads those events
    for security analysis.
    
    Requires:
        - Windows OS
        - Sysmon installed and running
        - pywin32 package
    """
    
    def __init__(
        self,
        endpoint_id: str = "",
        batch_size: int = 100,
        poll_interval: float = 1.0,
    ):
        super().__init__(endpoint_id)
        self.batch_size = batch_size
        self.poll_interval = poll_interval
        self._handle = None
        self._last_record_number = 0
        self._event_buffer: list[Event] = []
    
    @property
    def name(self) -> str:
        return "SysmonCollector"
    
    async def start(self) -> None:
        """Open handle to Sysmon event log."""
        if not WINDOWS_AVAILABLE:
            raise RuntimeError("SysmonCollector requires Windows and pywin32")
        
        self._running = True
        
        try:
            # Open the Sysmon Operational log
            self._handle = win32evtlog.OpenEventLog(
                None,  # Local computer
                "Microsoft-Windows-Sysmon/Operational"
            )
            
            # Get current record count to start from latest
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(self._handle, flags, 0)
            if events:
                self._last_record_number = events[0].RecordNumber
                
        except Exception as e:
            self._running = False
            raise RuntimeError(f"Failed to open Sysmon log: {e}. Is Sysmon installed?")
    
    async def stop(self) -> None:
        """Close event log handle."""
        self._running = False
        if self._handle:
            try:
                win32evtlog.CloseEventLog(self._handle)
            except Exception:
                pass
            self._handle = None
    
    async def collect(self) -> list[Event]:
        """Read new Sysmon events since last collection."""
        if not self._running or not self._handle:
            return []
        
        events: list[Event] = []
        
        try:
            # Read forwards from last position
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            while True:
                raw_events = win32evtlog.ReadEventLog(
                    self._handle,
                    flags,
                    0  # Offset (ignored for sequential)
                )
                
                if not raw_events:
                    break
                
                for raw in raw_events:
                    # Skip if we've seen this record
                    if raw.RecordNumber <= self._last_record_number:
                        continue
                    
                    self._last_record_number = raw.RecordNumber
                    
                    # Parse the event
                    event = self._parse_sysmon_event(raw)
                    if event:
                        events.append(event)
                    
                    # Limit batch size
                    if len(events) >= self.batch_size:
                        return events
                        
        except Exception:
            # Log may be unavailable temporarily
            pass
        
        return events
    
    def _parse_sysmon_event(self, raw_event: Any) -> Event | None:
        """Parse a raw Windows event into our Event structure."""
        try:
            event_id = raw_event.EventID & 0xFFFF  # Mask to get actual ID
            event_type_name = SYSMON_EVENT_TYPES.get(event_id, f"Unknown_{event_id}")
            
            # Extract timestamp
            timestamp = datetime.fromtimestamp(
                raw_event.TimeGenerated.timestamp(),
                tz=timezone.utc
            )
            
            # Get string inserts (Sysmon data fields)
            strings = raw_event.StringInserts or []
            
            # Build event data based on event type
            data: dict[str, Any] = {
                "sysmon_event_id": event_id,
                "sysmon_event_type": event_type_name,
                "record_number": raw_event.RecordNumber,
            }
            
            # Parse specific event types
            if event_id == 1:  # ProcessCreate
                data.update(self._parse_process_create(strings))
            elif event_id == 3:  # NetworkConnect
                data.update(self._parse_network_connect(strings))
            elif event_id == 11:  # FileCreate
                data.update(self._parse_file_create(strings))
            elif event_id == 22:  # DNSQuery
                data.update(self._parse_dns_query(strings))
            else:
                # Generic parsing - include all strings
                data["raw_strings"] = strings[:20]  # Limit size
            
            return self.create_event(
                EventType.SYSMON_EVENT,
                data,
                timestamp=timestamp
            )
            
        except Exception:
            return None
    
    def _parse_process_create(self, strings: list[str]) -> dict[str, Any]:
        """Parse Sysmon Event ID 1 (ProcessCreate)."""
        # Sysmon fields vary by version, common fields:
        return {
            "image": self._safe_get(strings, 4),  # Process path
            "cmdline": self._safe_get(strings, 10),
            "user": self._safe_get(strings, 12),
            "parent_image": self._safe_get(strings, 20),
            "parent_cmdline": self._safe_get(strings, 21),
        }
    
    def _parse_network_connect(self, strings: list[str]) -> dict[str, Any]:
        """Parse Sysmon Event ID 3 (NetworkConnect)."""
        return {
            "image": self._safe_get(strings, 4),
            "user": self._safe_get(strings, 6),
            "protocol": self._safe_get(strings, 7),
            "src_ip": self._safe_get(strings, 9),
            "src_port": self._safe_get(strings, 11),
            "dst_ip": self._safe_get(strings, 14),
            "dst_port": self._safe_get(strings, 16),
        }
    
    def _parse_file_create(self, strings: list[str]) -> dict[str, Any]:
        """Parse Sysmon Event ID 11 (FileCreate)."""
        return {
            "image": self._safe_get(strings, 4),
            "target_filename": self._safe_get(strings, 5),
        }
    
    def _parse_dns_query(self, strings: list[str]) -> dict[str, Any]:
        """Parse Sysmon Event ID 22 (DNSQuery)."""
        return {
            "image": self._safe_get(strings, 4),
            "query_name": self._safe_get(strings, 5),
            "query_results": self._safe_get(strings, 6),
        }
    
    @staticmethod
    def _safe_get(lst: list, index: int) -> str | None:
        """Safely get item from list."""
        try:
            return lst[index] if index < len(lst) else None
        except (IndexError, TypeError):
            return None


class MockSysmonCollector(BaseCollector):
    """Mock Sysmon collector for non-Windows development/testing."""
    
    @property
    def name(self) -> str:
        return "MockSysmonCollector"
    
    async def start(self) -> None:
        self._running = True
    
    async def stop(self) -> None:
        self._running = False
    
    async def collect(self) -> list[Event]:
        return []  # No events in mock mode


def get_sysmon_collector(endpoint_id: str = "") -> BaseCollector:
    """Factory to get appropriate Sysmon collector for current platform."""
    if WINDOWS_AVAILABLE:
        return SysmonCollector(endpoint_id=endpoint_id)
    return MockSysmonCollector(endpoint_id=endpoint_id)
