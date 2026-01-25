"""Process Collector using psutil.

Monitors running processes and collects behavioral data for ML analysis.
"""

import asyncio
from dataclasses import dataclass

import psutil

from .base import BaseCollector, Event, EventType


@dataclass
class ProcessInfo:
    """Structured process information for ML feature extraction."""
    pid: int
    name: str
    exe: str | None
    cmdline: list[str]
    ppid: int | None
    username: str | None
    status: str
    create_time: float
    cpu_percent: float
    memory_mb: float
    num_threads: int
    connections: list[dict]
    open_files: list[str]


class ProcessCollector(BaseCollector):
    """Collects process snapshots using psutil.
    
    This collector polls the system for running processes at configured
    intervals, capturing behavioral metrics useful for ML detection.
    """
    
    def __init__(
        self,
        endpoint_id: str = "",
        poll_interval: float = 2.0,
        full_snapshot: bool = False,  # If True, collect all process details (slow)
    ):
        super().__init__(endpoint_id)
        self.poll_interval = poll_interval
        self.full_snapshot = full_snapshot
        self._previous_pids: set[int] = set()
        self._process_cache: dict[int, ProcessInfo] = {}
    
    @property
    def name(self) -> str:
        return "ProcessCollector"
    
    async def start(self) -> None:
        """Initialize collector and capture initial process list."""
        self._running = True
        self._previous_pids = set(psutil.pids())
        # Prime CPU percent (first call always returns 0)
        for proc in psutil.process_iter(['pid']):
            try:
                proc.cpu_percent()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    
    async def stop(self) -> None:
        """Stop the collector."""
        self._running = False
        self._process_cache.clear()
    
    async def collect(self) -> list[Event]:
        """Collect current process snapshot and detect new/ended processes.
        
        For performance, we only collect basic info for all processes.
        Full details (network, files) are only collected for NEW processes.
        """
        events: list[Event] = []
        current_pids: set[int] = set()
        
        # Fast iteration - just get PIDs and basic info
        for proc in psutil.process_iter(['pid', 'name', 'ppid', 'status', 'create_time']):
            try:
                pid = proc.info['pid']
                current_pids.add(pid)
                
                # Only collect full details for NEW processes
                is_new = pid not in self._previous_pids
                
                if is_new or self.full_snapshot:
                    info = await self._get_process_info(proc, full_details=is_new)
                    if info:
                        self._process_cache[pid] = info
                        
                        if is_new:
                            events.append(self.create_event(
                                EventType.PROCESS_START,
                                self._process_info_to_dict(info)
                            ))
                        elif self.full_snapshot:
                            events.append(self.create_event(
                                EventType.PROCESS_SNAPSHOT,
                                self._process_info_to_dict(info)
                            ))
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # Detect ended processes
        ended_pids = self._previous_pids - current_pids
        for pid in ended_pids:
            if cached := self._process_cache.get(pid):
                events.append(self.create_event(
                    EventType.PROCESS_END,
                    {"pid": pid, "name": cached.name}
                ))
                del self._process_cache[pid]
        
        self._previous_pids = current_pids
        return events
    
    async def _get_process_info(
        self, proc: psutil.Process, full_details: bool = False
    ) -> ProcessInfo | None:
        """Extract process information.
        
        Args:
            proc: The psutil.Process object
            full_details: If True, collect network/file info (slower)
        """
        try:
            # Use oneshot context for efficiency
            with proc.oneshot():
                # Basic info
                pid = proc.pid
                name = proc.name()
                
                try:
                    exe = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    exe = None
                
                try:
                    cmdline = proc.cmdline()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    cmdline = []
                
                try:
                    ppid = proc.ppid()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    ppid = None
                
                try:
                    username = proc.username()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    username = None
                
                status = proc.status()
                create_time = proc.create_time()
                
                # Performance metrics
                cpu_percent = proc.cpu_percent()
                memory_info = proc.memory_info()
                memory_mb = memory_info.rss / (1024 * 1024)
                num_threads = proc.num_threads()
                
                # Network connections (slow - only for new processes)
                connections = []
                if full_details:
                    try:
                        for conn in proc.net_connections(kind='inet'):
                            connections.append({
                                "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                                "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                                "status": conn.status,
                            })
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                
                # Open files (slow - only for new processes)
                open_files = []
                if full_details:
                    try:
                        for f in proc.open_files():
                            open_files.append(f.path)
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                
                return ProcessInfo(
                    pid=pid,
                    name=name,
                    exe=exe,
                    cmdline=cmdline,
                    ppid=ppid,
                    username=username,
                    status=status,
                    create_time=create_time,
                    cpu_percent=cpu_percent,
                    memory_mb=round(memory_mb, 2),
                    num_threads=num_threads,
                    connections=connections,
                    open_files=open_files[:20],  # Limit to prevent huge payloads
                )
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
    
    def _process_info_to_dict(self, info: ProcessInfo) -> dict:
        """Convert ProcessInfo to dictionary for event data."""
        return {
            "pid": info.pid,
            "name": info.name,
            "exe": info.exe,
            "cmdline": info.cmdline,
            "ppid": info.ppid,
            "username": info.username,
            "status": info.status,
            "create_time": info.create_time,
            "cpu_percent": info.cpu_percent,
            "memory_mb": info.memory_mb,
            "num_threads": info.num_threads,
            "connections": info.connections,
            "open_files_count": len(info.open_files),
        }
