"""EDR Agent Core Loop.

Orchestrates collectors, processes events, and manages the agent lifecycle.
"""

import asyncio
import logging
import signal
import sys
from datetime import datetime, timezone
from typing import Callable

from .config import get_config, AgentConfig
from .collectors.base import BaseCollector, Event
from .collectors.process import ProcessCollector
from .collectors.sysmon import get_sysmon_collector
from .collectors.filesystem import FilesystemCollector
from .collectors.network import NetworkCollector
from .parser import EventParser


logger = logging.getLogger(__name__)


class AgentCore:
    """Main EDR Agent orchestrator.
    
    Manages the lifecycle of collectors and coordinates event processing.
    """
    
    def __init__(self, config: AgentConfig | None = None):
        self.config = config or get_config()
        self._collectors: list[BaseCollector] = []
        self._running = False
        self._event_handlers: list[Callable[[list[Event]], None]] = []
        self._shutdown_event = asyncio.Event()
        self._parser = EventParser()  # Filter engine
    
    def add_event_handler(self, handler: Callable[[list[Event]], None]) -> None:
        """Add a handler to be called with collected events.
        
        Handlers receive batches of events for processing (logging, ML, etc.)
        """
        self._event_handlers.append(handler)
    
    def _setup_collectors(self) -> None:
        """Initialize configured collectors."""
        endpoint_id = self.config.endpoint_id
        
        # Process collector (always enabled)
        self._collectors.append(
            ProcessCollector(
                endpoint_id=endpoint_id,
                poll_interval=self.config.collection.process_poll_interval,
            )
        )
        
        # Sysmon collector (Windows only)
        if self.config.collection.sysmon_enabled:
            try:
                sysmon = get_sysmon_collector(endpoint_id)
                self._collectors.append(sysmon)
            except Exception as e:
                logger.warning(f"Sysmon collector not available: {e}")
        
        # Filesystem collector
        if self.config.collection.filesystem_enabled:
            try:
                fs_collector = FilesystemCollector(
                    endpoint_id=endpoint_id,
                    watch_paths=self.config.collection.file_watch_paths,
                )
                self._collectors.append(fs_collector)
            except Exception as e:
                logger.warning(f"Filesystem collector not available: {e}")
        
        # Network collector
        if self.config.collection.network_enabled:
            try:
                net_collector = NetworkCollector(
                    endpoint_id=endpoint_id,
                    poll_interval=self.config.collection.process_poll_interval,
                )
                self._collectors.append(net_collector)
            except Exception as e:
                logger.warning(f"Network collector not available: {e}")
        
        logger.info(
            f"Initialized {len(self._collectors)} collectors: "
            f"{[c.name for c in self._collectors]}"
        )
    
    async def _start_collectors(self) -> None:
        """Start all collectors."""
        for collector in self._collectors:
            try:
                await collector.start()
                logger.info(f"Started {collector.name}")
            except Exception as e:
                logger.error(f"Failed to start {collector.name}: {e}")
    
    async def _stop_collectors(self) -> None:
        """Stop all collectors gracefully."""
        for collector in self._collectors:
            try:
                await collector.stop()
                logger.info(f"Stopped {collector.name}")
            except Exception as e:
                logger.error(f"Error stopping {collector.name}: {e}")
    
    async def _collection_loop(self) -> None:
        """Main collection loop - runs until shutdown."""
        poll_interval = self.config.collection.process_poll_interval
        
        while self._running:
            try:
                # Collect from all collectors
                all_events: list[Event] = []
                
                for collector in self._collectors:
                    if collector.is_running:
                        try:
                            events = await collector.collect()
                            all_events.extend(events)
                        except Exception as e:
                            logger.error(f"Error collecting from {collector.name}: {e}")
                
                # Filter events through parser (removes noise, deduplicates)
                if all_events:
                    filtered_events = self._parser.process(all_events)
                    
                    if filtered_events:
                        for handler in self._event_handlers:
                            try:
                                handler(filtered_events)
                            except Exception as e:
                                logger.error(f"Error in event handler: {e}")
                        
                        logger.debug(f"Processed {len(filtered_events)}/{len(all_events)} events (filtered)")
                
                # Wait for next poll interval or shutdown
                try:
                    await asyncio.wait_for(
                        self._shutdown_event.wait(),
                        timeout=poll_interval
                    )
                    # If we get here, shutdown was requested
                    break
                except asyncio.TimeoutError:
                    # Normal timeout, continue loop
                    pass
                    
            except Exception as e:
                logger.error(f"Error in collection loop: {e}")
                await asyncio.sleep(1)  # Brief pause on error
    
    def _setup_signal_handlers(self) -> None:
        """Setup graceful shutdown on SIGINT/SIGTERM."""
        def signal_handler(sig, frame):
            logger.info(f"Received signal {sig}, initiating shutdown...")
            self._running = False
            self._shutdown_event.set()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def run(self) -> None:
        """Start the agent and run until shutdown."""
        logger.info(f"Starting EDR Agent on endpoint: {self.config.endpoint_id}")
        
        self._running = True
        self._setup_signal_handlers()
        self._setup_collectors()
        
        try:
            await self._start_collectors()
            await self._collection_loop()
        finally:
            await self._stop_collectors()
            logger.info("EDR Agent shutdown complete")
    
    def stop(self) -> None:
        """Request graceful shutdown."""
        self._running = False
        self._shutdown_event.set()


def create_event_printer(verbose: bool = False):
    """Create an event handler that prints events to terminal.
    
    Args:
        verbose: If True, print full event details. If False, print summary only.
    """
    def event_printer(events: list[Event]) -> None:
        if not events:
            return
        
        if verbose:
            # Verbose mode: print each event with full details
            for e in events:
                ts = e.timestamp.strftime('%H:%M:%S')
                event_type = e.event_type.value
                
                # Format key data fields based on event type
                if event_type.startswith('process'):
                    details = f"pid={e.data.get('pid')} name={e.data.get('name')} exe={e.data.get('exe', 'N/A')}"
                elif event_type.startswith('file'):
                    details = f"path={e.data.get('path')}"
                elif event_type == 'network_connection':
                    action = e.data.get('action', 'unknown')
                    details = f"action={action} {e.data.get('remote_addr')}:{e.data.get('remote_port')} proc={e.data.get('process_name')}"
                elif event_type == 'sysmon_event':
                    details = f"sysmon_type={e.data.get('sysmon_event_type')} image={e.data.get('image', 'N/A')}"
                else:
                    details = str(e.data)[:100]
                
                print(f"[{ts}] {event_type}: {details}")
        else:
            # Summary mode: group by type
            by_type: dict[str, list[Event]] = {}
            for event in events:
                key = event.event_type.value
                by_type.setdefault(key, []).append(event)
            
            for event_type, type_events in by_type.items():
                if event_type == "process_snapshot":
                    continue
                elif len(type_events) == 1:
                    e = type_events[0]
                    name = e.data.get('name', e.data.get('path', 'N/A'))
                    print(f"[{e.timestamp.strftime('%H:%M:%S')}] {event_type}: {name}")
                else:
                    print(f"[{type_events[0].timestamp.strftime('%H:%M:%S')}] {event_type}: {len(type_events)} events")
    
    return event_printer


def default_event_printer(events: list[Event]) -> None:
    """Simple summary event printer (for backwards compatibility)."""
    create_event_printer(verbose=False)(events)


async def run_agent(
    config: AgentConfig | None = None,
    enable_exfil: bool = True,
) -> None:
    """Main entry point to run the agent.
    
    Args:
        config: Optional configuration override
        enable_exfil: Whether to enable server exfiltration (default True)
    """
    config = config or get_config()
    agent = AgentCore(config)
    exfil_handler = None
    json_logger = None
    
    # Add event printer (verbose controlled by VERBOSE_OUTPUT env var)
    verbose = config.logging.verbose_output
    agent.add_event_handler(create_event_printer(verbose=verbose))
    if verbose:
        logger.info("Verbose output enabled (VERBOSE_OUTPUT=true)")
    
    # Add local JSON logger (controlled by LOCAL_LOGGING_ENABLED env var)
    if config.logging.local_logging_enabled:
        try:
            from .logger import JSONLogger, create_json_logger_handler
            json_logger = JSONLogger()
            agent.add_event_handler(create_json_logger_handler(json_logger))
            logger.info(f"Local logging enabled: {json_logger.log_dir}")
        except Exception as e:
            logger.warning(f"Failed to start local logging: {e}")
    
    # Add server exfil handler if enabled and server URL is configured
    if enable_exfil:
        try:
            from .exfil import ServerExfilHandler, create_exfil_event_handler
            exfil_handler = ServerExfilHandler()
            await exfil_handler.start()
            agent.add_event_handler(create_exfil_event_handler(exfil_handler))
            logger.info("Server exfiltration enabled")
        except Exception as e:
            logger.warning(f"Failed to start server exfil: {e}")
    
    try:
        await agent.run()
    finally:
        if exfil_handler:
            await exfil_handler.stop()
        if json_logger:
            json_logger.close()

