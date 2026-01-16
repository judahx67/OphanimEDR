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
            self._collectors.append(get_sysmon_collector(endpoint_id))
        
        # Filesystem collector
        if self.config.collection.filesystem_enabled:
            self._collectors.append(
                FilesystemCollector(
                    endpoint_id=endpoint_id,
                    watch_paths=self.config.collection.file_watch_paths,
                )
            )
        
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
                
                # Process events through handlers
                if all_events:
                    for handler in self._event_handlers:
                        try:
                            handler(all_events)
                        except Exception as e:
                            logger.error(f"Error in event handler: {e}")
                    
                    logger.debug(f"Processed {len(all_events)} events")
                
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


def default_event_printer(events: list[Event]) -> None:
    """Simple event handler that prints events (for testing)."""
    for event in events:
        print(f"[{event.timestamp.isoformat()}] {event.event_type.value}: {event.data.get('name', event.data.get('path', 'N/A'))}")


async def run_agent(config: AgentConfig | None = None) -> None:
    """Main entry point to run the agent."""
    agent = AgentCore(config)
    
    # Add default printer for development
    # In production, this would be replaced with structured logging
    agent.add_event_handler(default_event_printer)
    
    await agent.run()
