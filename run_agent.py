#!/usr/bin/env python3
"""EDR Agent Entry Point for PyInstaller.

This is the entry point used when building with PyInstaller.
It uses absolute imports instead of relative imports.

Run with: python run_agent.py
Build with: pyinstaller --onefile run_agent.py
"""

import asyncio
import logging
import sys
import os

# Add the agent source to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "agent", "src"))

from edr_agent.config import get_config
from edr_agent.core import run_agent


def setup_logging() -> None:
    """Configure basic logging for development."""
    config = get_config()
    
    logging.basicConfig(
        level=getattr(logging, config.logging.level.upper()),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
        ]
    )


def main() -> None:
    """Main entry point."""
    setup_logging()
    
    logger = logging.getLogger(__name__)
    logger.info("=" * 60)
    logger.info("Ophanim EDR Agent Starting")
    logger.info("=" * 60)
    
    try:
        asyncio.run(run_agent())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
