"""EDR Agent Entry Point.

Run with: python -m edr_agent
"""

import asyncio
import logging
import sys

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
