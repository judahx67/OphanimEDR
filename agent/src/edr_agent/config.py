"""EDR Agent Configuration Module.

Loads configuration from environment variables with sensible defaults.
Designed for thesis-friendly simplicity (Option C from agent-configuration.md).

Automatically loads .env file from:
- PyInstaller bundle: next to .exe or in temp extraction dir
- Development: project root (4 parents up from this file)
"""

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path


def _find_env_file() -> Path | None:
    """Find .env file in the appropriate location."""
    # Check if running as PyInstaller frozen executable
    if getattr(sys, 'frozen', False):
        # Running as compiled .exe
        exe_dir = Path(sys.executable).parent
        
        # Option 1: .env next to the .exe (preferred for deployment)
        env_beside_exe = exe_dir / ".env"
        if env_beside_exe.exists():
            return env_beside_exe
        
        # Option 2: .env in PyInstaller's temp extraction dir
        if hasattr(sys, '_MEIPASS'):
            env_in_bundle = Path(sys._MEIPASS) / ".env"
            if env_in_bundle.exists():
                return env_in_bundle
        
        # Option 3: Check current working directory
        env_in_cwd = Path.cwd() / ".env"
        if env_in_cwd.exists():
            return env_in_cwd
    else:
        # Development mode: look relative to this file
        # Path: agent/src/edr_agent/config.py -> 4 parents to project root
        env_path = Path(__file__).parent.parent.parent.parent / ".env"
        if env_path.exists():
            return env_path
        
        # Also check CWD for development
        env_in_cwd = Path.cwd() / ".env"
        if env_in_cwd.exists():
            return env_in_cwd
    
    return None


# Load .env file automatically
try:
    from dotenv import load_dotenv
    env_path = _find_env_file()
    if env_path:
        load_dotenv(env_path, override=True)
except ImportError:
    pass  # python-dotenv not installed, use system env vars only


@dataclass
class CollectionConfig:
    """Settings for data collectors."""
    process_poll_interval: float = 2.0  # seconds between process snapshots
    sysmon_enabled: bool = True
    filesystem_enabled: bool = True
    file_watch_paths: list[str] = field(default_factory=lambda: [
        str(Path.home()),
        "C:\\ProgramData",
    ])


@dataclass
class DetectionConfig:
    """Settings for ML detection (Phase 5)."""
    model_path: str = "models/classifier.joblib"
    anomaly_model_path: str = "models/anomaly.joblib"
    threshold_high: float = 0.7
    threshold_medium: float = 0.5
    batch_window_seconds: float = 5.0


@dataclass
class ServerConfig:
    """Settings for management server communication."""
    url: str = "http://localhost:8000"
    api_key: str = ""
    heartbeat_interval: float = 30.0
    alert_retry_count: int = 3


@dataclass
class LoggingConfig:
    """Settings for structured logging."""
    level: str = "INFO"
    log_dir: Path = field(default_factory=lambda: Path("logs"))
    events_file: str = "edr-events.jsonl"
    max_file_size_mb: int = 50
    backup_count: int = 5


@dataclass
class AgentConfig:
    """Main configuration container for EDR Agent."""
    endpoint_id: str = ""
    collection: CollectionConfig = field(default_factory=CollectionConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    
    @classmethod
    def from_environment(cls) -> "AgentConfig":
        """Load configuration from environment variables."""
        config = cls()
        
        # Agent identity
        config.endpoint_id = os.environ.get(
            "EDR_ENDPOINT_ID",
            os.environ.get("COMPUTERNAME", "unknown")
        )
        
        # Server settings
        config.server.url = os.environ.get("SERVER_URL", config.server.url)
        config.server.api_key = os.environ.get("AGENT_API_KEY", "")
        
        # Collection settings
        if interval := os.environ.get("PROCESS_POLL_INTERVAL"):
            config.collection.process_poll_interval = float(interval)
        
        config.collection.sysmon_enabled = (
            os.environ.get("SYSMON_ENABLED", "true").lower() == "true"
        )
        config.collection.filesystem_enabled = (
            os.environ.get("FILESYSTEM_ENABLED", "true").lower() == "true"
        )
        
        # Logging settings
        config.logging.level = os.environ.get("LOG_LEVEL", config.logging.level)
        if log_dir := os.environ.get("LOG_DIR"):
            config.logging.log_dir = Path(log_dir)
        
        # Detection thresholds
        if threshold := os.environ.get("DETECTION_THRESHOLD"):
            config.detection.threshold_high = float(threshold)
        
        return config


# Global config instance (lazy loaded)
_config: AgentConfig | None = None


def get_config() -> AgentConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = AgentConfig.from_environment()
    return _config
