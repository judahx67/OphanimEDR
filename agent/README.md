# EDR Agent

Windows endpoint monitoring agent for behavioral threat detection.

## Features

- **Process Monitoring**: psutil-based process creation/termination tracking
- **Sysmon Integration**: Reads Sysmon Windows Event Log
- **Filesystem Monitoring**: watchdog-based file activity tracking
- **Network Monitoring**: Connection tracking via psutil
- **Event Filtering**: Reduces noise with configurable rules
- **Local Logging**: Rotating JSON Lines logs to `%APPDATA%\EDR\logs`

## Quick Start

```bash
# From agent/src/ directory
python -m edr_agent
```

## Configuration

Configuration is read from root `.env` file:

```env
# Agent Settings
VERBOSE_OUTPUT=false          # Show detailed terminal output
SERVER_URL=http://localhost:8000
LOCAL_LOGGING_ENABLED=true

# Collectors
PROCESS_POLL_INTERVAL=2.0
SYSMON_ENABLED=true
FILESYSTEM_ENABLED=true
NETWORK_ENABLED=true

# Logging
LOG_LEVEL=INFO
LOG_MAX_SIZE_MB=10
```

## Development

```bash
# Install dependencies
pip install -e .

# Run with verbose output
# Edit ../../.env: VERBOSE_OUTPUT=true
python -m edr_agent
```

## Data Flow

```
Collectors → Parser (filter) → Handlers
                                  ├─ JSON Logger (local)
                                  └─ Server Exfil (API)
```

## Next Enhancements

- Authentication logging (Event 4624/4634)
- ETW consumer integration
- PowerShell script block logging
- Registry monitoring
