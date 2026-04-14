"""
Rule definitions for the rule-based filter.

Each rule is a sequence of edge patterns to match against the causal graph.
A "match" is a stateful window tracked per root process.

Rule structure:
  - id:          unique string key
  - name:        human-readable name
  - severity:    low | medium | high | critical
  - mitre:       ATT&CK technique ID
  - description: what this rule detects
  - conditions:  ordered list of EdgeCondition dicts, checked as a sequence.
                 All must be satisfied (in causal order) to fire the rule.

EdgeCondition keys:
  subject_type:   NodeType (PROCESS / FILE / SOCKET / ...)  -- None = any
  subject_name_re: regex matched against subject.name       -- None = any
  edge_type:      EdgeType value or list of values          -- None = any
  object_type:    NodeType                                  -- None = any
  object_name_re: regex matched against object.name         -- None = any

The engine maintains a per-(rule, root_process_uuid) partial match state.
When an incoming NormalizedEvent advances a state to the final condition,
an incident is created.
"""

RULES = [
    {
        "id": "powershell_c2_dropper",
        "name": "PowerShell C2 Dropper",
        "severity": "critical",
        "mitre": "T1059.001",
        "description": (
            "PowerShell (or cmd) spawns a child process that connects to an "
            "external socket AND writes a file — classic staged dropper pattern."
        ),
        "conditions": [
            # Step 1: a powershell/cmd process forks a child
            {
                "subject_type": "PROCESS",
                "subject_name_re": r"(?i)(powershell|cmd\.exe|wscript|cscript)",
                "edge_type": "FORK",
                "object_type": "PROCESS",
                "object_name_re": None,
            },
            # Step 2: that child connects to a socket
            {
                "subject_type": "PROCESS",
                "subject_name_re": None,
                "edge_type": "CONNECT",
                "object_type": "SOCKET",
                "object_name_re": None,
            },
            # Step 3: child writes a file
            {
                "subject_type": "PROCESS",
                "subject_name_re": None,
                "edge_type": "WRITE",
                "object_type": "FILE",
                "object_name_re": None,
            },
        ],
    },
    {
        "id": "process_reads_sensitive_then_exfil",
        "name": "Credential File Read + Exfiltration",
        "severity": "high",
        "mitre": "T1552.001",
        "description": (
            "A process reads a sensitive credential file (/etc/shadow, "
            "/etc/passwd, SAM, NTDS) and then sends data over a socket."
        ),
        "conditions": [
            {
                "subject_type": "PROCESS",
                "subject_name_re": None,
                "edge_type": "READ",
                "object_type": "FILE",
                "object_name_re": r"(?i)(shadow|passwd|sam|ntds|\.key|id_rsa|credentials)",
            },
            {
                "subject_type": "PROCESS",
                "subject_name_re": None,
                "edge_type": ["SEND", "WRITE"],
                "object_type": "SOCKET",
                "object_name_re": None,
            },
        ],
    },
    {
        "id": "persistence_via_script",
        "name": "Persistence via Startup/Cron Write",
        "severity": "high",
        "mitre": "T1053.003",
        "description": (
            "A process writes to a known persistence location "
            "(crontab, systemd unit, startup folder, registry run key)."
        ),
        "conditions": [
            {
                "subject_type": "PROCESS",
                "subject_name_re": None,
                "edge_type": "WRITE",
                "object_type": "FILE",
                "object_name_re": (
                    r"(?i)(cron|/etc/init|systemd|\.service|"
                    r"startup|autorun|\.bashrc|\.profile|"
                    r"AppData\\Roaming\\Microsoft\\Windows\\Start Menu)"
                ),
            },
        ],
    },
    {
        "id": "lateral_movement_ssh",
        "name": "Lateral Movement via SSH",
        "severity": "high",
        "mitre": "T1021.004",
        "description": (
            "A process forks ssh/scp, which then connects to an internal host."
        ),
        "conditions": [
            {
                "subject_type": "PROCESS",
                "subject_name_re": None,
                "edge_type": "FORK",
                "object_type": "PROCESS",
                "object_name_re": r"(?i)(ssh|scp|sftp)",
            },
            {
                "subject_type": "PROCESS",
                "subject_name_re": r"(?i)(ssh|scp|sftp)",
                "edge_type": "CONNECT",
                "object_type": "SOCKET",
                "object_name_re": None,
            },
        ],
    },
    {
        "id": "shell_from_server_process",
        "name": "Shell Spawned from Server Process",
        "severity": "critical",
        "mitre": "T1059",
        "description": (
            "A typical server process (nginx, apache, httpd, java, python serving) "
            "forks a shell — indicative of webshell or RCE exploitation."
        ),
        "conditions": [
            {
                "subject_type": "PROCESS",
                "subject_name_re": r"(?i)(nginx|apache|httpd|tomcat|java|gunicorn|node)",
                "edge_type": "FORK",
                "object_type": "PROCESS",
                "object_name_re": r"(?i)(bash|sh|zsh|dash|cmd\.exe|powershell)",
            },
        ],
    },
    {
        "id": "memory_injection",
        "name": "Process Memory Injection",
        "severity": "critical",
        "mitre": "T1055",
        "description": (
            "A process mmaps or writes to a memory region associated with "
            "another process, then that second process forks — "
            "classic process hollowing / injection pattern."
        ),
        "conditions": [
            {
                "subject_type": "PROCESS",
                "subject_name_re": None,
                "edge_type": "MMAP",
                "object_type": "MEMORY",
                "object_name_re": None,
            },
            {
                "subject_type": "PROCESS",
                "subject_name_re": None,
                "edge_type": "FORK",
                "object_type": "PROCESS",
                "object_name_re": None,
            },
        ],
    },
]
