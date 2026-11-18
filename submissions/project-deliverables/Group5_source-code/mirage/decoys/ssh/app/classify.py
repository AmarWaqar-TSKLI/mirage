"""Map shell commands to MITRE ATT&CK techniques.

Rules are checked against the full command line, and every matching rule
contributes its techniques, so `cat ~/.aws/credentials | grep key` is labelled
as both file discovery and credential access.
"""

import re

# (pattern, techniques, short description). Patterns match the whole command line.
RULES: list[tuple[re.Pattern, list[str], str]] = [
    (re.compile(p), t, d) for p, t, d in [
        # Discovery
        (r"^\s*(whoami|id|w|who|last|users)\b", ["T1033"], "System Owner/User Discovery"),
        (r"\b(uname|hostname|hostnamectl|lsb_release)\b|/etc/(os-release|issue)|/proc/version",
         ["T1082"], "System Information Discovery"),
        (r"^\s*(ps|top|htop|pgrep)\b", ["T1057"], "Process Discovery"),
        (r"\b(ifconfig|ip\s+(a|addr|r|route)|route|arp|/etc/hosts|resolv\.conf)\b",
         ["T1016"], "System Network Configuration Discovery"),
        (r"\b(netstat|ss)\b", ["T1049"], "System Network Connections Discovery"),
        (r"^\s*(ls|find|tree|locate|stat|du)\b", ["T1083"], "File and Directory Discovery"),
        (r"/etc/(passwd|group)|\bgetent\b", ["T1087.001"], "Account Discovery: Local Account"),
        (r"\bsudo\s+-l\b", ["T1548.003"], "Abuse Elevation Control: Sudo"),
        (r"\b(nmap|nc|ncat|ping)\b", ["T1046"], "Network Service Discovery"),
        # Credential access
        (r"\.aws/credentials|\.env\b|id_rsa|\.pgpass|\bgrep\b.*(pass|secret|key|token)",
         ["T1552.001"], "Unsecured Credentials: Credentials In Files"),
        (r"\.bash_history|^\s*history\b", ["T1552.003"], "Unsecured Credentials: Bash History"),
        (r"/etc/shadow", ["T1003.008"], "OS Credential Dumping: /etc/passwd and /etc/shadow"),
        # Cloud
        (r"^\s*aws\s", ["T1580"], "Cloud Infrastructure Discovery"),
        # Tool transfer and execution
        (r"\b(wget|curl|scp|ftp|tftp)\b", ["T1105"], "Ingress Tool Transfer"),
        (r"\bchmod\s+\+?[0-7]*x", ["T1222.002"], "File Permissions Modification"),
        (r"\b(python3?|perl|php|ruby)\s+-c\b|\bbash\s+-c\b|\bsh\s+-c\b",
         ["T1059.004"], "Command and Scripting Interpreter: Unix Shell"),
        # Persistence
        (r"\bcrontab\b|/etc/cron", ["T1053.003"], "Scheduled Task: Cron"),
        (r"authorized_keys", ["T1098.004"], "Account Manipulation: SSH Authorized Keys"),
        (r"\b(useradd|adduser)\b", ["T1136.001"], "Create Account: Local Account"),
        (r"\.bashrc|\.profile|\.bash_profile", ["T1546.004"], "Event Triggered Execution: Unix Shell Config"),
        # Defense evasion
        (r"history\s+-c|rm\s.*\.bash_history|unset\s+HISTFILE|HISTFILE=/dev/null",
         ["T1070.003"], "Indicator Removal: Clear Command History"),
        (r"\b(rm|shred)\b.*(/var/log|\.log\b)", ["T1070.002"], "Indicator Removal: Clear Linux Logs"),
        # Privilege escalation
        (r"^\s*(sudo|su)\b", ["T1548.003"], "Abuse Elevation Control: Sudo"),
    ]
]


def classify(command: str) -> list[str]:
    """Return the ATT&CK technique IDs a command line maps to (deduplicated, ordered)."""
    # Check each piece of a compound line separately so rules anchored with "^"
    # also fire for commands after ";", "&&", "||" or "|".
    segments = [s for s in re.split(r"\|\||&&|[;|]", command) if s.strip()]
    techniques: list[str] = []
    for pattern, ids, _ in RULES:
        if any(pattern.search(s) for s in segments):
            techniques += [t for t in ids if t not in techniques]
    return techniques
