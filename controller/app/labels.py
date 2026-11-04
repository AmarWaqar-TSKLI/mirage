"""MITRE ATT&CK and MITRE Engage labels for decoy events."""

from mirage_common import Event, EventType, Honeytoken, Source

# What touching each kind of honeytoken tells us the attacker is doing.
TOKEN_TECHNIQUES = {
    "robots_link": ["T1595.003"],                 # Active Scanning: Wordlist Scanning
    "env_file": ["T1552.001"],                    # Unsecured Credentials: Credentials In Files
    "ssh_password": ["T1078", "T1021.004"],       # Valid Accounts; Remote Services: SSH
    "aws_credentials_file": ["T1552.001"],        # Unsecured Credentials: Credentials In Files
    "aws_key": ["T1078.004"],                     # Valid Accounts: Cloud Accounts
    "bait_file": ["T1530"],                       # Data from Cloud Storage
}

# Fallback when no honeytoken is involved.
EVENT_TECHNIQUES = {
    EventType.HTTP_REQUEST: ["T1595"],            # Active Scanning
    EventType.LOGIN_ATTEMPT: ["T1110"],           # Brute Force
    EventType.SESSION_START: ["T1021.004"],       # Remote Services: SSH
    EventType.COMMAND: ["T1059.004"],             # Command and Scripting Interpreter: Unix Shell
}

# Engage activities: how Mirage is engaging the adversary when this event fires.
SOURCE_ENGAGE = {
    Source.ADMIN_PANEL: ["Network Monitoring"],
    Source.S3: ["Network Monitoring"],
    Source.SSH: ["System Activity Monitoring"],
}
TOKEN_ENGAGE = ["Lures"]


def label(event: Event, token: Honeytoken | None) -> tuple[list[str], list[str]]:
    """Return (ATT&CK technique IDs, Engage activities) for an event."""
    techniques = list(event.attack_techniques)
    techniques += TOKEN_TECHNIQUES.get(token.kind, []) if token else EVENT_TECHNIQUES.get(event.event_type, [])
    engage = SOURCE_ENGAGE.get(event.source, []) + (TOKEN_ENGAGE if token else [])
    return list(dict.fromkeys(techniques)), list(dict.fromkeys(engage))
