"""The reveal: what a contained intruder is shown when Mirage shuts the door.

Deception normally stays hidden. Once an intruder is contained there is nothing
left to protect, so every decoy tells them the truth in the same words: the
system was never real, everything they took was bait, and they are blocked.
The SSH decoy adds what it saw them do in that session.
"""

from __future__ import annotations

# A 5-row block font, just the letters we need.
_FONT = {
    "M": ["█   █", "██ ██", "█ █ █", "█   █", "█   █"],
    "I": ["███", " █ ", " █ ", " █ ", "███"],
    "R": ["████ ", "█   █", "████ ", "█  █ ", "█   █"],
    "A": [" ███ ", "█   █", "█████", "█   █", "█   █"],
    "G": [" ████", "█    ", "█  ██", "█   █", " ████"],
    "E": ["█████", "█    ", "████ ", "█    ", "█████"],
}

RED, LIME, DIM, BOLD, RESET = "\x1b[38;5;203m", "\x1b[38;5;191m", "\x1b[2m", "\x1b[1m", "\x1b[0m"


def wordmark(word: str = "MIRAGE") -> list[str]:
    """Big block letters, each pixel two characters wide so it reads as square."""
    rows = []
    for r in range(5):
        row = " ".join(_FONT[ch][r] for ch in word)
        rows.append(row.replace("█", "██").replace(" ", "  "))
    return rows


def caught(ip: str, facts: list[tuple[str, str]] | None = None, *, color: bool = True, newline: str = "\n") -> str:
    """The full reveal screen. `facts` are extra (label, value) rows, e.g. session details."""
    c = (lambda code, s: f"{code}{s}{RESET}") if color else (lambda code, s: s)
    rule = c(DIM, "  " + "─" * 62)
    lines = ["", *[c(RED, "  " + row) for row in wordmark()], "", rule,
             "  " + c(BOLD + RED, "THIS SYSTEM WAS NEVER REAL."),
             "  You have been inside a Mirage deception trap the whole time.", ""]
    rows = [("intruder", ip), *(facts or []), ("status", "contained · blocked on every decoy")]
    width = max(len(k) for k, _ in rows) + 3
    for k, v in rows:
        lines.append("  " + c(DIM, k.ljust(width)) + v)
    lines += ["",
              "  Every password, key and file you found was planted bait.",
              "  Every request and keystroke was recorded as evidence.",
              "  " + c(LIME, "Your address is now blocked across this network."),
              rule, ""]
    return newline.join(lines)


S3_MESSAGE = "Contained by Mirage. This bucket was a decoy, your keys were bait, and your address is now blocked."
