"""Dynamic attacker risk scoring engine based on trail progression and tactics."""

from enum import StrEnum
from typing import List, Set
from mirage_common.trail import TrailStage

STAGE_BASE_SCORES = {
    TrailStage.NONE: 0,
    TrailStage.ROBOTS_TXT: 10,
    TrailStage.ENV_BACKUP: 25,
    TrailStage.SSH_LOGIN: 45,
    TrailStage.AWS_CREDS_READ: 65,
    TrailStage.S3_ACCESS: 85,
    TrailStage.BAIT_DOWNLOAD: 100,
}


class Playbook(StrEnum):
    WATCH = "watch"        # Score 0 - 39: passive observation & intelligence gathering
    TARPIT = "tarpit"      # Score 40 - 74: deliberate response delay / throttling
    CONTAIN = "contain"    # Score 75 - 100: session eviction, firewall ban, forensics


CONTAINMENT_THRESHOLD = 75
TARPIT_THRESHOLD = 40


def calculate_risk_score(max_stage: int, techniques: List[str], tokens: List[str], event_count: int) -> int:
    """Computes a normalized risk score (0-100) for an attacker."""
    stage = TrailStage(max_stage) if max_stage in TrailStage._value2member_map_ else TrailStage.NONE
    stage_score = STAGE_BASE_SCORES.get(stage, 0)

    # Technique diversity: +5 points per distinct ATT&CK technique (up to 25 pts)
    technique_score = min(len(set(techniques)) * 5, 25)

    # Unique tokens breached: +5 points per honeytoken (up to 20 pts)
    token_score = min(len(set(tokens)) * 5, 20)

    # Activity volume bonus: 1 pt per 5 events (up to 10 pts)
    volume_score = min(event_count // 5, 10)

    total = stage_score + technique_score + token_score + volume_score
    return max(0, min(100, total))


def evaluate_playbook(risk_score: int, previously_contained: bool = False) -> Playbook:
    """Maps a risk score to the corresponding active response playbook."""
    if previously_contained or risk_score >= CONTAINMENT_THRESHOLD:
        return Playbook.CONTAIN
    if risk_score >= TARPIT_THRESHOLD:
        return Playbook.TARPIT
    return Playbook.WATCH
