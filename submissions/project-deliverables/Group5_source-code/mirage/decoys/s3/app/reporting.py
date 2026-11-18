"""Telemetry and honeytoken event reporting for the S3 decoy."""

import logging
from typing import Any, Callable, Dict, Optional
from mirage_common import Event, EventClient, EventType, Source

log = logging.getLogger("mirage.s3")

HT_AWS_KEY = "ht-aws-access-key"
HT_PASSWORDS_XLSX = "ht-passwords-xlsx"


class S3Reporter:
    def __init__(self, emit: Optional[Callable[[Event], Any]] = None):
        self._custom_emit = emit
        self._client: Optional[EventClient] = None

    def _get_emit(self) -> Callable[[Event], Any]:
        if self._custom_emit is not None:
            return self._custom_emit
        if self._client is None:
            self._client = EventClient()
        return self._client.submit

    def report(
        self,
        event_type: EventType,
        src_ip: str,
        src_port: Optional[int] = None,
        asset: Optional[str] = None,
        honeytoken_id: Optional[str] = None,
        attack_techniques: Optional[list[str]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        try:
            event = Event(
                source=Source.S3,
                event_type=event_type,
                src_ip=src_ip,
                src_port=src_port,
                asset=asset,
                honeytoken_id=honeytoken_id,
                attack_techniques=attack_techniques or [],
                details=details or {},
            )
            self._get_emit()(event)
        except Exception:
            # Telemetry errors must never disrupt decoy operation
            log.exception("failed to emit S3 event")

    def report_key_used(self, src_ip: str, src_port: Optional[int], asset: str, details: Dict[str, Any]) -> None:
        self.report(
            event_type=EventType.HONEYTOKEN_USED,
            src_ip=src_ip,
            src_port=src_port,
            asset=asset,
            honeytoken_id=HT_AWS_KEY,
            attack_techniques=["T1078.004"],
            details=details,
        )

    def report_bait_download(self, src_ip: str, src_port: Optional[int], asset: str, details: Dict[str, Any]) -> None:
        self.report(
            event_type=EventType.FILE_ACCESS,
            src_ip=src_ip,
            src_port=src_port,
            asset=asset,
            honeytoken_id=HT_PASSWORDS_XLSX,
            attack_techniques=["T1530"],
            details=details,
        )

    def report_failed_auth(self, src_ip: str, src_port: Optional[int], access_key: Optional[str], asset: str, error: str) -> None:
        self.report(
            event_type=EventType.LOGIN_ATTEMPT,
            src_ip=src_ip,
            src_port=src_port,
            asset=asset,
            attack_techniques=["T1110"],
            details={"access_key": access_key, "success": False, "error": error},
        )

    def report_probe(self, src_ip: str, src_port: Optional[int], method: str, path: str) -> None:
        self.report(
            event_type=EventType.HTTP_REQUEST,
            src_ip=src_ip,
            src_port=src_port,
            asset=path,
            details={"method": method, "path": path},
        )
