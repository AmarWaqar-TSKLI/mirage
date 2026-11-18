"""Forensic capture helper for snapshotting compromised decoy containers."""

import logging
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict

log = logging.getLogger("mirage.controller.forensics")


class SnapshotManager:
    def __init__(self, prefix: str = "mirage-evidence"):
        self.prefix = prefix
        self._docker_path = shutil.which("docker")

    def snapshot(self, container_name: str, src_ip: str) -> Dict[str, Any]:
        """Creates a forensic Docker image snapshot before container resets."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        sanitized_ip = src_ip.replace(".", "_").replace(":", "_")
        image_tag = f"{self.prefix}/{container_name}:{sanitized_ip}_{ts}"

        if self._docker_path:
            try:
                cmd = [self._docker_path, "commit", container_name, image_tag]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10.0)
                if res.returncode == 0:
                    image_id = res.stdout.strip()
                    log.info("created forensic snapshot %s (%s)", image_tag, image_id[:12])
                    return {"success": True, "image_tag": image_tag, "image_id": image_id, "backend": "docker"}
                log.warning("docker commit failed for %s: %s", container_name, res.stderr.strip())
            except Exception as e:
                log.warning("docker snapshot error: %s", e)

        # Fallback / simulated evidence metadata
        log.info("simulated forensic snapshot tag %s", image_tag)
        return {"success": True, "image_tag": image_tag, "backend": "simulated"}
