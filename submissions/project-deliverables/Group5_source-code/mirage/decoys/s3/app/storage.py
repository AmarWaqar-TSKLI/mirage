"""In-memory virtual S3 storage holding bait and filler objects."""

import hashlib
import gzip
import io
import tarfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .bait import generate_passwords_spreadsheet

BUCKET_NAME = "corp-backups"


@dataclass
class S3Object:
    key: str
    data: bytes
    content_type: str
    last_modified: datetime
    etag: str

    @classmethod
    def create(cls, key: str, data: bytes, content_type: str) -> "S3Object":
        etag = f'"{hashlib.md5(data).hexdigest()}"'
        return cls(
            key=key,
            data=data,
            content_type=content_type,
            last_modified=datetime.now(timezone.utc),
            etag=etag,
        )


def _build_filler_tar_gz() -> bytes:
    """Creates a realistic ops-console-v3.8.2.tar.gz archive."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        files = {
            "ops-console/package.json": b'{"name":"ops-console","version":"3.8.2","private":true}\n',
            "ops-console/VERSION": b"3.8.2\n",
            "ops-console/config/production.json": b'{"port":80,"logLevel":"info","dbHost":"db01.halcyon-freight.internal"}\n',
        }
        for name, content in files.items():
            ti = tarfile.TarInfo(name=name)
            ti.size = len(content)
            ti.mtime = int(datetime(2026, 11, 1, tzinfo=timezone.utc).timestamp())
            tar.addfile(tarinfo=ti, fileobj=io.BytesIO(content))
    return buf.getvalue()


def _build_filler_sql_gz() -> bytes:
    """Creates a realistic SQL backup dump."""
    sql = (
        "-- Halcyon Freight DB Schema Dump\n"
        "-- Host: db01.halcyon-freight.internal Database: ops_console\n"
        "SET statement_timeout = 0;\n"
        "CREATE TABLE shipments (id SERIAL PRIMARY KEY, tracking_no VARCHAR(64), status VARCHAR(32));\n"
        "INSERT INTO shipments (tracking_no, status) VALUES ('HLC-99021', 'DELIVERED'), ('HLC-99022', 'IN_TRANSIT');\n"
    ).encode("utf-8")
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(sql)
    return buf.getvalue()


class Storage:
    def __init__(self):
        self.buckets = [BUCKET_NAME]
        self._objects: Dict[str, Dict[str, S3Object]] = {BUCKET_NAME: {}}
        self._populate_defaults()

    def _populate_defaults(self) -> None:
        # Bait file (Stage 6)
        passwords_xlsx = generate_passwords_spreadsheet()
        self.put(
            BUCKET_NAME,
            "finance/passwords.xlsx",
            passwords_xlsx,
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

        # Filler objects (mentioned in bash_history and deploy.sh)
        self.put(
            BUCKET_NAME,
            "releases/ops-console-v3.8.2.tar.gz",
            _build_filler_tar_gz(),
            "application/gzip",
        )
        self.put(
            BUCKET_NAME,
            "db/staging-dump-20261101.sql.gz",
            _build_filler_sql_gz(),
            "application/gzip",
        )
        self.put(
            BUCKET_NAME,
            "manifest.json",
            b'{"backup_policy":"daily-retention-30d","encrypted":false,"owner":"infra-ops"}\n',
            "application/json",
        )

    def put(self, bucket: str, key: str, data: bytes, content_type: str) -> S3Object:
        if bucket not in self._objects:
            self._objects[bucket] = {}
        obj = S3Object.create(key=key, data=data, content_type=content_type)
        self._objects[bucket][key] = obj
        return obj

    def get(self, bucket: str, key: str) -> Optional[S3Object]:
        return self._objects.get(bucket, {}).get(key)

    def list_objects(self, bucket: str, prefix: str = "", delimiter: str = "") -> List[S3Object]:
        bucket_objs = self._objects.get(bucket, {})
        results = []
        for key, obj in sorted(bucket_objs.items()):
            if key.startswith(prefix):
                results.append(obj)
        return results

    def exists(self, bucket: str, key: Optional[str] = None) -> bool:
        if bucket not in self._objects:
            return False
        if key is not None:
            return key in self._objects[bucket]
        return True
