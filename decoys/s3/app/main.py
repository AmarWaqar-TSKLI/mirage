"""Fake AWS S3 endpoint (trail stages 5 and 6).

Implements an S3-compatible storage service that accepts the fake AWS access keys
planted in ~/.aws/credentials and serves the bait passwords.xlsx spreadsheet.
All AWS requests, bucket scans, and file downloads are tracked and reported to
the Mirage controller.
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, Response, status
from mirage_common import EnforcementState, Registry, start_control_server

from .auth import S3Authenticator
from .reporting import S3Reporter
from .storage import BUCKET_NAME, Storage
from .xml_views import xml_error, xml_list_buckets, xml_list_objects

log = logging.getLogger("mirage.s3")
logging.basicConfig(level=logging.INFO)

SERVER_HEADER = "MinIO"

# Containment state pushed from the controller (see mirage_common.control).
enforcement = EnforcementState()


@asynccontextmanager
async def lifespan(app: FastAPI):
    token_path = os.environ.get("MIRAGE_HONEYTOKENS", "/etc/mirage/honeytokens.json")
    expected_access_key = ""
    expected_secret_key = ""

    if os.path.exists(token_path):
        try:
            registry = Registry.load(token_path)
            aws_token = registry.get("ht-aws-access-key")
            if aws_token and aws_token.value:
                expected_access_key = aws_token.value.get("access_key_id", "")
                expected_secret_key = aws_token.value.get("secret_access_key", "")
        except Exception:
            log.exception("failed to load honeytoken registry from %s", token_path)

    if not hasattr(app.state, "storage") or app.state.storage is None:
        app.state.storage = Storage()
    if not hasattr(app.state, "auth") or app.state.auth is None:
        app.state.auth = S3Authenticator(expected_access_key, expected_secret_key)
    if not hasattr(app.state, "reporter") or app.state.reporter is None:
        app.state.reporter = S3Reporter()

    port = int(os.environ.get("S3_CONTROL_PORT", "8090"))
    try:
        start_control_server(enforcement, port)
    except OSError as e:
        log.warning("control server not started on %d: %s", port, e)

    log.info("s3 decoy ready; accepting access key: %s...", expected_access_key[:8] if expected_access_key else "none")
    yield


app = FastAPI(title="Mirage S3 Decoy", lifespan=lifespan, docs_url=None, redoc_url=None)


@app.middleware("http")
async def enforce(request: Request, call_next):
    ip = request.client.host if request.client else ""
    if enforcement.is_blocked(ip):
        return Response(content=xml_error("AccessDenied", "Access Denied", request.url.path),
                        status_code=status.HTTP_403_FORBIDDEN, media_type="application/xml",
                        headers={"Server": SERVER_HEADER})
    delay = enforcement.tarpit_delay(ip)
    if delay:
        await asyncio.sleep(delay)
    return await call_next(request)


def _client_ip_port(request: Request) -> tuple[str, Optional[int]]:
    import ipaddress
    client_ip = "127.0.0.1"
    client_port = request.client.port if request.client else None
    if request.client and request.client.host:
        try:
            ipaddress.ip_address(request.client.host)
            client_ip = request.client.host
        except ValueError:
            client_ip = "127.0.0.1"
    return client_ip, client_port


def _xml_response(content: str, status_code: int = 200) -> Response:
    return Response(
        content=content,
        status_code=status_code,
        media_type="application/xml",
        headers={"Server": SERVER_HEADER, "x-amz-request-id": "TX000000000000000001"},
    )


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/")
def list_buckets(request: Request) -> Response:
    ip, port = _client_ip_port(request)
    auth = request.app.state.auth.authenticate(request)

    if not auth.authenticated:
        request.app.state.reporter.report_failed_auth(ip, port, auth.access_key, "/", auth.error or "AccessDenied")
        return _xml_response(xml_error(auth.error or "AccessDenied", "Access Denied", "/"), status.HTTP_403_FORBIDDEN)

    request.app.state.reporter.report_key_used(ip, port, "s3://", {"action": "ListBuckets"})
    xml = xml_list_buckets(request.app.state.storage.buckets)
    return _xml_response(xml)


@app.get("/{bucket}")
@app.get("/{bucket}/")
def list_bucket_objects(bucket: str, request: Request, prefix: str = "", delimiter: str = "") -> Response:
    ip, port = _client_ip_port(request)
    auth = request.app.state.auth.authenticate(request)
    storage: Storage = request.app.state.storage

    if not storage.exists(bucket):
        return _xml_response(xml_error("NoSuchBucket", "The specified bucket does not exist", f"/{bucket}"), status.HTTP_404_NOT_FOUND)

    if not auth.authenticated:
        request.app.state.reporter.report_failed_auth(ip, port, auth.access_key, f"s3://{bucket}", auth.error or "AccessDenied")
        return _xml_response(xml_error(auth.error or "AccessDenied", "Access Denied", f"/{bucket}"), status.HTTP_403_FORBIDDEN)

    request.app.state.reporter.report_key_used(ip, port, f"s3://{bucket}", {"action": "ListObjects", "prefix": prefix})
    objs = storage.list_objects(bucket, prefix=prefix, delimiter=delimiter)
    return _xml_response(xml_list_objects(bucket, objs, prefix=prefix))


@app.get("/{bucket}/{key:path}")
def get_object(bucket: str, key: str, request: Request) -> Response:
    ip, port = _client_ip_port(request)
    auth = request.app.state.auth.authenticate(request)
    storage: Storage = request.app.state.storage
    obj = storage.get(bucket, key)

    if not storage.exists(bucket):
        return _xml_response(xml_error("NoSuchBucket", "The specified bucket does not exist", f"/{bucket}"), status.HTTP_404_NOT_FOUND)

    if not auth.authenticated:
        request.app.state.reporter.report_failed_auth(ip, port, auth.access_key, f"{bucket}/{key}", auth.error or "AccessDenied")
        return _xml_response(xml_error(auth.error or "AccessDenied", "Access Denied", f"/{bucket}/{key}"), status.HTTP_403_FORBIDDEN)

    if not obj:
        return _xml_response(xml_error("NoSuchKey", "The specified key does not exist.", f"/{bucket}/{key}"), status.HTTP_404_NOT_FOUND)

    asset = f"{bucket}/{key}"
    details = {"action": "GetObject", "size": len(obj.data)}

    # Honeytoken check: downloading the bait spreadsheet triggers Stage 6
    if bucket == BUCKET_NAME and key == "finance/passwords.xlsx":
        request.app.state.reporter.report_bait_download(ip, port, asset, details)
    else:
        request.app.state.reporter.report_key_used(ip, port, asset, details)

    return Response(
        content=obj.data,
        status_code=status.HTTP_200_OK,
        media_type=obj.content_type,
        headers={
            "Server": SERVER_HEADER,
            "ETag": obj.etag,
            "Content-Length": str(len(obj.data)),
            "Last-Modified": obj.last_modified.strftime("%a, %d %b %Y %H:%M:%S GMT"),
            "Accept-Ranges": "bytes",
        },
    )


@app.head("/{bucket}/{key:path}")
def head_object(bucket: str, key: str, request: Request) -> Response:
    ip, port = _client_ip_port(request)
    auth = request.app.state.auth.authenticate(request)
    storage: Storage = request.app.state.storage
    obj = storage.get(bucket, key)

    if not storage.exists(bucket) or not obj:
        return Response(status_code=status.HTTP_404_NOT_FOUND, headers={"Server": SERVER_HEADER})

    if not auth.authenticated:
        request.app.state.reporter.report_failed_auth(ip, port, auth.access_key, f"{bucket}/{key}", auth.error or "AccessDenied")
        return Response(status_code=status.HTTP_403_FORBIDDEN, headers={"Server": SERVER_HEADER})

    return Response(
        status_code=status.HTTP_200_OK,
        media_type=obj.content_type,
        headers={
            "Server": SERVER_HEADER,
            "ETag": obj.etag,
            "Content-Length": str(len(obj.data)),
            "Last-Modified": obj.last_modified.strftime("%a, %d %b %Y %H:%M:%S GMT"),
        },
    )
