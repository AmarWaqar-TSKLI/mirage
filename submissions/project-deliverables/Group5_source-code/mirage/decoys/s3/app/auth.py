"""AWS Signature and Authorization parsing for the fake S3 endpoint."""

import re
from dataclasses import dataclass
from typing import Optional
from fastapi import Request


@dataclass
class AuthResult:
    authenticated: bool
    access_key: Optional[str] = None
    is_honeytoken: bool = False
    error: Optional[str] = None


CREDENTIAL_REGEX = re.compile(r"Credential=([^/,\s]+)")
AWS_LEGACY_REGEX = re.compile(r"^AWS\s+([^:]+):")


class S3Authenticator:
    def __init__(self, expected_access_key: str, expected_secret_key: Optional[str] = None):
        self.expected_access_key = expected_access_key
        self.expected_secret_key = expected_secret_key

    def extract_access_key(self, request: Request) -> Optional[str]:
        # 1. Authorization header (AWS SigV4 or legacy)
        auth_header = request.headers.get("authorization", "")
        if auth_header:
            match = CREDENTIAL_REGEX.search(auth_header)
            if match:
                return match.group(1)
            legacy_match = AWS_LEGACY_REGEX.match(auth_header)
            if legacy_match:
                return legacy_match.group(1)

        # 2. Query parameters (presigned URLs)
        cred_param = request.query_params.get("X-Amz-Credential")
        if cred_param:
            return cred_param.split("/")[0]

        aws_id_param = request.query_params.get("AWSAccessKeyId")
        if aws_id_param:
            return aws_id_param

        return None

    def authenticate(self, request: Request) -> AuthResult:
        access_key = self.extract_access_key(request)

        # No auth provided
        if not access_key:
            return AuthResult(authenticated=False, access_key=None, error="AccessDenied")

        # Planted honeytoken key matched
        if self.expected_access_key and access_key == self.expected_access_key:
            return AuthResult(authenticated=True, access_key=access_key, is_honeytoken=True)

        # Wrong access key
        return AuthResult(authenticated=False, access_key=access_key, is_honeytoken=False, error="InvalidAccessKeyId")
