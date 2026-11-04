"""The breadcrumb trail, in the order an attacker is meant to walk it.

robots.txt → backup .env → SSH login → ~/.aws/credentials → S3 → passwords.xlsx
"""

from enum import IntEnum


class TrailStage(IntEnum):
    NONE = 0
    ROBOTS_TXT = 1       # read robots.txt and found the hidden backup path
    ENV_BACKUP = 2       # downloaded the exposed backup .env
    SSH_LOGIN = 3        # logged into the fake SSH server with the .env password
    AWS_CREDS_READ = 4   # read ~/.aws/credentials on the SSH decoy
    S3_ACCESS = 5        # used the fake AWS keys against the fake S3 endpoint
    BAIT_DOWNLOAD = 6    # downloaded passwords.xlsx from the bucket


FINAL_STAGE = TrailStage.BAIT_DOWNLOAD
