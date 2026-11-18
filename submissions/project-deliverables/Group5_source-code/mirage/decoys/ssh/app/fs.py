"""Virtual filesystem for the fake deploy server.

The filesystem is plain data: a set of directories and a dict of file contents.
Every SSH session gets its own copy, so anything an attacker creates or deletes
persists for that session but never leaks into another attacker's view.

The bait (~/.aws/credentials and the hints in ~/.bash_history) is always
present and always identical, so the breadcrumb trail can be relied on.
"""

import posixpath
from dataclasses import dataclass, field

HOSTNAME = "ops-deploy-01"
USER = "deploy"
HOME = f"/home/{USER}"
S3_ENDPOINT = "http://10.66.0.22:9000"
BUCKET = "corp-backups"

# Path of the planted AWS credentials file (tagged as a honeytoken on read).
AWS_CREDENTIALS = f"{HOME}/.aws/credentials"


def _base_files(aws_key: dict[str, str]) -> dict[str, str]:
    """Static content of the server. `aws_key` comes from the honeytoken registry."""
    return {
        "/etc/hostname": f"{HOSTNAME}\n",
        "/etc/os-release": (
            'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\n'
            'VERSION="24.04.1 LTS (Noble Numbat)"\nVERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\n'
            'HOME_URL="https://www.ubuntu.com/"\nSUPPORT_URL="https://help.ubuntu.com/"\n'
        ),
        "/etc/passwd": (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
            "systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin\n"
            "sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n"
            "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
            f"{USER}:x:1001:1001:Release deploy,,,:{HOME}:/bin/bash\n"
            "postgres:x:110:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\n"
        ),
        "/etc/hosts": (
            "127.0.0.1 localhost\n127.0.1.1 ops-deploy-01\n"
            "10.66.0.20 ops.halcyon-freight.internal\n"
            "10.66.0.22 s3.halcyon-freight.internal\n"
            "10.66.0.31 db01.halcyon-freight.internal\n"
        ),
        f"{HOME}/.bashrc": (
            "# ~/.bashrc: executed by bash(1) for non-login shells.\n"
            "case $- in\n    *i*) ;;\n      *) return;;\nesac\n"
            "HISTCONTROL=ignoreboth\nHISTSIZE=1000\nHISTFILESIZE=2000\n"
            "alias ll='ls -alF'\nalias la='ls -A'\n"
            f"export AWS_ENDPOINT_URL={S3_ENDPOINT}\n"
        ),
        f"{HOME}/.profile": "if [ -n \"$BASH_VERSION\" ]; then\n    . \"$HOME/.bashrc\"\nfi\n",
        # Hints that lead the attacker to the next step: the S3 bucket.
        f"{HOME}/.bash_history": (
            "cd releases\nls -la\n./deploy.sh ops-console v3.8.2\n"
            "sudo systemctl status ops-console\n"
            f"aws s3 ls s3://{BUCKET}/ --endpoint-url {S3_ENDPOINT}\n"
            f"aws s3 cp s3://{BUCKET}/finance/ ./finance-backup --recursive --endpoint-url {S3_ENDPOINT}\n"
            "rm -rf finance-backup\npsql -h db01.halcyon-freight.internal -U ops_app ops_console\nexit\n"
        ),
        f"{HOME}/.aws/config": "[default]\nregion = eu-west-1\noutput = json\n",
        AWS_CREDENTIALS: (
            "[default]\n"
            f"aws_access_key_id = {aws_key.get('access_key_id', '')}\n"
            f"aws_secret_access_key = {aws_key.get('secret_access_key', '')}\n"
        ),
        f"{HOME}/releases/deploy.sh": (
            "#!/bin/bash\n# usage: ./deploy.sh <app> <version>\nset -euo pipefail\n"
            "APP=$1\nVER=$2\n"
            f"aws s3 cp s3://{BUCKET}/releases/$APP-$VER.tar.gz /tmp/ --endpoint-url {S3_ENDPOINT}\n"
            "sudo tar -xzf /tmp/$APP-$VER.tar.gz -C /opt/$APP\nsudo systemctl restart $APP\n"
        ),
        f"{HOME}/releases/CHANGELOG.md": (
            "## v3.8.2\n- fix shipment export timeout\n## v3.8.1\n- rotate db password (TODO: update .env backups)\n"
        ),
        f"{HOME}/notes.txt": (
            "- finance asked for the monthly passwords sheet backup to go to the s3 bucket, not email\n"
            "- move deploy creds to vault before audit (Q4)\n"
        ),
        "/var/log/syslog": "",
        "/opt/ops-console/VERSION": "3.8.2\n",
    }


@dataclass
class FileSystem:
    files: dict[str, str]
    dirs: set[str] = field(default_factory=set)

    @classmethod
    def build(cls, aws_key: dict[str, str]) -> "FileSystem":
        fs = cls(files=_base_files(aws_key))
        # Directories that exist even though they hold no files of ours.
        for d in ["/", "/bin", "/usr", "/usr/bin", "/tmp", "/var", "/var/www", "/root", "/proc",
                  "/home/ubuntu", f"{HOME}/.ssh", f"{HOME}/.cache"]:
            fs.dirs.add(d)
        # Every parent of every file is a directory.
        for path in fs.files:
            fs._add_parents(path)
        return fs

    def copy(self) -> "FileSystem":
        return FileSystem(files=dict(self.files), dirs=set(self.dirs))

    def _add_parents(self, path: str) -> None:
        parent = posixpath.dirname(path)
        while parent not in self.dirs:
            self.dirs.add(parent)
            if parent == "/":
                break
            parent = posixpath.dirname(parent)

    @staticmethod
    def resolve(cwd: str, path: str) -> str:
        """Turn a user-supplied path into a normalised absolute path."""
        if path == "~" or path.startswith("~/"):
            path = HOME + path[1:]
        return posixpath.normpath(posixpath.join(cwd, path)) if path else cwd

    def is_dir(self, path: str) -> bool:
        return path in self.dirs

    def is_file(self, path: str) -> bool:
        return path in self.files

    def read(self, path: str) -> str:
        return self.files[path]

    def write(self, path: str, content: str, append: bool = False) -> None:
        self._add_parents(path)
        self.files[path] = (self.files.get(path, "") if append else "") + content

    def mkdir(self, path: str) -> None:
        self._add_parents(path)
        self.dirs.add(path)

    def remove(self, path: str) -> None:
        """Remove a file, or a directory and everything under it."""
        self.files.pop(path, None)
        prefix = path.rstrip("/") + "/"
        for f in [f for f in self.files if f.startswith(prefix)]:
            del self.files[f]
        self.dirs -= {d for d in self.dirs if d == path or d.startswith(prefix)}

    def listdir(self, path: str) -> list[str]:
        """Names directly inside a directory, sorted like `ls`."""
        prefix = path.rstrip("/") + "/"
        names = {p[len(prefix):].split("/")[0] for p in [*self.files, *self.dirs]
                 if p.startswith(prefix) and p != path}
        return sorted(names, key=lambda n: n.lstrip(".").lower())
