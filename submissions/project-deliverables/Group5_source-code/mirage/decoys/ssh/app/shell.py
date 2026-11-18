"""Deterministic fake bash shell.

This is the scripted layer of the SSH decoy. It understands the commands an
intruder typically runs on a freshly compromised box, supports `;`, `&&`,
`||`, pipes, `>`/`>>` redirection and $VARIABLES, and keeps per-session
state (working directory, files created or deleted, history).

Anything it does not know is handed to an optional `fallback` (the LLM layer,
added later). Without a fallback, unknown commands get bash's normal
"command not found", so the decoy is fully functional with no LLM at all.
"""

import posixpath
import re
import shlex
from collections.abc import Callable

from .fs import HOME, HOSTNAME, USER, FileSystem

# fallback(command_line, shell) -> output, or None if it cannot answer.
Fallback = Callable[[str, "Shell"], str | None]

FIXED_DATE = "Sep 14 02:13"
OPERATORS = {";", "&&", "||", "|", ">", ">>"}

UNAME = {
    "-s": "Linux", "-n": HOSTNAME, "-r": "6.8.0-45-generic", "-m": "x86_64",
    "-a": f"Linux {HOSTNAME} 6.8.0-45-generic #45-Ubuntu SMP PREEMPT_DYNAMIC Fri Aug 30 12:02:04 UTC 2026 "
          "x86_64 x86_64 x86_64 GNU/Linux",
}

PS = """USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.3 167548 12960 ?        Ss   Sep14   0:21 /sbin/init
root         412  0.0  0.4  48212 17024 ?        S<s  Sep14   0:09 /lib/systemd/systemd-journald
root         688  0.0  0.1  15428  7364 ?        Ss   Sep14   0:00 sshd: /usr/sbin/sshd -D
root         702  0.0  0.0   7364  2880 ?        Ss   Sep14   0:03 /usr/sbin/cron -f
www-data     915  0.1  2.4 912340 98312 ?        Ssl  Sep14  12:47 /opt/ops-console/bin/ops-console --port 8080
root        1203  0.0  0.1  17168 10752 ?        Ss   15:02   0:00 sshd: deploy [priv]
deploy      1219  0.0  0.1   8792  5504 pts/0    Ss   15:02   0:00 -bash
deploy      1247  0.0  0.0  10884  4352 pts/0    R+   15:04   0:00 ps aux
"""

IP_ADDR = """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 52:54:00:3a:91:7c brd ff:ff:ff:ff:ff:ff
    inet 10.66.0.21/24 brd 10.66.0.255 scope global eth0
       valid_lft forever preferred_lft forever
"""

NETSTAT = """Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*
tcp   LISTEN 0      511        127.0.0.1:8080       0.0.0.0:*
tcp   ESTAB  0      0         10.66.0.21:22      {peer}:{port}
tcp   ESTAB  0      0         10.66.0.21:41822   10.66.0.31:5432
"""

DF = """Filesystem      Size  Used Avail Use% Mounted on
/dev/vda1        48G   17G   31G  36% /
tmpfs           2.0G     0  2.0G   0% /dev/shm
/dev/vda15      105M  6.1M   99M   6% /boot/efi
"""

FREE = """               total        used        free      shared  buff/cache   available
Mem:         4005384     1187220      398116        1344     2420048     2818164
Swap:        2097148           0     2097148
"""

KNOWN_BINARIES = {"bash", "sh", "ls", "cat", "grep", "ps", "id", "whoami", "uname", "hostname", "curl", "wget",
                  "python3", "perl", "ip", "ss", "netstat", "aws", "psql", "sudo", "tar", "systemctl", "vim"}


class Shell:
    def __init__(self, fs: FileSystem, peer: tuple[str, int] = ("10.66.0.50", 50000),
                 fallback: Fallback | None = None):
        self.fs = fs
        self.peer = peer
        self.fallback = fallback
        self.cwd = HOME
        self.env = {"HOME": HOME, "USER": USER, "LOGNAME": USER, "SHELL": "/bin/bash", "PWD": HOME,
                    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG": "C.UTF-8", "AWS_ENDPOINT_URL": "http://10.66.0.22:9000"}
        self.history: list[str] = fs.read(f"{HOME}/.bash_history").splitlines() \
            if fs.is_file(f"{HOME}/.bash_history") else []
        self.status = 0
        self.exited = False
        # Paths of files read by the last command line (used to detect honeytoken reads).
        self.files_read: list[str] = []
        # True when the last command line had to go to the fallback.
        self.used_fallback = False

    # ------------------------------------------------------------------ helpers

    def prompt(self) -> str:
        where = "~" + self.cwd[len(HOME):] if self.cwd.startswith(HOME) else self.cwd
        return f"{USER}@{HOSTNAME}:{where}$ "

    def _path(self, p: str) -> str:
        return self.fs.resolve(self.cwd, p)

    def _expand(self, token: str) -> str:
        return re.sub(r"\$\{?(\w+)\}?", lambda m: self.env.get(m.group(1), ""), token)

    def _read(self, path: str) -> str:
        self.files_read.append(path)
        return self.fs.read(path)

    # ------------------------------------------------------------------ parsing

    def run(self, line: str) -> str:
        """Run one command line and return everything it prints."""
        self.files_read = []
        self.used_fallback = False
        line = line.strip()
        if not line:
            return ""
        self.history.append(line)

        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|<>")
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError:
            # Unbalanced quotes: bash would wait for more input; we just error out.
            self.status = 2
            return "-bash: unexpected EOF while looking for matching quote\n"

        output, run_next = "", True
        # Split into [pipeline, operator, pipeline, operator, ...] on ; && ||
        for chunk, op in self._split(tokens, {";", "&&", "||"}):
            if run_next:
                output += self._pipeline(chunk, line)
            if self.exited:
                break
            run_next = op in (None, ";") or (op == "&&" and self.status == 0) or (op == "||" and self.status != 0)
        return output

    @staticmethod
    def _split(tokens: list[str], seps: set[str]) -> list[tuple[list[str], str | None]]:
        parts, cur = [], []
        for t in tokens:
            if t in seps:
                parts.append((cur, t))
                cur = []
            else:
                cur.append(t)
        parts.append((cur, None))
        return [(p, op) for p, op in parts if p]

    def _pipeline(self, tokens: list[str], raw_line: str) -> str:
        stdin = None
        for i, (cmd, _) in enumerate(self._split(tokens, {"|"})):
            # Output redirection: cmd > file / cmd >> file
            redirect = None
            for op in (">>", ">"):
                if op in cmd:
                    idx = cmd.index(op)
                    target = cmd[idx + 1] if idx + 1 < len(cmd) else None
                    redirect, cmd = (op, target), cmd[:idx]
                    break
            out = self._command([self._expand(t) for t in cmd], stdin, raw_line)
            if redirect:
                op, target = redirect
                if target is None:
                    self.status = 2
                    return "-bash: syntax error near unexpected token `newline'\n"
                path = self._path(self._expand(target))
                if not self.fs.is_dir(posixpath.dirname(path)):
                    self.status = 1
                    return f"-bash: {target}: No such file or directory\n"
                self.fs.write(path, out, append=(op == ">>"))
                out = ""
            stdin = out
        return stdin or ""

    def _command(self, argv: list[str], stdin: str | None, raw_line: str) -> str:
        if not argv:
            return ""
        name, args = argv[0], argv[1:]
        handler = getattr(self, "cmd_" + name, None) if name.isidentifier() else None
        self.status = 0
        if handler:
            return handler(args, stdin)

        if self.fallback:
            answer = self.fallback(raw_line, self)
            if answer is not None:
                self.used_fallback = True
                return answer if answer.endswith("\n") or not answer else answer + "\n"
        self.status = 127
        return f"-bash: {name}: command not found\n"

    # ------------------------------------------------------------------ commands
    # Each cmd_<name>(args, stdin) returns the command's output and sets self.status.

    def cmd_pwd(self, args, stdin):
        return self.cwd + "\n"

    def cmd_cd(self, args, stdin):
        target = self._path(args[0]) if args else HOME
        if not self.fs.is_dir(target):
            self.status = 1
            return f"-bash: cd: {args[0]}: {'Not a directory' if self.fs.is_file(target) else 'No such file or directory'}\n"
        self.cwd = self.env["PWD"] = target
        return ""

    def cmd_ls(self, args, stdin):
        flags = "".join(a[1:] for a in args if a.startswith("-"))
        paths = [a for a in args if not a.startswith("-")] or ["."]
        show_all, long = "a" in flags or "A" in flags, "l" in flags
        out = []
        for p in paths:
            path = self._path(p)
            if self.fs.is_file(path):
                out.append(self._ls_entry(path, p, long))
                continue
            if not self.fs.is_dir(path):
                self.status = 2
                out.append(f"ls: cannot access '{p}': No such file or directory")
                continue
            names = self.fs.listdir(path)
            if not show_all:
                names = [n for n in names if not n.startswith(".")]
            elif "a" in flags:
                names = [".", ".."] + names
            if len(paths) > 1:
                out.append(f"{p}:")
            if long:
                out.append(f"total {4 * len(names)}")
                out += [self._ls_entry(posixpath.join(path, n), n, True) for n in names]
            elif names:
                out.append("  ".join(names))
        return "\n".join(out) + "\n" if out else ""

    def _ls_entry(self, path: str, name: str, long: bool) -> str:
        if not long:
            return name
        is_dir = self.fs.is_dir(path) or name in (".", "..")
        owner = USER if path.startswith(HOME) else "root"
        size = 4096 if is_dir else len(self.fs.files.get(path, ""))
        perms = "drwxr-xr-x" if is_dir else ("-rwxr-xr-x" if path.endswith(".sh") else "-rw-r--r--")
        if path.endswith("/.aws/credentials") or path.endswith(".bash_history"):
            perms = "-rw-------"
        return f"{perms} 1 {owner:<6} {owner:<6} {size:>5} {FIXED_DATE} {name}"

    def cmd_cat(self, args, stdin):
        files = [a for a in args if not a.startswith("-")]
        if not files:
            return stdin or ""
        out = []
        for f in files:
            path = self._path(f)
            if self.fs.is_dir(path):
                self.status = 1
                out.append(f"cat: {f}: Is a directory\n")
            elif not self.fs.is_file(path):
                self.status = 1
                out.append(f"cat: {f}: {'Permission denied' if path.startswith('/root') or path == '/etc/shadow' else 'No such file or directory'}\n")
            else:
                out.append(self._read(path))
        return "".join(out)

    def cmd_echo(self, args, stdin):
        if args and args[0] == "-n":
            return " ".join(args[1:])
        return " ".join(args) + "\n"

    def cmd_whoami(self, args, stdin):
        return USER + "\n"

    def cmd_id(self, args, stdin):
        return f"uid=1001({USER}) gid=1001({USER}) groups=1001({USER}),4(adm),24(cdrom),30(dip)\n"

    def cmd_hostname(self, args, stdin):
        return HOSTNAME + "\n"

    def cmd_uname(self, args, stdin):
        return (UNAME.get(args[0], UNAME["-s"]) if args else UNAME["-s"]) + "\n"

    def cmd_uptime(self, args, stdin):
        return " 15:04:11 up 51 days,  3:12,  1 user,  load average: 0.08, 0.05, 0.01\n"

    def cmd_w(self, args, stdin):
        return (self.cmd_uptime(args, stdin) +
                "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
                f"{USER:<8} pts/0    {self.peer[0]:<16} 15:02    0.00s  0.02s  0.00s w\n")

    def cmd_ps(self, args, stdin):
        return PS

    def cmd_ip(self, args, stdin):
        return IP_ADDR

    cmd_ifconfig = cmd_ip

    def cmd_ss(self, args, stdin):
        return NETSTAT.format(peer=self.peer[0], port=self.peer[1])

    cmd_netstat = cmd_ss

    def cmd_df(self, args, stdin):
        return DF

    def cmd_free(self, args, stdin):
        return FREE

    def cmd_env(self, args, stdin):
        return "".join(f"{k}={v}\n" for k, v in self.env.items())

    cmd_printenv = cmd_env

    def cmd_export(self, args, stdin):
        for a in args:
            if "=" in a:
                k, v = a.split("=", 1)
                self.env[k] = v
        return ""

    def cmd_history(self, args, stdin):
        if args and args[0] == "-c":
            self.history = []
            return ""
        return "".join(f"{i:>5}  {c}\n" for i, c in enumerate(self.history, 1))

    def cmd_which(self, args, stdin):
        found = [f"/usr/bin/{a}" for a in args if a in KNOWN_BINARIES or hasattr(self, "cmd_" + a)]
        self.status = 0 if len(found) == len(args) else 1
        return "".join(f + "\n" for f in found)

    def cmd_clear(self, args, stdin):
        return "\x1b[H\x1b[2J"

    def cmd_exit(self, args, stdin):
        self.exited = True
        return "logout\n"

    cmd_logout = cmd_exit

    # --- filters (work on stdin or files)

    def _input(self, files: list[str], stdin: str | None, cmd: str) -> str | None:
        if not files:
            return stdin or ""
        path = self._path(files[0])
        if not self.fs.is_file(path):
            self.status = 1
            return None
        return self._read(path)

    def cmd_grep(self, args, stdin):
        flags = "".join(a[1:] for a in args if a.startswith("-"))
        rest = [a for a in args if not a.startswith("-")]
        if not rest:
            self.status = 2
            return "Usage: grep [OPTION]... PATTERNS [FILE]...\n"
        pattern, files = rest[0], rest[1:]
        text = self._input(files, stdin, "grep")
        if text is None:
            return f"grep: {files[0]}: No such file or directory\n"
        try:
            rx = re.compile(pattern, re.IGNORECASE if "i" in flags else 0)
        except re.error:
            rx = re.compile(re.escape(pattern), re.IGNORECASE if "i" in flags else 0)
        lines = [l for l in text.splitlines() if bool(rx.search(l)) != ("v" in flags)]
        self.status = 0 if lines else 1
        return "".join(l + "\n" for l in lines)

    def _head_tail(self, args, stdin, tail: bool):
        n = 10
        files = []
        it = iter(args)
        for a in it:
            if a == "-n":
                n = int(next(it, "10"))
            elif re.fullmatch(r"-\d+", a):
                n = int(a[1:])
            else:
                files.append(a)
        text = self._input(files, stdin, "tail" if tail else "head")
        if text is None:
            return f"{'tail' if tail else 'head'}: cannot open '{files[0]}' for reading: No such file or directory\n"
        lines = text.splitlines()
        lines = lines[-n:] if tail else lines[:n]
        return "".join(l + "\n" for l in lines)

    def cmd_head(self, args, stdin):
        return self._head_tail(args, stdin, tail=False)

    def cmd_tail(self, args, stdin):
        return self._head_tail(args, stdin, tail=True)

    def cmd_wc(self, args, stdin):
        files = [a for a in args if not a.startswith("-")]
        text = self._input(files, stdin, "wc")
        if text is None:
            return f"wc: {files[0]}: No such file or directory\n"
        if "-l" in args:
            return f"{text.count(chr(10))}{' ' + files[0] if files else ''}\n"
        return f"{text.count(chr(10)):>7} {len(text.split()):>7} {len(text):>7}{' ' + files[0] if files else ''}\n"

    # --- commands that change the session's filesystem

    def cmd_touch(self, args, stdin):
        for a in args:
            path = self._path(a)
            if not self.fs.is_file(path):
                self.fs.write(path, "")
        return ""

    def cmd_mkdir(self, args, stdin):
        for a in (a for a in args if not a.startswith("-")):
            path = self._path(a)
            if self.fs.is_dir(path) or self.fs.is_file(path):
                if "-p" not in args:
                    self.status = 1
                    return f"mkdir: cannot create directory '{a}': File exists\n"
                continue
            if "-p" not in args and not self.fs.is_dir(posixpath.dirname(path)):
                self.status = 1
                return f"mkdir: cannot create directory '{a}': No such file or directory\n"
            self.fs.mkdir(path)
        return ""

    def cmd_rm(self, args, stdin):
        flags = "".join(a[1:] for a in args if a.startswith("-"))
        for a in (a for a in args if not a.startswith("-")):
            path = self._path(a)
            if self.fs.is_dir(path) and "r" not in flags.lower():
                self.status = 1
                return f"rm: cannot remove '{a}': Is a directory\n"
            if not (self.fs.is_dir(path) or self.fs.is_file(path)):
                if "f" not in flags:
                    self.status = 1
                    return f"rm: cannot remove '{a}': No such file or directory\n"
                continue
            self.fs.remove(path)
        return ""

    def cmd_cp(self, args, stdin):
        files = [a for a in args if not a.startswith("-")]
        if len(files) != 2 or not self.fs.is_file(self._path(files[0])):
            self.status = 1
            return f"cp: cannot stat '{files[0] if files else ''}': No such file or directory\n"
        src, dst = self._path(files[0]), self._path(files[1])
        if self.fs.is_dir(dst):
            dst = posixpath.join(dst, posixpath.basename(src))
        self.fs.write(dst, self._read(src))
        return ""

    def cmd_mv(self, args, stdin):
        out = self.cmd_cp(args, stdin)
        if self.status == 0:
            self.fs.remove(self._path([a for a in args if not a.startswith("-")][0]))
        return out

    def cmd_chmod(self, args, stdin):
        return ""

    # --- commands that would need privileges or the network

    def cmd_sudo(self, args, stdin):
        self.status = 1
        return f"[sudo] password for {USER}: \nSorry, try again.\nsudo: 1 incorrect password attempt\n"

    def cmd_su(self, args, stdin):
        self.status = 1
        return "Password: \nsu: Authentication failure\n"

    def cmd_curl(self, args, stdin):
        # The box has no outbound internet (true in the isolated lab too).
        host = next((a for a in args if not a.startswith("-")), "")
        host = re.sub(r"^\w+://", "", host).split("/")[0]
        self.status = 6
        return f"curl: (6) Could not resolve host: {host}\n" if host else \
            "curl: try 'curl --help' or 'curl --manual' for more information\n"

    def cmd_wget(self, args, stdin):
        url = next((a for a in args if not a.startswith("-")), "")
        host = re.sub(r"^\w+://", "", url).split("/")[0]
        self.status = 4
        return (f"--2026-11-04 15:04:12--  {url}\nResolving {host} ({host})... failed: "
                f"Temporary failure in name resolution.\nwget: unable to resolve host address '{host}'\n")

    def cmd_aws(self, args, stdin):
        # Point the attacker at the endpoint from their own machine (the next trail step).
        self.status = 255
        return f'\nCould not connect to the endpoint URL: "{self.env["AWS_ENDPOINT_URL"]}/"\n'
