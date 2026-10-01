"""Signing secrets must never be tracked, and a leaked one must be rotated."""
import subprocess
from pathlib import Path

from conftest import load_sentrylog

REPO_ROOT = Path(__file__).resolve().parent.parent


def _tracked():
    return subprocess.run(["git", "ls-files"], cwd=str(REPO_ROOT), capture_output=True,
                          text=True, check=True).stdout.split()


def test_no_secret_files_tracked():
    bad = [f for f in _tracked()
           if f.endswith((".key", ".pem")) or "auth_secret" in f]
    assert bad == []


def test_auth_secret_is_gitignored():
    out = subprocess.run(["git", "check-ignore", "-q", "auth_secret.key"],
                         cwd=str(REPO_ROOT))
    assert out.returncode == 0


def test_leaked_secret_on_disk_is_rotated(data_dir, monkeypatch):
    mod = load_sentrylog(data_dir)
    secret_file = data_dir / "auth_secret.key"
    leaked = secret_file.read_bytes()  # what this install generated
    # Pretend the value on disk is a published one.
    monkeypatch.setattr(mod, "_REVOKED_SECRET_SHA256",
                        frozenset({__import__("hashlib").sha256(leaked).hexdigest()}))
    fresh = mod._load_or_create_secret()
    assert fresh != leaked and len(fresh) >= 32
    assert secret_file.read_bytes().strip() == fresh


def test_leaked_secret_in_env_is_ignored(data_dir, monkeypatch):
    mod = load_sentrylog(data_dir)
    monkeypatch.setenv("SENTRYLOG_AUTH_SECRET", "x" * 40)
    monkeypatch.setattr(mod, "_REVOKED_SECRET_SHA256",
                        frozenset({__import__("hashlib").sha256(b"x" * 40).hexdigest()}))
    assert mod._load_or_create_secret() != b"x" * 40


def test_the_committed_secret_is_on_the_revocation_list(data_dir):
    mod = load_sentrylog(data_dir)
    assert ("3c508d38e69ceeab14d0a1acdcde5a127de164bd154b4b6cca028d943f8c81b7"
            in mod._REVOKED_SECRET_SHA256)


def test_real_committed_value_is_rejected(data_dir):
    blob = subprocess.run(["git", "show", "5d57551:auth_secret.key"], cwd=str(REPO_ROOT),
                          capture_output=True, check=False).stdout
    if not blob:
        return  # shallow clone without that commit
    mod = load_sentrylog(data_dir)
    (data_dir / "auth_secret.key").write_bytes(blob)
    assert mod._load_or_create_secret() != blob.strip()
