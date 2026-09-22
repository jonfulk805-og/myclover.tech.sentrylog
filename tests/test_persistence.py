"""Container-replacement persistence test for NetMon / SentryLog.

Docker is unavailable in this sandbox, so we simulate a container replacement on
the filesystem: the app code is copied into a throwaway "image" directory, the
data dir lives outside it, the app is initialised, the image directory is then
deleted and recreated from the repo (a fresh container from the same image), and
we assert the database written in round 1 is still there and still readable in
round 2.

Run:  pytest tests/test_persistence.py   (or: python tests/test_persistence.py)
"""
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

PY = sys.executable

APPS = {
    "netmon": {
        "module": "netmon.py",
        "db": "netmon.db",
        "cfg": "config.yaml",
        "env_prefix": "NETMON",
        "extra": ["ai_assistant.py", "stripe_handler.py", "stripe_config.yaml",
                  "templates", "plugins"],
        "probe_table": "check_results",
    },
    "sentrylog": {
        "module": "sentrylog.py",
        "db": "sentrylog.db",
        "cfg": "sentrylog_config.yaml",
        "env_prefix": "SENTRYLOG",
        "extra": ["templates"],
        "probe_table": "sources",
    },
}


def build_image(repo: Path, image_dir: Path, spec: dict) -> None:
    """Copy just the application files into a fresh throwaway 'image' dir."""
    if image_dir.exists():
        shutil.rmtree(image_dir)
    image_dir.mkdir(parents=True)
    for name in [spec["module"], spec["cfg"]] + spec["extra"]:
        src = repo / name
        if not src.exists():
            continue
        dst = image_dir / name
        if src.is_dir():
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)


def run_init(image_dir: Path, data_dir: Path, spec: dict) -> str:
    """Import the app with the data-dir env vars set and initialise its DB."""
    p = spec["env_prefix"]
    env = dict(os.environ)
    env.update({
        "%s_DATA_DIR" % p: str(data_dir),
        "%s_DB_PATH" % p: str(data_dir / spec["db"]),
        "%s_CONFIG" % p: str(data_dir / spec["cfg"]),
        "%s_BACKUP_DIR" % p: str(data_dir / "backups"),
    })
    code = (
        "import importlib.util, sys, pathlib\n"
        "spec = importlib.util.spec_from_file_location('app', %r)\n"
        "m = importlib.util.module_from_spec(spec)\n"
        "sys.modules['app'] = m\n"
        "spec.loader.exec_module(m)\n"
        "m._ensure_data_dirs()\n"
        "m.init_db()\n"
        "print('DB_PATH=%%s' %% m.DB_PATH)\n"
        "print('CFG=%%s' %% m.DEFAULT_CFG)\n"
        "print('BACKUP_DIR=%%s' %% m.BACKUP_DIR)\n"
    ) % str(image_dir / spec["module"])
    res = subprocess.run([PY, "-c", code], cwd=str(image_dir), env=env,
                         capture_output=True, text=True)
    if res.returncode != 0:
        raise SystemExit("init failed:\n%s\n%s" % (res.stdout, res.stderr))
    return res.stdout


def table_names(db: Path):
    conn = sqlite3.connect(str(db))
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    finally:
        conn.close()
    return {r[0] for r in rows}


APP = "sentrylog"


def test_survives_container_replacement():
    main()


def main(repo_path=None) -> int:
    app = APP
    repo = (Path(repo_path) if repo_path
            else Path(__file__).resolve().parent.parent).resolve()
    spec = APPS[app]

    tmp = Path(tempfile.mkdtemp(prefix="persist-%s-" % app))
    image_dir, data_dir = tmp / "image", tmp / "data"
    data_dir.mkdir()

    print("== round 1: first container")
    build_image(repo, image_dir, spec)
    print(run_init(image_dir, data_dir, spec).strip())

    db = data_dir / spec["db"]
    assert db.is_file(), "DB was not created in the data dir: %s" % db
    assert not (image_dir / spec["db"]).exists(), \
        "DB leaked into the image dir (%s) - not persistent" % spec["db"]
    tables_1 = table_names(db)
    assert spec["probe_table"] in tables_1, \
        "expected table %s missing" % spec["probe_table"]

    # Write a marker row so we prove data (not just the file) survives.
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE IF NOT EXISTS persist_probe (v TEXT)")
    conn.execute("INSERT INTO persist_probe VALUES ('survived')")
    conn.commit()
    conn.close()
    (data_dir / spec["cfg"]).write_text("# edited by admin\n", encoding="utf-8")

    print("== destroying the container (image dir) and starting a fresh one")
    shutil.rmtree(image_dir)
    build_image(repo, image_dir, spec)
    print(run_init(image_dir, data_dir, spec).strip())

    assert db.is_file(), "DB vanished after container replacement"
    conn = sqlite3.connect(str(db))
    got = conn.execute("SELECT v FROM persist_probe").fetchall()
    conn.close()
    assert got == [("survived",)], "probe row lost: %r" % (got,)
    assert table_names(db) >= tables_1, "tables lost after replacement"
    assert (data_dir / spec["cfg"]).read_text(encoding="utf-8") == \
        "# edited by admin\n", "admin config edit was overwritten"
    assert (data_dir / "backups").is_dir(), "backups dir not on the data volume"

    print("PASS %s: db, config edit and backups dir survived container "
          "replacement" % app)
    shutil.rmtree(tmp)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else None))
