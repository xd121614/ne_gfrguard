"""
gfrguard Web API - Flask-based management interface.

Provides REST endpoints (GET/POST only) for:
  1. View/modify policy configuration
  2. View/manage blocked sessions
  3. Whitelist management
  4. Event/detection status (blocked events only)
  5. Quarantine management
  6. Restore blocked sessions
  7. Storage usage info
"""

import json
import os
import subprocess
import sqlite3
import shutil
import time as _time
from pathlib import Path

from flask import Flask, jsonify, request, abort, send_from_directory

app = Flask(__name__, static_folder=None)

POLICY_PATH = "/etc/gf2000/rguard-policy.json"
BLOCKED_PATH = "/run/gfrguardd/blocked"
DB_PATH = "/var/lib/gf2000/rguard-store/index.db"
STORE_PATH = "/var/lib/gf2000/rguard-store"
QUARANTINE_PATH = os.path.join(STORE_PATH, "quarantine")
BACKUP_PATH = os.path.join(STORE_PATH, "backups")
WEB_DIR = os.path.dirname(os.path.abspath(__file__))
RECOVER_BIN = "/usr/bin/gfrguard-recover"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_policy():
    with open(POLICY_PATH, "r") as f:
        return json.load(f)


def save_policy(data):
    with open(POLICY_PATH, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

    os.system('systemctl restart gfrguardd')


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def read_blocked():
    """Return list of blocked session keys."""
    try:
        with open(BLOCKED_PATH, "r") as f:
            lines = f.read().strip().splitlines()
        return [l.strip() for l in lines if l.strip()]
    except FileNotFoundError:
        return []


def write_blocked(sessions):
    """Atomically write blocked list."""
    tmp = BLOCKED_PATH + ".tmp"
    content = "\n".join(sessions) + "\n" if sessions else ""
    with open(tmp, "w") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.rename(tmp, BLOCKED_PATH)

def get_func_switch():
    output = subprocess.getoutput("grep gfrguard:protect /etc/samba/smb.conf | awk '{print $NF}'")
    if output.strip().lower() in ("yes", "true", "1", "on"):
        return True
    return False

def set_func_switch(enabled):
    if enabled:
        os.system("sed -i 's/^.*gfrguard:protect.*/gfrguard:protect = yes/i' /etc/samba/smb.conf")
    else:
        os.system("sed -i 's/^.*gfrguard:protect.*/gfrguard:protect = no/i' /etc/samba/smb.conf")
    os.system('systemctl restart smb')

def dir_usage_bytes(path):
    """Return total bytes used by a directory tree."""
    total = 0
    if not os.path.isdir(path):
        return 0
    for root, _dirs, files in os.walk(path):
        for fname in files:
            try:
                total += os.path.getsize(os.path.join(root, fname))
            except OSError:
                pass
    return total


# ---------------------------------------------------------------------------
# Static file serving
# ---------------------------------------------------------------------------

@app.route("/")
def serve_index():
    return send_from_directory(WEB_DIR, "index.html")


# ---------------------------------------------------------------------------
# 1. View current config
# ---------------------------------------------------------------------------

@app.route("/api/config", methods=["GET"])
def get_config():
    """Return current policy configuration."""
    policy = load_policy()
    return jsonify({
        "mode": get_func_switch(),
        "auto_restore": policy.get("auto_restore", {}),
        "scoring": policy.get("scoring", {}),
        "whitelist": policy.get("whitelist", {}),
        "space": policy.get("space", {}),
        "log_level": policy.get("log_level", "info"),
        "store_path": policy.get("store_path", STORE_PATH),
		"file_extensions": policy.get("file_extensions", {}),
    })


# ---------------------------------------------------------------------------
# 2. Modify configuration (POST only)
# ---------------------------------------------------------------------------

@app.route("/api/config", methods=["POST"])
def update_config():
    """Update policy fields. Accepts partial updates."""
    body = request.get_json(force=True)
    if not body:
        abort(400, description="Empty request body")

    policy = load_policy()

    allowed = {"mode", "auto_restore", "scoring", "whitelist", "space", "log_level", "file_extensions"}
    for key, value in body.items():
        if key not in allowed:
            continue
        if key == "mode":
            set_func_switch(bool(value))
        elif isinstance(value, dict) and isinstance(policy.get(key), dict):
            policy[key].update(value)
        else:
            policy[key] = value

    save_policy(policy)
    return jsonify({"status": "ok", "config": policy})


# ---------------------------------------------------------------------------
# 3. View blocked sessions
# ---------------------------------------------------------------------------

@app.route("/api/blocked", methods=["GET"])
def get_blocked():
    """List currently blocked sessions with event info."""
    sessions = read_blocked()
    result = []
    for skey in sessions:
        entry = {}
        parts = skey.split("@", 1)
        entry["username"] = parts[0] if parts else skey
        entry["client_ip"] = parts[1] if len(parts) > 1 else ""
        entry["session_key"] = skey
        result.append(entry)

    return jsonify({"blocked": result, "count": len(result)})


# ---------------------------------------------------------------------------
# 4. Unblock session (POST only)
# ---------------------------------------------------------------------------

@app.route("/api/blocked/remove", methods=["POST"])
def unblock_session():
    """Remove a session from blocked list.
    Body: {"session_key": "user@ip"}
    """
    body = request.get_json(force=True)
    session_key = body.get("session_key", "").strip()
    if not session_key:
        abort(400, description="Missing 'session_key'")

    sessions = read_blocked()
    if session_key not in sessions:
        return jsonify({"status": "not_found",
                        "message": f"{session_key} is not blocked"}), 404

    sessions.remove(session_key)
    write_blocked(sessions)
	# auto del ip from blacklist when unblock session
    policy = load_policy()
    bl = policy.setdefault("blacklist", {"users": [], "ips": []})
    curr_ip = session_key.split("@", 1)[1] if "@" in session_key else ""
    if curr_ip in bl["ips"]:
        bl["ips"].remove(curr_ip)
        save_policy(policy)

    return jsonify({"status": "ok", "unblocked": session_key})


# ---------------------------------------------------------------------------
# 5. Restore blocked session
# ---------------------------------------------------------------------------

@app.route("/api/restore", methods=["POST"])
def restore_event():
    """Restore files for a blocked event and unblock the session.
    Body: {"event_id": "evt-YYYYMMDD-NNN"}
    """
    body = request.get_json(force=True)
    event_id = body.get("event_id", "").strip()
    if not event_id:
        abort(400, description="Missing 'event_id'")

    if "/" in event_id or ".." in event_id or ";" in event_id:
        abort(400, description="Invalid event_id")

    try:
        result = subprocess.run(
            [RECOVER_BIN, "restore", "--event", event_id],
            capture_output=True, text=True, timeout=120
        )
        return jsonify({
            "status": "ok" if result.returncode == 0 else "error",
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        })
    except FileNotFoundError:
        return jsonify({"status": "error",
                        "message": "gfrguard-recover not found"}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error",
                        "message": "restore timed out"}), 500


# ---------------------------------------------------------------------------
# 6. Whitelist management
# ---------------------------------------------------------------------------

@app.route("/api/users", methods=["GET"])
def get_users():
    usertype = request.args.get("type", "whitelist").strip().lower()
    output = subprocess.getoutput("ls /mnt/storage/filer/home/")
    users = []
    for one in output.splitlines():
        if one.strip().rsplit('b_')[0] == '':
            continue
        users.append(one.strip())

    ex_user = load_policy().get("whitelist", {}).get("users", []) if usertype == "whitelist" else load_policy().get("blacklist", {}).get("users", [])
    users = [u for u in users if u not in ex_user]
    return jsonify({"users": users})

@app.route("/api/whitelist", methods=["GET"])
def get_whitelist():
    """Return current whitelist and blacklist."""
    policy = load_policy()
    wl = policy.get("whitelist", {"users": [], "ips": []})
    bl = policy.get("blacklist", {"users": [], "ips": []})
    return jsonify({"whitelist": wl, "blacklist": bl})


@app.route("/api/whitelist/users/add", methods=["POST"])
def add_whitelist_user():
    """Add a user to whitelist. Body: {"user": "name"}"""
    body = request.get_json(force=True)
    user = body.get("user", "").strip()
    if not user:
        abort(400, description="Missing 'user' field")

    policy = load_policy()
    wl = policy.setdefault("whitelist", {"users": [], "ips": []})
    if user not in wl["users"]:
        wl["users"].append(user)
        save_policy(policy)
    return jsonify({"status": "ok", "whitelist": wl})


@app.route("/api/whitelist/users/remove", methods=["POST"])
def remove_whitelist_user():
    """Remove a user from whitelist. Body: {"user": "name"}"""
    body = request.get_json(force=True)
    username = body.get("user", "").strip()
    if not username:
        abort(400, description="Missing 'user' field")

    policy = load_policy()
    wl = policy.setdefault("whitelist", {"users": [], "ips": []})
    if username in wl["users"]:
        wl["users"].remove(username)
        save_policy(policy)
        return jsonify({"status": "ok", "whitelist": wl})
    return jsonify({"status": "not_found"}), 404


@app.route("/api/whitelist/ips/add", methods=["POST"])
def add_whitelist_ip():
    """Add an IP to whitelist. Body: {"ip": "x.x.x.x"}"""
    body = request.get_json(force=True)
    ip = body.get("ip", "").strip()
    if not ip:
        abort(400, description="Missing 'ip' field")

    policy = load_policy()
    wl = policy.setdefault("whitelist", {"users": [], "ips": []})
    if ip not in wl["ips"]:
        wl["ips"].append(ip)
        save_policy(policy)
    return jsonify({"status": "ok", "whitelist": wl})


@app.route("/api/whitelist/ips/remove", methods=["POST"])
def remove_whitelist_ip():
    """Remove an IP from whitelist. Body: {"ip": "x.x.x.x"}"""
    body = request.get_json(force=True)
    ip = body.get("ip", "").strip()
    if not ip:
        abort(400, description="Missing 'ip' field")

    policy = load_policy()
    wl = policy.setdefault("whitelist", {"users": [], "ips": []})
    if ip in wl["ips"]:
        wl["ips"].remove(ip)
        save_policy(policy)
        return jsonify({"status": "ok", "whitelist": wl})
    return jsonify({"status": "not_found"}), 404


# ---------------------------------------------------------------------------
# 6b. Blacklist management
# ---------------------------------------------------------------------------

@app.route("/api/blacklist/users/add", methods=["POST"])
def add_blacklist_user():
    """Add a user to blacklist. Body: {"user": "name"}"""
    body = request.get_json(force=True)
    user = body.get("user", "").strip()
    if not user:
        abort(400, description="Missing 'user' field")

    policy = load_policy()
    bl = policy.setdefault("blacklist", {"users": [], "ips": []})
    if user not in bl["users"]:
        bl["users"].append(user)
        save_policy(policy)
    return jsonify({"status": "ok", "blacklist": bl})


@app.route("/api/blacklist/users/remove", methods=["POST"])
def remove_blacklist_user():
    """Remove a user from blacklist. Body: {"user": "name"}"""
    body = request.get_json(force=True)
    username = body.get("user", "").strip()
    if not username:
        abort(400, description="Missing 'user' field")

    policy = load_policy()
    bl = policy.setdefault("blacklist", {"users": [], "ips": []})
    if username in bl["users"]:
        bl["users"].remove(username)
        save_policy(policy)
        return jsonify({"status": "ok", "blacklist": bl})
    return jsonify({"status": "not_found"}), 404


@app.route("/api/blacklist/ips/add", methods=["POST"])
def add_blacklist_ip():
    """Add an IP to blacklist. Body: {"ip": "x.x.x.x"}"""
    body = request.get_json(force=True)
    ip = body.get("ip", "").strip()
    if not ip:
        abort(400, description="Missing 'ip' field")

    policy = load_policy()
    bl = policy.setdefault("blacklist", {"users": [], "ips": []})
    if ip not in bl["ips"]:
        bl["ips"].append(ip)
        save_policy(policy)
    return jsonify({"status": "ok", "blacklist": bl})


@app.route("/api/blacklist/ips/remove", methods=["POST"])
def remove_blacklist_ip():
    """Remove an IP from blacklist. Body: {"ip": "x.x.x.x"}"""
    body = request.get_json(force=True)
    ip = body.get("ip", "").strip()
    if not ip:
        abort(400, description="Missing 'ip' field")

    policy = load_policy()
    bl = policy.setdefault("blacklist", {"users": [], "ips": []})
    if ip in bl["ips"]:
        bl["ips"].remove(ip)
        save_policy(policy)
        return jsonify({"status": "ok", "blacklist": bl})
    return jsonify({"status": "not_found"}), 404


# ---------------------------------------------------------------------------
# 7. Detection events (blocked + restored history)
# ---------------------------------------------------------------------------

@app.route("/api/events", methods=["GET"])
def get_events():
    """List detection events that were blocked (including restored ones).
    Query params: username, limit (default 50)
    """
    username_filter = request.args.get("username")
    limit = request.args.get("limit", 50, type=int)

    db = get_db()
    sql = "SELECT * FROM events WHERE action_taken IN ('blocked', 'restored')"
    params = []

    if username_filter:
        sql += " AND username = ?"
        params.append(username_filter)

    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    rows = db.execute(sql, params).fetchall()

    events = [dict(r) for r in rows]

    # Compute actual files_protected from protected_files table
    if events:
        event_ids = [ev['event_id'] for ev in events]
        placeholders = ','.join(['?'] * len(event_ids))
        count_rows = db.execute(
            f"SELECT event_id, COUNT(*) as cnt FROM protected_files "
            f"WHERE event_id IN ({placeholders}) GROUP BY event_id",
            event_ids
        ).fetchall()
        counts = {r['event_id']: r['cnt'] for r in count_rows}
        for ev in events:
            ev['files_protected'] = counts.get(ev['event_id'], 0)
            new_file_count = db.execute(
                "SELECT COUNT(*) FROM created_files WHERE event_id = ?", (ev['event_id'],)).fetchone()[0]
            # if ev['action_taken'] == 'restored':
            ev['files_deleted'] = new_file_count
            ev['files_created'] = new_file_count

    db.close()

    return jsonify({"events": events, "count": len(events)})


@app.route("/api/events/files", methods=["GET"])
def get_event_files():
    """List protected files for a specific event.
    Query params: event_id (required)
    """
    event_id = request.args.get("event_id", "").strip()
    if not event_id:
        abort(400, description="Missing 'event_id' parameter")

    db = get_db()
    rows = db.execute(
        "SELECT id, event_id, original_path, backup_path, share_name, "
        "username, client_ip, file_size, op_type, protected_at, restore_status, restored_at "
        "FROM protected_files WHERE event_id = ? ORDER BY id",
        (event_id,)
    ).fetchall()

    created = db.execute(
        "SELECT id, file_path, created_at FROM created_files WHERE event_id = ? ORDER BY id",
        (event_id,)
    ).fetchall()
    db.close()

    return jsonify({
        "event_id": event_id,
        "protected_files": [dict(r) for r in rows],
        "created_files": [dict(r) for r in created],
    })


# ---------------------------------------------------------------------------
# 8. Quarantine info (with username and client_ip)
# ---------------------------------------------------------------------------

@app.route("/api/quarantine", methods=["GET"])
def get_quarantine():
    """List quarantine contents with username and client_ip per event."""
    result = []
    if not os.path.isdir(QUARANTINE_PATH):
        return jsonify({"quarantine": result, "total_files": 0})

    total = 0
    db = None
    try:
        db = get_db()
    except Exception:
        pass

    for event_dir in sorted(os.listdir(QUARANTINE_PATH)):
        event_path = os.path.join(QUARANTINE_PATH, event_dir)
        if not os.path.isdir(event_path):
            continue
        files = []
        earliest_mtime = None
        for root, _dirs, filenames in os.walk(event_path):
            for fname in filenames:
                full = os.path.join(root, fname)
                rel = os.path.relpath(full, event_path)
                mtime = None
                try:
                    st = os.stat(full)
                    size = st.st_size
                    mtime = st.st_mtime
                    if earliest_mtime is None or mtime < earliest_mtime:
                        earliest_mtime = mtime
                except OSError:
                    size = 0
                file_mtime = _time.strftime(
                    "%Y-%m-%dT%H:%M:%S", _time.localtime(mtime)) if mtime else ""
                files.append({"path": rel, "size": size, "mtime": file_mtime})
                total += 1

        quarantine_time = ""
        if earliest_mtime is not None:
            quarantine_time = _time.strftime(
                "%Y-%m-%dT%H:%M:%S", _time.localtime(earliest_mtime))

        username = ""
        client_ip = ""
        started_at = ""
        ended_at = ""
        if db:
            try:
                row = db.execute(
                    "SELECT username, client_ip, started_at, ended_at FROM events WHERE event_id = ?",
                    (event_dir,)
                ).fetchone()
                if row:
                    username = row["username"]
                    client_ip = row["client_ip"]
                    started_at = row["started_at"] or ""
                    ended_at = row["ended_at"] or ""
            except Exception:
                pass

        # Enrich each file with event-level times
        for f in files:
            f["started_at"] = started_at
            f["quarantine_time"] = ended_at if ended_at else quarantine_time

        result.append({
            "event_id": event_dir,
            "username": username,
            "client_ip": client_ip,
            "started_at": started_at,
            "quarantine_time": ended_at if ended_at else quarantine_time,
            "files": files,
            "file_count": len(files),
        })

    if db:
        db.close()

    return jsonify({"quarantine": result, "total_files": total})


# ---------------------------------------------------------------------------
# 9. Delete quarantine content (POST only)
# ---------------------------------------------------------------------------

@app.route("/api/quarantine/remove", methods=["POST"])
def delete_quarantine():
    """Delete quarantine files for a specific event or all.
    Body: {"event_id": "evt-..."} or omit/empty to clear all.
    """
    body = request.get_json(force=True) if request.data else {}
    event_id = body.get("event_id", "").strip()

    if event_id:
        if "/" in event_id or ".." in event_id:
            abort(400, description="Invalid event_id")
        event_path = os.path.join(QUARANTINE_PATH, event_id)
        if not os.path.isdir(event_path):
            return jsonify({"status": "not_found"}), 404
        shutil.rmtree(event_path)
        return jsonify({"status": "ok", "deleted_event": event_id})
    else:
        if not os.path.isdir(QUARANTINE_PATH):
            return jsonify({"status": "ok", "message": "quarantine already empty"})
        shutil.rmtree(QUARANTINE_PATH)
        os.makedirs(QUARANTINE_PATH, mode=0o755, exist_ok=True)
        return jsonify({"status": "ok", "message": "all quarantine content deleted"})


@app.route("/api/quarantine/restore", methods=["POST"])
def restore_quarantine():
    """Restore quarantined files back to their original locations.
    Body: {"event_id": "evt-...", "files": ["/path/to/file", ...]}
    If 'files' is omitted or empty, restore all files in the event.
    """
    body = request.get_json(force=True) if request.data else {}
    event_id = body.get("event_id", "").strip()
    selected_files = body.get("files", [])

    if not event_id:
        abort(400, description="event_id is required")
    if "/" in event_id or ".." in event_id or ";" in event_id:
        abort(400, description="Invalid event_id")

    event_path = os.path.join(QUARANTINE_PATH, event_id)
    if not os.path.isdir(event_path):
        return jsonify({"status": "not_found", "message": "Event not found"}), 404

    restored = 0
    failed = 0
    total = 0

    if selected_files:
        # Restore specific files
        for fpath in selected_files:
            fpath = fpath.strip()
            if not fpath or ".." in fpath:
                continue
            rel = fpath.lstrip("/")
            src = os.path.join(event_path, rel)
            dst = os.path.join("/", rel)
            if not os.path.isfile(src):
                continue
            total += 1
            try:
                os.makedirs(os.path.dirname(dst), mode=0o755, exist_ok=True)
                shutil.copy2(src, dst)
                os.remove(src)
                restored += 1
            except Exception:
                failed += 1
    else:
        # Restore all files in event
        for root, _dirs, fnames in os.walk(event_path):
            for fname in fnames:
                src = os.path.join(root, fname)
                rel = os.path.relpath(src, event_path)
                dst = os.path.join("/", rel)
                total += 1
                try:
                    os.makedirs(os.path.dirname(dst), mode=0o755, exist_ok=True)
                    shutil.copy2(src, dst)
                    os.remove(src)
                    restored += 1
                except Exception:
                    failed += 1

    # Clean up empty event directory
    try:
        _remove_empty_dirs(event_path)
    except Exception:
        pass

    # Update DB: mark restored files
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            "UPDATE events SET action_taken='restored', status='resolved' WHERE event_id=?",
            (event_id,)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

    return jsonify({
        "status": "ok",
        "restored": restored,
        "failed": failed,
        "total": total,
    })

# ---------------------------------------------------------------------------
# 9b. Delete quarantine files (single/multiple, POST only)
# ---------------------------------------------------------------------------

@app.route("/api/quarantine/delete_files", methods=["POST"])
def delete_quarantine_files():
    """Delete specific files in a quarantine event.
    Body: {"event_id": "evt-...", "files": ["/path/to/file", ...]}
    """
    body = request.get_json(force=True) if request.data else {}
    event_id = body.get("event_id", "").strip()
    files = body.get("files", [])
    if not event_id or not files or not isinstance(files, list):
        abort(400, description="event_id and files required")
    if "/" in event_id or ".." in event_id or ";" in event_id:
        abort(400, description="Invalid event_id")
    event_path = os.path.join(QUARANTINE_PATH, event_id)
    if not os.path.isdir(event_path):
        return jsonify({"status": "not_found", "message": "Event not found"}), 404
    deleted = 0
    failed = 0
    for fpath in files:
        fpath = fpath.strip()
        if not fpath or ".." in fpath:
            failed += 1
            continue
        rel = fpath.lstrip("/")
        absf = os.path.join(event_path, rel)
        if os.path.isfile(absf):
            try:
                os.remove(absf)
                deleted += 1
            except Exception:
                failed += 1
        else:
            failed += 1
    # 清理空目录
    try:
        _remove_empty_dirs(event_path)
    except Exception:
        pass
    return jsonify({"status": "ok", "deleted": deleted, "failed": failed, "total": len(files)})

def _remove_empty_dirs(path):
    """Remove directory tree if empty after file restoration."""
    if not os.path.isdir(path):
        return
    for root, dirs, files in os.walk(path, topdown=False):
        if not files and not dirs:
            os.rmdir(root)
        elif not files:
            # check if subdirs are also empty
            for d in dirs:
                dp = os.path.join(root, d)
                if os.path.isdir(dp) and not os.listdir(dp):
                    os.rmdir(dp)
    if os.path.isdir(path) and not os.listdir(path):
        os.rmdir(path)


# ---------------------------------------------------------------------------
# 10. Storage usage
# ---------------------------------------------------------------------------

@app.route("/api/storage", methods=["GET"])
def get_storage():
    """Return usage info for quarantine and backup directories."""
    quarantine_used = dir_usage_bytes(QUARANTINE_PATH)
    backup_used = dir_usage_bytes(BACKUP_PATH)

    return jsonify({
        "quarantine": {
            "path": QUARANTINE_PATH,
            "used_bytes": quarantine_used,
        },
        "backup": {
            "path": BACKUP_PATH,
            "used_bytes": backup_used,
        },
    })


# ---------------------------------------------------------------------------
# 11. Clear backup zone (POST only)
# ---------------------------------------------------------------------------

@app.route("/api/backup/clear", methods=["POST"])
def clear_backup():
    """Delete all backup content."""
    if not os.path.isdir(BACKUP_PATH):
        return jsonify({"status": "ok", "message": "backup already empty"})
    shutil.rmtree(BACKUP_PATH)
    os.makedirs(BACKUP_PATH, mode=0o755, exist_ok=True)
    return jsonify({"status": "ok", "message": "all backup content deleted"})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8880, debug=False)
