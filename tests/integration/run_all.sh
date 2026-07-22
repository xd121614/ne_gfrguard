#!/bin/bash
# run_all.sh — gfrguard integration test suite (single daemon instance)
# Supports system Samba and source-built Samba (any version).
# set -euo pipefail  # disabled: kill/pidof can trigger early exit in test flow

# SAMBA_VER: source-built Samba version (e.g. "4.19.6", "4.23.5").
# SAMBA_SRC_BASE: root dir containing samba-${SAMBA_VER} trees.
# If SAMBA_VER is empty or source tree not found, system smbd is used.
# Resolve relative to THIS SCRIPT, not the caller's cwd — running from
# anywhere else silently fell back to system smbd before.
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAMBA_VER="${SAMBA_VER:-}"
SAMBA_SRC_BASE="${SAMBA_SRC_BASE:-${PROJECT_DIR}/samba-src}"
SAMBA_SRC="${SAMBA_SRC_BASE}/samba-${SAMBA_VER}"

if [ -n "${SAMBA_VER}" ] && [ -d "${SAMBA_SRC}" ]; then
    SMB_BIN="${SAMBA_SRC}/bin/default/source3"
    VFS_DIR="${SAMBA_SRC}/bin/modules/vfs"
    SMB_CONF="/usr/local/samba/etc/smb.conf"

    SMB="timeout 15 ${SMB_BIN}/client/smbclient -s ${SMB_CONF} //localhost/rguard-test -U testuser%testpass"
    SMB4="timeout 15 ${SMB_BIN}/client/smbclient -s ${SMB_CONF} //127.0.0.1/rguard-test -U testuser%testpass"

    smb_restart() {
        pkill -9 smbd 2>/dev/null || true
        sleep 1
        ${SMB_BIN}/smbd/smbd -D -s "${SMB_CONF}" 2>/dev/null &
        disown 2>/dev/null
        sleep 2
    }
    smb_stop() {
        pkill -9 smbd 2>/dev/null || true
        sleep 1
    }
    # blocker_execute needs version-matched smbcontrol
    export PATH="${SMB_BIN}/utils:${SMB_BIN}:${PATH}"
else
    SMB="timeout 15 smbclient //localhost/rguard-test -U testuser%testpass"
    SMB4="timeout 15 smbclient //127.0.0.1/rguard-test -U testuser%testpass"
    SMB_CONF="/etc/samba/smb.conf"
    smb_restart() {
        if systemctl is-active smb >/dev/null 2>&1; then
            timeout 30 systemctl restart smb 2>/dev/null
        else
            pkill -9 smbd 2>/dev/null || true
            sleep 1
            smbd -D 2>/dev/null &
            disown 2>/dev/null
        fi
        sleep 2
    }
    smb_stop() {
        timeout 30 systemctl stop smb 2>/dev/null || true
        pkill -9 smbd 2>/dev/null || true
    }
fi

SHARE_DIR="/srv/samba/rguard-test"

# --- vsftpd (real FTP server for the FTP channel tests) ---
# exec -a fakes once taught the tests a cmdline format that never existed
# in vsftpd ("ip: user: action" instead of "ip/user: action").  The FTP
# tests now drive a REAL vsftpd via python3 ftplib so the daemon parses
# genuine process titles.  NOTE: vsftpd only rewrites its process title
# when setproctitle_enable=YES (default OFF) — without it the daemon
# silently falls back to socket-inode resolution and virtual users are
# invisible.
VSFTPD_BIN="${PROJECT_DIR}/vsftpd-3.0.5/vsftpd"
VSFTPD_CONF="/tmp/gfrguard-vsftpd.conf"
VSFTPD_PORT=2121
HAVE_VSFTPD=false
[ -x "$VSFTPD_BIN" ] && HAVE_VSFTPD=true

ftp_setup() {
    mkdir -p /srv/ftp /usr/share/empty /home/testuser
    chmod 0777 /srv/ftp && chmod 0555 /usr/share/empty
    chown testuser:testuser /home/testuser 2>/dev/null || true
    echo 'testuser:testpass' | chpasswd
    if [ ! -f /etc/pam.d/vsftpd ]; then
        cat > /etc/pam.d/vsftpd << 'PAMEOF'
auth required pam_unix.so
account required pam_unix.so
PAMEOF
    fi
    cat > "$VSFTPD_CONF" << VSFTPDEOF
listen=YES
listen_port=${VSFTPD_PORT}
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_root=/srv/ftp
setproctitle_enable=YES
check_shell=NO
seccomp_sandbox=NO
local_umask=022
VSFTPDEOF
}

ftp_start() {
    # $1: YES (default) rewrites process titles; NO keeps the original
    # argv — the daemon must then fall back to socket-inode + UID
    # resolution (vsftpd's factory default is OFF).
    local proctitle="${1:-YES}"
    sed -i "s/^setproctitle_enable=.*/setproctitle_enable=${proctitle}/" "$VSFTPD_CONF"
    # Match comm ("vsftpd"), NOT -f: setproctitle rewrites the listener's
    # cmdline to "vsftpd: LISTENER", so a path pattern never matches.
    pkill -x vsftpd 2>/dev/null || true
    sleep 1
    "$VSFTPD_BIN" "$VSFTPD_CONF" &
    disown 2>/dev/null
    sleep 1
}

ftp_stop() {
    pkill -x vsftpd 2>/dev/null || true
}

STORE="/var/lib/gf2000/rguard-store"
LOG="/var/log/gfrguard/gfrguard.log"
DB="${STORE}/index.db"
POLICY="/etc/gf2000/rguard-policy.json"
BLOCKED="/run/gfrguardd/blocked"
DAEMON="/usr/local/sbin/gfrguardd"
YR_DIR="${PROJECT_DIR}/tests/fixtures/ransomware_notes"

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); echo "  ✅"; }
fail() { FAIL=$((FAIL+1)); echo "  ❌"; }

# --- helpers ---

kill_daemon() {
    pkill -9 gfrguardd 2>/dev/null
    rm -f /run/gfrguardd/gfrguardd.sock
}

start_daemon() {
    :> "$LOG"
    $DAEMON --config "$POLICY" &
    disown 2>/dev/null
    for i in $(seq 1 10); do sleep 1; grep -q 'YARA_ENGINE_READY' "$LOG" 2>/dev/null && break; done
}

clean_policy() {
    cat > "$POLICY" << 'POLICYEOF'
{"store_path":"/var/lib/gf2000/rguard-store","log_path":"/var/log/gfrguard","log_level":"debug","mode":"permissive","scoring_config":"/etc/gf2000/rguard-scoring.json","ransom_extensions_config":"/etc/gf2000/ransom-extensions.json","exceptions":{"files":[],"folders":[]},"whitelist":{"users":[],"ips":[]},"blacklist":{"users":[],"ips":[]},"space":{"max_usage_percent":80,"cleanup_days":30},"auto_restore":{"enabled":false,"delay_seconds":3},"scoring":{"window_short":10,"window_long":30,"weights":{"modified":3,"rename":4,"delete":3,"dirs":5,"ext_change":5,"ransom_ext":20,"high_entropy":8,"yara_match":40},"thresholds":{"warn":30,"high":60,"critical":80},"entropy_threshold":7.0,"entropy_enabled":true,"yara_enabled":true}}
POLICYEOF
}

clean_state() {
    :> "$BLOCKED"
    sqlite3 "$DB" "DELETE FROM events; DELETE FROM protected_files; DELETE FROM created_files;" 2>/dev/null
    rm -rf "${STORE}/backups"/*
    kill_daemon
    start_daemon
}

policy_with_exceptions() {
    local files_json="${1:-[]}"
    local folders_json="${2:-[]}"
    cat > "$POLICY" << POLICYEOF
{"store_path":"/var/lib/gf2000/rguard-store","log_path":"/var/log/gfrguard","log_level":"debug","mode":"permissive","scoring_config":"/etc/gf2000/rguard-scoring.json","ransom_extensions_config":"/etc/gf2000/ransom-extensions.json","exceptions":{"files":${files_json},"folders":${folders_json}},"whitelist":{"users":[],"ips":[]},"blacklist":{"users":[],"ips":[]},"space":{"max_usage_percent":80,"cleanup_days":30},"auto_restore":{"enabled":false,"delay_seconds":3},"scoring":{"window_short":10,"window_long":30,"weights":{"modified":3,"rename":4,"delete":3,"dirs":5,"ext_change":5,"ransom_ext":20,"high_entropy":8,"yara_match":40},"thresholds":{"warn":30,"high":60,"critical":80},"entropy_threshold":7.0,"entropy_enabled":true,"yara_enabled":true}}
POLICYEOF
}

reset_files() {
    for i in $(seq 1 10); do echo "original $i" > "${SHARE_DIR}/f${i}.txt"; chown testuser:testuser "${SHARE_DIR}/f${i}.txt" 2>/dev/null || true; done
    rm -f "${SHARE_DIR}"/*.locked 2>/dev/null
}

dump_diag() {
    echo "  diag: daemon_pid=$(pidof gfrguardd 2>/dev/null || echo 0) smbd_pids=$(pidof smbd 2>/dev/null || echo 0)"
    echo "  diag: log_lines=$(wc -l < "$LOG" 2>/dev/null || echo 0) blocked_bytes=$(stat -c%s "$BLOCKED" 2>/dev/null || echo 0)"
    echo "  diag: MSG_RECV=$(grep -c MSG_RECV "$LOG" 2>/dev/null || echo 0) YARA_MATCH=$(grep -c YARA_MATCH "$LOG" 2>/dev/null || echo 0) BLOCK_EXECUTED=$(grep -c BLOCK_EXECUTED "$LOG" 2>/dev/null || echo 0)"
    echo "  diag: socket=$(ls -la /run/gfrguardd/gfrguardd.sock 2>/dev/null || echo MISSING)"
    echo "  diag: blocked_content='$(tr '\n' '|' < "$BLOCKED" 2>/dev/null)'"
    echo "  diag: log_tail='$(tail -5 "$LOG" 2>/dev/null | tr '\n' '|')'"
}

WAIT=3

echo "============================================"
echo " GFRGuard Integration Tests"
echo " $(uname -n) / $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || echo Unknown)"
if [ -n "${SAMBA_VER}" ] && [ -d "${SAMBA_SRC}" ]; then
    echo " Samba $(${SMB_BIN}/smbd/smbd --version 2>/dev/null)"
else
    echo " Samba $(smbd --version 2>/dev/null)"
fi
echo "============================================"

# One-time env setup
id testuser >/dev/null 2>&1 || { useradd -M testuser 2>/dev/null || true; }
mkdir -p /srv/samba/rguard-test && chmod 0777 /srv/samba/rguard-test

# Set up smb.conf and VFS module
if [ -n "${SAMBA_VER}" ] && [ -d "${SAMBA_SRC}" ]; then
    # Source-built Samba configuration
    mkdir -p /usr/local/samba/{etc,var,private}
    cat > "${SMB_CONF}" << SMBEOF
[global]
    workgroup = SAMBA
    security = user
    passdb backend = tdbsam
    server min protocol = SMB2
[rguard-test]
    path = /srv/samba/rguard-test
    read only = No
    guest ok = Yes
    vfs objects = gfrguard
    gfrguard:protect = yes
    gfrguard:store = /var/lib/gf2000/rguard-store
    gfrguard:policy = /etc/gf2000/rguard-policy.json
    gfrguard:mode = permissive
SMBEOF
    # Install VFS module (try build-vfs-<ver> then build dirs)
    mkdir -p "${VFS_DIR}"
    VFS_SRC=""
    for d in "${PROJECT_DIR}/build-vfs-${SAMBA_VER}" "${PROJECT_DIR}/build" "${PROJECT_DIR}/build-vfs-19" "${PROJECT_DIR}/build-vfs-23"; do
        if [ -f "${d}/gfrguard.so" ]; then VFS_SRC="${d}/gfrguard.so"; break; fi
    done
    if [ -n "${VFS_SRC}" ]; then
        cp -f "${VFS_SRC}" "${VFS_DIR}/"
        echo "VFS module: ${VFS_SRC} -> ${VFS_DIR}/gfrguard.so"
        # Source builds differ: in-tree smbd loads from bin/modules, but an
        # install-configured build (e.g. 4.19.6) loads from its --prefix
        # MODULESDIR.  Ask smbd where it actually looks and install there too
        # — a stale module elsewhere silently drops every event (protocol
        # size mismatch → daemon recv 丢弃).
        MODDIR=$("${SMB_BIN}/smbd/smbd" -b 2>/dev/null | awk '/MODULESDIR/{print $2}')
        if [ -n "${MODDIR}" ] && [ "${MODDIR}/vfs" != "${VFS_DIR}" ]; then
            mkdir -p "${MODDIR}/vfs"
            cp -f "${VFS_SRC}" "${MODDIR}/vfs/"
            echo "VFS module: ${VFS_SRC} -> ${MODDIR}/vfs/gfrguard.so (MODULESDIR)"
        fi
    fi
    # Create test user
    if [ -x "${SMB_BIN}/utils/pdbedit" ]; then
        (echo testpass; echo testpass) | ${SMB_BIN}/utils/pdbedit \
            -s "${SMB_CONF}" -a testuser -t 2>/dev/null || true
    fi
    # Also set system smbpasswd for backward compat
    (echo testpass; echo testpass) | smbpasswd -a -s testuser 2>/dev/null || true
else
    # System Samba configuration
    if ! grep -q 'rguard-test' /etc/samba/smb.conf 2>/dev/null; then
        cat >> /etc/samba/smb.conf << 'SMBEOF'

[rguard-test]
	path = /srv/samba/rguard-test
	read only = No
	guest ok = Yes
	vfs objects = gfrguard
	gfrguard:protect = yes
	gfrguard:store = /var/lib/gf2000/rguard-store
	gfrguard:policy = /etc/gf2000/rguard-policy.json
	gfrguard:mode = permissive
SMBEOF
    fi
    # Install VFS module for system Samba
    VFS_SYS_DIR="/usr/lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)/samba/vfs"
    mkdir -p "${VFS_SYS_DIR}"
    cp -f "${PROJECT_DIR}/build/gfrguard.so" "${VFS_SYS_DIR}/" 2>/dev/null || true
    (echo testpass; echo testpass) | smbpasswd -a -s testuser 2>/dev/null || true
fi
setenforce 0 2>/dev/null || true

# Ensure no stale smbd from previous runs
pkill -9 smbd 2>/dev/null || true
sleep 1

# Start fresh
clean_policy && :> "$BLOCKED" && reset_files
smb_restart

# Verify smbd is running
if ! pidof smbd >/dev/null 2>&1; then
    echo "ERROR: smbd failed to start"
    exit 1
fi

kill_daemon
start_daemon
echo "Daemon PID: $(pidof gfrguardd)"
echo ""

# ================================================================
# [1] First-write backup
# ================================================================
echo -n "[1] Backup  "
clean_state && reset_files
$SMB -c 'put /etc/hostname f1.txt' 2>/dev/null
sleep $WAIT
bk=$(find ${STORE}/backups -type f 2>/dev/null | wc -l)
if [ "${bk:-0}" -ge 1 ]; then pass; else fail; dump_diag; fi

# ================================================================
# [2] YARA — resets daemon state afterwards (CRITICAL causes blacklist)
# ================================================================
echo -n "[2] YARA    "
clean_state && reset_files
$SMB -c "put ${YR_DIR}/README_LOCKBIT.txt f2.txt" 2>/dev/null
sleep $WAIT
yr=$(grep -c YARA_MATCH "$LOG" 2>/dev/null || true)
if [ "${yr:-0}" -ge 1 ]; then pass; else fail; dump_diag; fi
clean_policy && :> "$BLOCKED"
smb_restart

# ================================================================
# [3] Blocked session
# ================================================================
echo -n "[3] Blocked "
clean_policy && :> "$BLOCKED"
smb_restart
$SMB -c 'ls' 2>/dev/null >/dev/null
printf "127.0.0.1\n::1\n" > "$BLOCKED"
if $SMB -c 'ls' 2>&1 | grep -qi 'NT_STATUS'; then pass; else fail; dump_diag; fi

# ================================================================
# [4] gfrguard-recover restore
# ================================================================
echo -n "[4] Restore "
clean_state && reset_files
$SMB -c 'put /etc/hostname f4.txt' 2>/dev/null
sleep $WAIT
eid=$(sqlite3 "$DB" "SELECT event_id FROM protected_files LIMIT 1;" 2>/dev/null)
if [ -n "$eid" ] && /usr/local/bin/gfrguard-recover restore --event "$eid" 2>&1 | grep -q 'Restore complete'; then pass; else fail; dump_diag; fi

# ================================================================
# [5] Exception file
# ================================================================
echo -n "[5] ExcFile "
clean_policy && :> "$BLOCKED"
policy_with_exceptions '["f5.txt"]' '[]'
kill_daemon; start_daemon
reset_files
$SMB -c "put ${YR_DIR}/README_LOCKBIT.txt f5.txt" 2>/dev/null
sleep $WAIT
yr5=$(grep -c YARA_MATCH "$LOG" 2>/dev/null || true)
if [ "${yr5:-0}" -eq 0 ]; then pass; else fail; dump_diag; fi

# ================================================================
# [6] Exception folder
# ================================================================
echo -n "[6] ExcDir  "
mkdir -p "${SHARE_DIR}/excepted"
chmod 0777 "${SHARE_DIR}/excepted"
clean_policy && :> "$BLOCKED"
policy_with_exceptions '[]' "[\"${SHARE_DIR}/excepted\"]"
kill_daemon; start_daemon
reset_files
$SMB -c "put ${YR_DIR}/README_LOCKBIT.txt excepted/f99.txt" 2>/dev/null
sleep $WAIT
yr6=$(grep -c YARA_MATCH "$LOG" 2>/dev/null || true)
if [ "${yr6:-0}" -eq 0 ]; then pass; else fail; dump_diag; fi

# ================================================================
# [7] Sanity: non-excepted file still triggers YARA
# ================================================================
echo -n "[7] ExcSane "
clean_policy
clean_state && reset_files
$SMB -c "put ${YR_DIR}/README_LOCKBIT.txt f99.txt" 2>/dev/null
sleep $WAIT
yr7=$(grep -c YARA_MATCH "$LOG" 2>/dev/null || true)
if [ "${yr7:-0}" -ge 1 ]; then pass; else fail; dump_diag; fi
clean_policy && :> "$BLOCKED"
smb_restart

# ================================================================
# [8] Whitelist IP
# ================================================================
echo -n "[8] WlIP    "
clean_policy && :> "$BLOCKED"
cat > "$POLICY" << 'POLICYEOF'
{"store_path":"/var/lib/gf2000/rguard-store","log_path":"/var/log/gfrguard","log_level":"debug","mode":"permissive","scoring_config":"/etc/gf2000/rguard-scoring.json","ransom_extensions_config":"/etc/gf2000/ransom-extensions.json","exceptions":{"files":[],"folders":[]},"whitelist":{"users":[],"ips":["127.0.0.1"]},"blacklist":{"users":[],"ips":[]},"space":{"max_usage_percent":80,"cleanup_days":30},"auto_restore":{"enabled":false,"delay_seconds":3},"scoring":{"window_short":10,"window_long":30,"weights":{"modified":3,"rename":4,"delete":3,"dirs":5,"ext_change":5,"ransom_ext":20,"high_entropy":8,"yara_match":40},"thresholds":{"warn":30,"high":60,"critical":80},"entropy_threshold":7.0,"entropy_enabled":true,"yara_enabled":true}}
POLICYEOF
smb_restart
kill_daemon; start_daemon
reset_files
$SMB4 -c "put ${YR_DIR}/README_LOCKBIT.txt f8.txt" 2>/dev/null
sleep $WAIT
yr8=$(grep -c YARA_MATCH "$LOG" 2>/dev/null || true)
if [ "${yr8:-0}" -eq 0 ]; then pass; else fail; dump_diag; fi
clean_policy && :> "$BLOCKED"
smb_restart
kill_daemon; start_daemon

# ================================================================
# [9] Blacklist auto-add — CRITICAL → add_to_blacklist + blocker
# ================================================================
echo -n "[9] BlAuto  "
clean_state && reset_files
$SMB4 -c "put ${YR_DIR}/README_LOCKBIT.txt f9.txt" 2>/dev/null
sleep $WAIT
yr9=$(grep -c YARA_MATCH "$LOG" 2>/dev/null || true)
blk9=$(grep -c BLOCK_EXECUTED "$LOG" 2>/dev/null || true)
$SMB4 -c 'ls' 2>&1 | grep -qi 'NT_STATUS' && blk_ok=1 || blk_ok=0
if [ "${yr9:-0}" -ge 1 ] && [ "${blk9:-0}" -ge 1 ] && [ "${blk_ok:-0}" -eq 1 ]; then
    pass
else
    fail
    echo "  diag: YARA_MATCH=${yr9:-0} BLOCK_EXECUTED=${blk9:-0} ls_blocked=${blk_ok:-0}"
    dump_diag
fi
clean_policy && :> "$BLOCKED"
smb_restart

# ================================================================
# [10] Whitelist user
# ================================================================
echo -n "[10] WlUser  "
clean_policy && :> "$BLOCKED"
cat > "$POLICY" << 'POLICYEOF'
{"store_path":"/var/lib/gf2000/rguard-store","log_path":"/var/log/gfrguard","log_level":"debug","mode":"permissive","scoring_config":"/etc/gf2000/rguard-scoring.json","ransom_extensions_config":"/etc/gf2000/ransom-extensions.json","exceptions":{"files":[],"folders":[]},"whitelist":{"users":["testuser"],"ips":[]},"blacklist":{"users":[],"ips":[]},"space":{"max_usage_percent":80,"cleanup_days":30},"auto_restore":{"enabled":false,"delay_seconds":3},"scoring":{"window_short":10,"window_long":30,"weights":{"modified":3,"rename":4,"delete":3,"dirs":5,"ext_change":5,"ransom_ext":20,"high_entropy":8,"yara_match":40},"thresholds":{"warn":30,"high":60,"critical":80},"entropy_threshold":7.0,"entropy_enabled":true,"yara_enabled":true}}
POLICYEOF
kill_daemon; start_daemon
reset_files
$SMB -c "put ${YR_DIR}/README_LOCKBIT.txt f10.txt" 2>/dev/null
sleep $WAIT
yr10=$(grep -c YARA_MATCH "$LOG" 2>/dev/null || true)
if [ "${yr10:-0}" -eq 0 ]; then pass; else fail; dump_diag; fi

# ================================================================
# [11] Manual blacklist IP — VFS denies via policy JSON blacklist
# ================================================================
echo -n "[11] BlMan   "
clean_policy && :> "$BLOCKED"
cat > "$POLICY" << 'POLICYEOF'
{"store_path":"/var/lib/gf2000/rguard-store","log_path":"/var/log/gfrguard","log_level":"debug","mode":"permissive","scoring_config":"/etc/gf2000/rguard-scoring.json","ransom_extensions_config":"/etc/gf2000/ransom-extensions.json","exceptions":{"files":[],"folders":[]},"whitelist":{"users":[],"ips":[]},"blacklist":{"users":[],"ips":[{"ip":"127.0.0.1","auto_add":false}]},"space":{"max_usage_percent":80,"cleanup_days":30},"auto_restore":{"enabled":false,"delay_seconds":3},"scoring":{"window_short":10,"window_long":30,"weights":{"modified":3,"rename":4,"delete":3,"dirs":5,"ext_change":5,"ransom_ext":20,"high_entropy":8,"yara_match":40},"thresholds":{"warn":30,"high":60,"critical":80},"entropy_threshold":7.0,"entropy_enabled":true,"yara_enabled":true}}
POLICYEOF
    kill_daemon; start_daemon
smb_restart
if $SMB4 -c 'ls' 2>&1 | grep -qi 'NT_STATUS'; then pass; else fail; dump_diag; fi
clean_policy && :> "$BLOCKED"
smb_restart
kill_daemon; start_daemon

# ================================================================
# [12] Manual blacklist user — VFS denies via policy JSON blacklist
# ================================================================
echo -n "[12] BlUsr   "
clean_policy && :> "$BLOCKED"
cat > "$POLICY" << 'POLICYEOF'
{"store_path":"/var/lib/gf2000/rguard-store","log_path":"/var/log/gfrguard","log_level":"debug","mode":"permissive","scoring_config":"/etc/gf2000/rguard-scoring.json","ransom_extensions_config":"/etc/gf2000/ransom-extensions.json","exceptions":{"files":[],"folders":[]},"whitelist":{"users":[],"ips":[]},"blacklist":{"users":["testuser"],"ips":[]},"space":{"max_usage_percent":80,"cleanup_days":30},"auto_restore":{"enabled":false,"delay_seconds":3},"scoring":{"window_short":10,"window_long":30,"weights":{"modified":3,"rename":4,"delete":3,"dirs":5,"ext_change":5,"ransom_ext":20,"high_entropy":8,"yara_match":40},"thresholds":{"warn":30,"high":60,"critical":80},"entropy_threshold":7.0,"entropy_enabled":true,"yara_enabled":true}}
POLICYEOF
    kill_daemon; start_daemon
smb_restart
reset_files
# User blacklist is checked at event time by the daemon, not at VFS
# connect time.  Trigger a file operation and check for BLACKLIST_BLOCK.
$SMB -c "put /etc/hostname f12.txt" 2>/dev/null
sleep $WAIT
blk12=$(grep -c BLACKLIST_BLOCK "$LOG" 2>/dev/null || true)
if [ "${blk12:-0}" -ge 1 ]; then pass; else fail; dump_diag; fi
clean_policy && :> "$BLOCKED"
smb_restart

# ================================================================
# [13] FTP fanotify blacklist block — FAN_DENY on blacklisted IP
# ================================================================
echo -n "[13] FTP-Blk "
HAVE_PY3=false
command -v python3 >/dev/null 2>&1 && HAVE_PY3=true

if $HAVE_PY3 && $HAVE_VSFTPD; then
    clean_policy && :> "$BLOCKED"
    ftp_setup && ftp_start
    mkdir -p /srv/ftp && chmod 0777 /srv/ftp
    echo "original ftp content" > /srv/ftp/ftp_test.txt
    chmod 0666 /srv/ftp/ftp_test.txt
    printf 'YOUR FILES ARE ENCRYPTED. PAY BITCOIN TO RECOVER.' > /tmp/gf_ftp_rnote.bin
    cat > "$POLICY" << 'POLICYEOF'
{"store_path":"/var/lib/gf2000/rguard-store","log_path":"/var/log/gfrguard","log_level":"debug","mode":"permissive","scoring_config":"/etc/gf2000/rguard-scoring.json","ransom_extensions_config":"/etc/gf2000/ransom-extensions.json","protection":{"enabled":true,"smb":false,"ftp":true,"cloud_sync":false,"host":false},"monitor_path":{"ftp":["/srv/ftp"],"cloud_sync":[],"local":[]},"exceptions":{"files":[],"folders":[]},"whitelist":{"users":[],"ips":[]},"blacklist":{"users":[],"ips":[{"ip":"127.0.0.1","auto_add":false}]},"space":{"max_usage_percent":80,"cleanup_days":30},"auto_restore":{"enabled":false,"delay_seconds":3},"scoring":{"window_short":10,"window_long":30,"weights":{"modified":3,"rename":4,"delete":3,"dirs":5,"ext_change":5,"ransom_ext":20,"high_entropy":8,"yara_match":40},"thresholds":{"warn":30,"high":60,"critical":80},"entropy_threshold":7.0,"entropy_enabled":true,"yara_enabled":true}}
POLICYEOF
    kill_daemon; start_daemon
    # Real vsftpd worker: its title is "vsftpd: 127.0.0.1/testuser: STOR ..."
    # ftp_parse_cmdline() extracts IP=127.0.0.1 → blacklist match → FAN_DENY,
    # so storbinary is expected to fail.
    python3 - << 'PYEOF' 2>/dev/null
from ftplib import FTP
try:
    ftp = FTP()
    ftp.connect('127.0.0.1', 2121, timeout=10)
    ftp.login('testuser', 'testpass')
    with open('/tmp/gf_ftp_rnote.bin', 'rb') as f:
        ftp.storbinary('STOR ftp_test.txt', f)
    ftp.quit()
except Exception:
    pass  # 553/EPERM is the expected outcome of a blacklist deny
PYEOF
    sleep $WAIT
    ftp_blk=$(grep -cE "FANOTIFY_BLACKLIST_DENY|BLACKLIST_BLOCK" "$LOG" 2>/dev/null || true)
    ftp_content=$(head -c 30 /srv/ftp/ftp_test.txt 2>/dev/null || echo "MISSING")
    if [ "${ftp_blk:-0}" -ge 1 ] && echo "$ftp_content" | grep -q "original"; then
        pass
    else
        fail
        echo "  diag: BLACKLIST_BLOCK=${ftp_blk:-0} content='${ftp_content}'"
        dump_diag
    fi
    clean_policy && :> "$BLOCKED"
    kill_daemon; start_daemon
    smb_restart
    rm -f /tmp/gf_ftp_rnote.bin
else
    echo "  SKIP (python3 or vsftpd not available)"
fi

# ================================================================
# [13b] FTP-NoTitle — setproctitle_enable=NO (vsftpd default):
#       cmdline keeps the original argv, ftp_parse_cmdline() MUST fail
#       and the socket-inode + UID fallback must still resolve the
#       session (blacklist deny on 127.0.0.1).
# ================================================================
echo -n "[13b] FTP-NoTtl"
if $HAVE_PY3 && $HAVE_VSFTPD; then
    clean_policy && :> "$BLOCKED"
    ftp_start NO
    mkdir -p /srv/ftp && chmod 0777 /srv/ftp
    echo "original ftp content" > /srv/ftp/ftp_test.txt
    chmod 0666 /srv/ftp/ftp_test.txt
    printf 'YOUR FILES ARE ENCRYPTED. PAY BITCOIN TO RECOVER.' > /tmp/gf_ftp_rnote.bin
    cat > "$POLICY" << 'POLICYEOF'
{"store_path":"/var/lib/gf2000/rguard-store","log_path":"/var/log/gfrguard","log_level":"debug","mode":"permissive","scoring_config":"/etc/gf2000/rguard-scoring.json","ransom_extensions_config":"/etc/gf2000/ransom-extensions.json","protection":{"enabled":true,"smb":false,"ftp":true,"cloud_sync":false,"host":false},"monitor_path":{"ftp":["/srv/ftp"],"cloud_sync":[],"local":[]},"exceptions":{"files":[],"folders":[]},"whitelist":{"users":[],"ips":[]},"blacklist":{"users":[],"ips":[{"ip":"127.0.0.1","auto_add":false}]},"space":{"max_usage_percent":80,"cleanup_days":30},"auto_restore":{"enabled":false,"delay_seconds":3},"scoring":{"window_short":10,"window_long":30,"weights":{"modified":3,"rename":4,"delete":3,"dirs":5,"ext_change":5,"ransom_ext":20,"high_entropy":8,"yara_match":40},"thresholds":{"warn":30,"high":60,"critical":80},"entropy_threshold":7.0,"entropy_enabled":true,"yara_enabled":true}}
POLICYEOF
    kill_daemon; start_daemon
    python3 - << 'PYEOF' 2>/dev/null
from ftplib import FTP
try:
    ftp = FTP()
    ftp.connect('127.0.0.1', 2121, timeout=10)
    ftp.login('testuser', 'testpass')
    with open('/tmp/gf_ftp_rnote.bin', 'rb') as f:
        ftp.storbinary('STOR ftp_test.txt', f)
    ftp.quit()
except Exception:
    pass  # 553/EPERM is the expected outcome of a blacklist deny
PYEOF
    sleep $WAIT
    fb_blk=$(grep -cE "FANOTIFY_BLACKLIST_DENY|BLACKLIST_BLOCK" "$LOG" 2>/dev/null || true)
    fb_content=$(head -c 30 /srv/ftp/ftp_test.txt 2>/dev/null || echo "MISSING")
    # Proof the fallback (not the cmdline parser) did the resolving:
    # the logged cmdline must be the raw argv, not a "vsftpd: <ip>" title.
    fb_raw=$(grep FTP_CMDLINE_READ "$LOG" 2>/dev/null | grep -c "vsftpd-3.0.5/vsftpd" || true)
    if [ "${fb_blk:-0}" -ge 1 ] && echo "$fb_content" | grep -q "original" && [ "${fb_raw:-0}" -ge 1 ]; then
        pass
    else
        fail
        echo "  diag: BLACKLIST_BLOCK=${fb_blk:-0} raw_argv=${fb_raw:-0} content='${fb_content}'"
        dump_diag
    fi
    clean_policy && :> "$BLOCKED"
    kill_daemon; start_daemon
    smb_restart
    ftp_start   # back to setproctitle_enable=YES for the remaining FTP tests
    rm -f /tmp/gf_ftp_rnote.bin
else
    echo "  SKIP (python3 or vsftpd not available)"
fi

# ================================================================
# [14] LOCAL fanotify blacklist block — FAN_DENY + SIGKILL
# ================================================================
echo -n "[14] LocalBlk"
if $HAVE_PY3; then
    clean_policy && :> "$BLOCKED"
    LOCAL_DIR="/tmp/gfrguard-local-test"
    mkdir -p "$LOCAL_DIR" && chmod 0777 "$LOCAL_DIR"
    echo "original local content" > "${LOCAL_DIR}/local_test.txt"
    cat > "$POLICY" << 'POLICYEOF'
{"store_path":"/var/lib/gf2000/rguard-store","log_path":"/var/log/gfrguard","log_level":"debug","mode":"permissive","scoring_config":"/etc/gf2000/rguard-scoring.json","ransom_extensions_config":"/etc/gf2000/ransom-extensions.json","protection":{"enabled":true,"smb":false,"ftp":false,"cloud_sync":false,"host":true},"monitor_path":{"ftp":[],"cloud_sync":[],"local":["/tmp/gfrguard-local-test"]},"exceptions":{"files":[],"folders":[]},"whitelist":{"users":[],"ips":[]},"blacklist":{"users":["python3"],"ips":[]},"space":{"max_usage_percent":80,"cleanup_days":30},"auto_restore":{"enabled":false,"delay_seconds":3},"scoring":{"window_short":10,"window_long":30,"weights":{"modified":3,"rename":4,"delete":3,"dirs":5,"ext_change":5,"ransom_ext":20,"high_entropy":8,"yara_match":40},"thresholds":{"warn":30,"high":60,"critical":80},"entropy_threshold":7.0,"entropy_enabled":true,"yara_enabled":true}}
POLICYEOF
    kill_daemon; start_daemon
    # python3 is NOT in the built-in whitelist; blacklist user "python3"
    # causes scorer_is_blacklisted() → true → block + SIGKILL + FAN_DENY
    python3 -c "
import os, sys
try:
    f = open('${LOCAL_DIR}/local_test.txt', 'w')
    f.write('SHOULD BE BLOCKED BY FANOTIFY')
    f.close()
    sys.exit(0)
except (PermissionError, OSError):
    sys.exit(1)
" 2>/dev/null &
    PY_PID=$!
    for i in $(seq 1 10); do
        if ! kill -0 "$PY_PID" 2>/dev/null; then break; fi
        sleep 0.5
    done
    kill -9 "$PY_PID" 2>/dev/null || true
    wait "$PY_PID" 2>/dev/null || true
    sleep $WAIT
    local_content=$(head -c 30 "${LOCAL_DIR}/local_test.txt" 2>/dev/null || echo "MISSING")
    local_content=$(head -c 30 "${LOCAL_DIR}/local_test.txt" 2>/dev/null || echo "MISSING")
    if echo "$local_content" | grep -q "original"; then
        pass
    else
        fail
        echo "  diag: content='${local_content}'"
        dump_diag
    fi
    clean_policy && :> "$BLOCKED"
    smb_restart
    kill_daemon; start_daemon
    rm -rf "$LOCAL_DIR" 2>/dev/null || true
else
    echo "  SKIP (python3 not available)"
fi

if $HAVE_PY3; then
    # ================================================================
    # [15] FTP fanotify YARA — write ransom note → CLOSE_WRITE → YARA scan → CRITICAL
    # ================================================================
    echo -n "[15] FTP-YARA"
    if ! $HAVE_VSFTPD; then
        echo "  SKIP (vsftpd not available)"
    else
    clean_policy && :> "$BLOCKED"
    mkdir -p /srv/ftp && chmod 0777 /srv/ftp
    echo "original ftp yara content" > /srv/ftp/ftp_yara_test.txt
    chmod 0666 /srv/ftp/ftp_yara_test.txt
    cat > "$POLICY" << 'POLICYEOF'
{"store_path":"/var/lib/gf2000/rguard-store","log_path":"/var/log/gfrguard","log_level":"debug","mode":"permissive","scoring_config":"/etc/gf2000/rguard-scoring.json","ransom_extensions_config":"/etc/gf2000/ransom-extensions.json","protection":{"enabled":true,"smb":false,"ftp":true,"cloud_sync":false,"host":false},"monitor_path":{"ftp":["/srv/ftp"],"cloud_sync":[],"local":[]},"exceptions":{"files":[],"folders":[]},"whitelist":{"users":[],"ips":[]},"blacklist":{"users":[],"ips":[]},"space":{"max_usage_percent":80,"cleanup_days":30},"auto_restore":{"enabled":false,"delay_seconds":3},"scoring":{"window_short":10,"window_long":30,"weights":{"modified":3,"rename":4,"delete":3,"dirs":5,"ext_change":5,"ransom_ext":20,"high_entropy":8,"yara_match":40},"thresholds":{"warn":30,"high":60,"critical":80},"entropy_threshold":7.0,"entropy_enabled":true,"yara_enabled":true}}
POLICYEOF
    kill_daemon; start_daemon
    # Real vsftpd worker uploads the ransom note:
    # open → FAN_OPEN_PERM → backup → ALLOW
    # write + close → FAN_CLOSE_WRITE → YARA scan → CRITICAL → block
    python3 - << PYEOF 2>/dev/null
from ftplib import FTP
try:
    ftp = FTP()
    ftp.connect('127.0.0.1', 2121, timeout=10)
    ftp.login('testuser', 'testpass')
    with open("$YR_DIR/README_LOCKBIT.txt", 'rb') as f:
        ftp.storbinary('STOR ftp_yara_test.txt', f)
    ftp.quit()
except Exception:
    pass
PYEOF
    sleep $WAIT
    # YARA scan runs in CLOSE_WRITE handler, may take extra time
    sleep 4
    yr15=$(grep -c YARA_MATCH "$LOG" 2>/dev/null || true)
    blk15=$(grep -c BLOCK_EXECUTED "$LOG" 2>/dev/null || true)
    if [ "${yr15:-0}" -ge 1 ]; then pass; else fail; dump_diag; fi
    clean_policy && :> "$BLOCKED"
    kill_daemon; start_daemon
    smb_restart
    rm -rf /srv/ftp 2>/dev/null || true
    fi

    # ================================================================
    # [16] LOCAL fanotify YARA — write ransom note → CLOSE_WRITE → YARA scan → CRITICAL
    # ================================================================
    echo -n "[16] LocalYAR"
    clean_policy && :> "$BLOCKED"
    YR_LOCAL_DIR="/tmp/gfrguard-local-yara"
    mkdir -p "$YR_LOCAL_DIR" && chmod 0777 "$YR_LOCAL_DIR"
    echo "original local yara content" > "${YR_LOCAL_DIR}/local_yara_test.txt"
    cat > "$POLICY" << 'POLICYEOF'
{"store_path":"/var/lib/gf2000/rguard-store","log_path":"/var/log/gfrguard","log_level":"debug","mode":"permissive","scoring_config":"/etc/gf2000/rguard-scoring.json","ransom_extensions_config":"/etc/gf2000/ransom-extensions.json","protection":{"enabled":true,"smb":false,"ftp":false,"cloud_sync":false,"host":true},"monitor_path":{"ftp":[],"cloud_sync":[],"local":["/tmp/gfrguard-local-yara"]},"exceptions":{"files":[],"folders":[]},"whitelist":{"users":[],"ips":[]},"blacklist":{"users":[],"ips":[]},"space":{"max_usage_percent":80,"cleanup_days":30},"auto_restore":{"enabled":false,"delay_seconds":3},"scoring":{"window_short":10,"window_long":30,"weights":{"modified":3,"rename":4,"delete":3,"dirs":5,"ext_change":5,"ransom_ext":20,"high_entropy":8,"yara_match":40},"thresholds":{"warn":30,"high":60,"critical":80},"entropy_threshold":7.0,"entropy_enabled":true,"yara_enabled":true}}
POLICYEOF
    kill_daemon; start_daemon
    # python3 not whitelisted → handler accepts event
    # open → FAN_OPEN_PERM → backup → ALLOW
    # write + close → FAN_CLOSE_WRITE → YARA → CRITICAL → SIGKILL
    python3 -c "
import shutil, sys
try:
    shutil.copy('${YR_DIR}/README_LOCKBIT.txt', '${YR_LOCAL_DIR}/local_yara_test.txt')
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null &
    YPID=$!
    for i in $(seq 1 10); do
        if ! kill -0 "$YPID" 2>/dev/null; then break; fi
        sleep 0.5
    done
    kill -9 "$YPID" 2>/dev/null || true
    wait "$YPID" 2>/dev/null || true
    sleep $WAIT
    sleep 4  # YARA scan
    yr16=$(grep -c YARA_MATCH "$LOG" 2>/dev/null || true)
    blk16=$(grep -c BLOCK_EXECUTED "$LOG" 2>/dev/null || true)
    if [ "${yr16:-0}" -ge 1 ]; then pass; else fail; dump_diag; fi
    clean_policy && :> "$BLOCKED"
    smb_restart
    kill_daemon; start_daemon
    rm -rf "$YR_LOCAL_DIR" 2>/dev/null || true

    # ================================================================
    # [17] FTP fanotify entropy — write random data → CLOSE_WRITE → HIGH_ENTROPY
    # ================================================================
    echo -n "[17] FTP-Ent "
    if ! $HAVE_VSFTPD; then
        echo "  SKIP (vsftpd not available)"
    else
    clean_policy && :> "$BLOCKED"
    mkdir -p /srv/ftp && chmod 0777 /srv/ftp
    dd if=/dev/urandom of=/tmp/gf_ftp_ent.bin bs=1024 count=16 2>/dev/null
    for i in 1 2 3; do
        echo "original $i" > "/srv/ftp/ftp_ent_${i}.txt"
        chmod 0666 "/srv/ftp/ftp_ent_${i}.txt"
    done
    cat > "$POLICY" << 'POLICYEOF'
{"store_path":"/var/lib/gf2000/rguard-store","log_path":"/var/log/gfrguard","log_level":"debug","mode":"permissive","scoring_config":"/etc/gf2000/rguard-scoring.json","ransom_extensions_config":"/etc/gf2000/ransom-extensions.json","protection":{"enabled":true,"smb":false,"ftp":true,"cloud_sync":false,"host":false},"monitor_path":{"ftp":["/srv/ftp"],"cloud_sync":[],"local":[]},"exceptions":{"files":[],"folders":[]},"whitelist":{"users":[],"ips":[]},"blacklist":{"users":[],"ips":[]},"space":{"max_usage_percent":80,"cleanup_days":30},"auto_restore":{"enabled":false,"delay_seconds":3},"scoring":{"window_short":10,"window_long":30,"weights":{"modified":3,"rename":4,"delete":3,"dirs":5,"ext_change":5,"ransom_ext":20,"high_entropy":8,"yara_match":40},"thresholds":{"warn":30,"high":60,"critical":80},"entropy_threshold":7.0,"entropy_enabled":true,"yara_enabled":true}}
POLICYEOF
    kill_daemon; start_daemon
    # Upload 3 high-entropy files in ONE FTP session (same vsftpd worker
    # process → shared session, accumulated score)
    python3 - << 'PYEOF' 2>/dev/null
from ftplib import FTP
try:
    ftp = FTP()
    ftp.connect('127.0.0.1', 2121, timeout=10)
    ftp.login('testuser', 'testpass')
    for i in range(1, 4):
        with open('/tmp/gf_ftp_ent.bin', 'rb') as f:
            ftp.storbinary(f'STOR ftp_ent_{i}.txt', f)
    ftp.quit()
except Exception:
    pass
PYEOF
    sleep $WAIT
    sleep 3  # entropy checks on CLOSE_WRITE
    ent17=$(grep -c HIGH_ENTROPY "$LOG" 2>/dev/null || true)
    if [ "${ent17:-0}" -ge 1 ]; then pass; else fail; dump_diag; fi
    clean_policy && :> "$BLOCKED"
    kill_daemon; start_daemon
    smb_restart
    rm -rf /srv/ftp /tmp/gf_ftp_ent.bin 2>/dev/null || true
    fi

    # ================================================================
    # [18] LOCAL fanotify entropy — write random data → CLOSE_WRITE → HIGH_ENTROPY
    # ================================================================
    echo -n "[18] LocalEnt"
    clean_policy && :> "$BLOCKED"
    ENT_LOCAL_DIR="/tmp/gfrguard-local-entropy"
    mkdir -p "$ENT_LOCAL_DIR" && chmod 0777 "$ENT_LOCAL_DIR"
    dd if=/dev/urandom of=/tmp/gf_local_ent.bin bs=1024 count=16 2>/dev/null
    cat > "$POLICY" << 'POLICYEOF'
{"store_path":"/var/lib/gf2000/rguard-store","log_path":"/var/log/gfrguard","log_level":"debug","mode":"permissive","scoring_config":"/etc/gf2000/rguard-scoring.json","ransom_extensions_config":"/etc/gf2000/ransom-extensions.json","protection":{"enabled":true,"smb":false,"ftp":false,"cloud_sync":false,"host":true},"monitor_path":{"ftp":[],"cloud_sync":[],"local":["/tmp/gfrguard-local-entropy"]},"exceptions":{"files":[],"folders":[]},"whitelist":{"users":[],"ips":[]},"blacklist":{"users":[],"ips":[]},"space":{"max_usage_percent":80,"cleanup_days":30},"auto_restore":{"enabled":false,"delay_seconds":3},"scoring":{"window_short":10,"window_long":30,"weights":{"modified":3,"rename":4,"delete":3,"dirs":5,"ext_change":5,"ransom_ext":20,"high_entropy":8,"yara_match":40},"thresholds":{"warn":30,"high":60,"critical":80},"entropy_threshold":7.0,"entropy_enabled":true,"yara_enabled":true}}
POLICYEOF
    kill_daemon; start_daemon
    # Write 3 high-entropy files from single python3 process
    python3 -c "
import shutil, sys, os
for i in range(1, 4):
    dest = f'${ENT_LOCAL_DIR}/local_ent_{i}.txt'
    with open(dest, 'w') as f:
        f.write(f'original {i}')
    shutil.copy('/tmp/gf_local_ent.bin', dest)
sys.exit(0)
" 2>/dev/null &
    EPID=$!
    for i in $(seq 1 10); do
        if ! kill -0 "$EPID" 2>/dev/null; then break; fi
        sleep 0.5
    done
    kill -9 "$EPID" 2>/dev/null || true
    wait "$EPID" 2>/dev/null || true
    sleep $WAIT
    sleep 3  # entropy checks
    ent18=$(grep -c HIGH_ENTROPY "$LOG" 2>/dev/null || true)
    if [ "${ent18:-0}" -ge 1 ]; then pass; else fail; dump_diag; fi
    clean_policy && :> "$BLOCKED"
    smb_restart
    kill_daemon; start_daemon
    rm -rf "$ENT_LOCAL_DIR" /tmp/gf_local_ent.bin 2>/dev/null || true
fi

if $HAVE_PY3; then
    # ================================================================
    # FID notify pipeline tests [19]-[24] — recursive marks, MODIFY,
    # CREATE/mkdir, DELETE, FAN_RENAME, flood gate.
    # Local channel; python3 is not whitelisted.  Files are pre-created
    # BEFORE the daemon starts (no stray events from bash/coreutils).
    # ================================================================
    FID_DIR="/tmp/gfrguard-local-fid"

    fid_policy() {
        cat > "$POLICY" << 'POLICYEOF'
{"store_path":"/var/lib/gf2000/rguard-store","log_path":"/var/log/gfrguard","log_level":"debug","mode":"permissive","scoring_config":"/etc/gf2000/rguard-scoring.json","ransom_extensions_config":"/etc/gf2000/ransom-extensions.json","protection":{"enabled":true,"smb":false,"ftp":false,"cloud_sync":false,"host":true},"monitor_path":{"ftp":[],"cloud_sync":[],"local":["/tmp/gfrguard-local-fid"]},"exceptions":{"files":[],"folders":[]},"whitelist":{"users":[],"ips":[]},"blacklist":{"users":[],"ips":[]},"space":{"max_usage_percent":80,"cleanup_days":30},"auto_restore":{"enabled":false,"delay_seconds":3},"scoring":{"window_short":10,"window_long":30,"weights":{"modified":3,"rename":4,"delete":3,"dirs":5,"ext_change":5,"ransom_ext":20,"high_entropy":8,"yara_match":40},"thresholds":{"warn":30,"high":60,"critical":80},"entropy_threshold":7.0,"entropy_enabled":true,"yara_enabled":true}}
POLICYEOF
    }

    fid_blacklist_policy() {
        cat > "$POLICY" << 'POLICYEOF'
{"store_path":"/var/lib/gf2000/rguard-store","log_path":"/var/log/gfrguard","log_level":"debug","mode":"permissive","scoring_config":"/etc/gf2000/rguard-scoring.json","ransom_extensions_config":"/etc/gf2000/ransom-extensions.json","protection":{"enabled":true,"smb":false,"ftp":false,"cloud_sync":false,"host":true},"monitor_path":{"ftp":[],"cloud_sync":[],"local":["/tmp/gfrguard-local-fid"]},"exceptions":{"files":[],"folders":[]},"whitelist":{"users":[],"ips":[]},"blacklist":{"users":["python3"],"ips":[]},"space":{"max_usage_percent":80,"cleanup_days":30},"auto_restore":{"enabled":false,"delay_seconds":3},"scoring":{"window_short":10,"window_long":30,"weights":{"modified":3,"rename":4,"delete":3,"dirs":5,"ext_change":5,"ransom_ext":20,"high_entropy":8,"yara_match":40},"thresholds":{"warn":30,"high":60,"critical":80},"entropy_threshold":7.0,"entropy_enabled":true,"yara_enabled":true}}
POLICYEOF
    }

    fid_reset() {
        rm -rf "$FID_DIR"
        mkdir -p "$FID_DIR/a/b/c" && chmod -R 0777 "$FID_DIR"
        echo "original deep" > "$FID_DIR/a/b/c/deep.txt"
        for i in 1 2 3; do echo "original $i" > "$FID_DIR/a/f${i}.txt"; done
        :> "$BLOCKED"
    }

    # ================================================================
    # [19] SubdirBlk — blacklist deny works 3 levels deep (recursive marks)
    # ================================================================
    echo -n "[19] SubdirBlk"
    fid_blacklist_policy; fid_reset
    kill_daemon; start_daemon
    timeout 5 python3 -c "
open('${FID_DIR}/a/b/c/deep.txt','w').write('SHOULD BE BLOCKED')
" 2>/dev/null
    sleep $WAIT
    c19=$(head -c 13 "$FID_DIR/a/b/c/deep.txt" 2>/dev/null || echo "MISSING")
    if [ "$c19" = "original deep" ]; then pass; else fail; echo "  diag: content='$c19'"; dump_diag; fi

    # ================================================================
    # [20] SubWrite — path-truncate in subdir surfaces OP_WRITE (FAN_MODIFY)
    # ================================================================
    echo -n "[20] SubWrite "
    fid_policy; fid_reset
    kill_daemon; start_daemon
    timeout 5 python3 -c "
import os
os.truncate('${FID_DIR}/a/b/c/deep.txt', 4)      # no open: MODIFY only
open('${FID_DIR}/a/f1.txt','w').write('overwrite')  # open path: OPEN+CLOSE
" 2>/dev/null
    sleep $WAIT
    w20=$(grep MSG_RECV "$LOG" | grep -c '"op":2' || true)
    cl20=$(grep MSG_RECV "$LOG" | grep -c '"op":6' || true)
    b20=$(grep -c BLOCK_EXECUTED "$LOG" 2>/dev/null || true)
    if [ "${w20:-0}" -ge 1 ] && [ "${cl20:-0}" -ge 1 ] && [ "${b20:-0}" -eq 0 ]; then
        pass
    else
        fail; echo "  diag: op2=$w20 op6=$cl20 blocks=$b20"; dump_diag
    fi

    # ================================================================
    # [21] Mkdir — NEW_FILE event + dynamic mark covers the new dir
    # ================================================================
    echo -n "[21] Mkdir    "
    fid_policy; fid_reset
    kill_daemon; start_daemon
    timeout 5 python3 -c "
import os, time
os.mkdir('${FID_DIR}/a/newdir')
time.sleep(0.5)
open('${FID_DIR}/a/newdir/inner.txt','w').write('inner')
" 2>/dev/null
    sleep $WAIT
    mk21=$(grep MSG_RECV "$LOG" | grep '"op":1' | grep newdir | grep -c '0x0010' || true)
    in21=$(grep MSG_RECV "$LOG" | grep -c 'newdir/inner.txt' || true)
    if [ "${mk21:-0}" -ge 1 ] && [ "${in21:-0}" -ge 1 ]; then
        pass
    else
        fail; echo "  diag: mkdir_ev=$mk21 inner_ev=$in21"; dump_diag
    fi

    # ================================================================
    # [22] SubDelete — OP_DELETE events; delete-only session never blocks
    # ================================================================
    echo -n "[22] SubDelete"
    fid_policy; fid_reset
    kill_daemon; start_daemon
    timeout 5 python3 -c "
import os
for i in (1, 2, 3):
    os.remove(f'${FID_DIR}/a/f{i}.txt')
" 2>/dev/null
    sleep $WAIT
    d22=$(grep MSG_RECV "$LOG" | grep -c '"op":5' || true)
    b22=$(grep -c BLOCK_EXECUTED "$LOG" 2>/dev/null || true)
    if [ "${d22:-0}" -ge 3 ] && [ "${b22:-0}" -eq 0 ]; then
        pass
    else
        fail; echo "  diag: op5=$d22 blocks=$b22"; dump_diag
    fi

    # ================================================================
    # [23] RansomMv — FAN_RENAME carries new_name and daemon-side
    #      RANSOM_EXT scoring escalates
    # ================================================================
    echo -n "[23] RansomMv "
    fid_policy; fid_reset
    kill_daemon; start_daemon
    timeout 5 python3 -c "
import os
os.rename('${FID_DIR}/a/f1.txt', '${FID_DIR}/a/f1.locked')
os.rename('${FID_DIR}/a/f2.txt', '${FID_DIR}/a/f2.locked')
" 2>/dev/null
    sleep $WAIT
    rn23=$(grep MSG_RECV "$LOG" | grep '"op":4' | grep -c '"new_name":"f[12].locked"' || true)
    esc23=$(grep -c SCORE_ESCALATION "$LOG" 2>/dev/null || true)
    if [ "${rn23:-0}" -ge 2 ] && [ "${esc23:-0}" -ge 1 ]; then
        pass
    else
        fail; echo "  diag: renames=$rn23 escalations=$esc23"; dump_diag
    fi

    # ================================================================
    # [24] FloodGate — 100 rewrites of one file must NOT block the session
    # ================================================================
    echo -n "[24] FloodGate"
    fid_policy; fid_reset
    kill_daemon; start_daemon
    timeout 20 python3 -c "
for i in range(100):
    open('${FID_DIR}/a/f1.txt','w').write(f'iteration {i}')
" 2>/dev/null
    sleep $WAIT
    b24=$(grep -c BLOCK_EXECUTED "$LOG" 2>/dev/null || true)
    r24=$(grep RISK_HIT "$LOG" 2>/dev/null | grep -c 'f1.txt' || true)
    c24=$(head -c 9 "$FID_DIR/a/f1.txt" 2>/dev/null || echo "MISSING")
    if [ "${b24:-0}" -eq 0 ] && [ "${r24:-0}" -le 3 ] && [ "$c24" = "iteration" ]; then
        pass
    else
        fail; echo "  diag: blocks=$b24 risk_hits=$r24 content='$c24'"; dump_diag
    fi

    clean_policy && :> "$BLOCKED"
    kill_daemon; start_daemon
    smb_restart
    rm -rf "$FID_DIR" 2>/dev/null || true
fi

if $HAVE_PY3; then
    # ================================================================
    # [25] SighupMark — SIGHUP 切换监控路径后新路径立即生效（重新打 mark）
    # ================================================================
    echo -n "[25] SighupMark"
    RM_DIR_A="/tmp/gfrguard-remark-a"; RM_DIR_B="/tmp/gfrguard-remark-b"
    rm -rf "$RM_DIR_A" "$RM_DIR_B"
    mkdir -p "$RM_DIR_A" "$RM_DIR_B/sub" && chmod -R 0777 "$RM_DIR_A" "$RM_DIR_B"
    echo "original b" > "$RM_DIR_B/sub/target.txt"
    :> "$BLOCKED"
    cat > "$POLICY" << 'POLICYEOF'
{"store_path":"/var/lib/gf2000/rguard-store","log_path":"/var/log/gfrguard","log_level":"debug","mode":"permissive","scoring_config":"/etc/gf2000/rguard-scoring.json","ransom_extensions_config":"/etc/gf2000/ransom-extensions.json","protection":{"enabled":true,"smb":false,"ftp":false,"cloud_sync":false,"host":true},"monitor_path":{"ftp":[],"cloud_sync":[],"local":["/tmp/gfrguard-remark-a"]},"exceptions":{"files":[],"folders":[]},"whitelist":{"users":[],"ips":[]},"blacklist":{"users":[],"ips":[]},"space":{"max_usage_percent":80,"cleanup_days":30},"auto_restore":{"enabled":false,"delay_seconds":3},"scoring":{"window_short":10,"window_long":30,"weights":{"modified":3,"rename":4,"delete":3,"dirs":5,"ext_change":5,"ransom_ext":20,"high_entropy":8,"yara_match":40},"thresholds":{"warn":30,"high":60,"critical":80},"entropy_threshold":7.0,"entropy_enabled":true,"yara_enabled":true}}
POLICYEOF
    kill_daemon; start_daemon
    # 切换监控路径 A → B，SIGHUP 热重载
    sed -i 's|gfrguard-remark-a|gfrguard-remark-b|' "$POLICY"
    kill -HUP "$(pidof gfrguardd)" 2>/dev/null
    sleep 2
    rl25=$(grep -c FANOTIFY_MARKS_RELOADED "$LOG" 2>/dev/null || true)
    timeout 5 python3 -c "
open('${RM_DIR_B}/sub/target.txt','w').write('hot reload works')
" 2>/dev/null
    sleep $WAIT
    ev25=$(grep MSG_RECV "$LOG" | grep -c 'gfrguard-remark-b' || true)
    if [ "${rl25:-0}" -ge 1 ] && [ "${ev25:-0}" -ge 1 ]; then
        pass
    else
        fail; echo "  diag: reloaded=$rl25 events_b=$ev25"; dump_diag
    fi
    rm -rf "$RM_DIR_A" "$RM_DIR_B" 2>/dev/null || true

    # ================================================================
    # [26] CloudYARA — 云通道 notify：伪 rclone 写赎金信 → CLOSE_WRITE →
    #      YARA → CRITICAL → CLOUD_BLOCK_EXECUTED
    # ================================================================
    echo -n "[26] CloudYARA"
    CL_DIR="/tmp/gfrguard-cloud-fid"
    rm -rf "$CL_DIR"; mkdir -p "$CL_DIR" && chmod 0777 "$CL_DIR"
    echo "original cloud" > "$CL_DIR/synced.txt"
    :> "$BLOCKED"
    cat > "$POLICY" << 'POLICYEOF'
{"store_path":"/var/lib/gf2000/rguard-store","log_path":"/var/log/gfrguard","log_level":"debug","mode":"permissive","scoring_config":"/etc/gf2000/rguard-scoring.json","ransom_extensions_config":"/etc/gf2000/ransom-extensions.json","protection":{"enabled":true,"smb":false,"ftp":false,"cloud_sync":true,"host":false},"monitor_path":{"ftp":[],"cloud_sync":["/tmp/gfrguard-cloud-fid"],"local":[]},"exceptions":{"files":[],"folders":[]},"whitelist":{"users":[],"ips":[]},"blacklist":{"users":[],"ips":[]},"space":{"max_usage_percent":80,"cleanup_days":30},"auto_restore":{"enabled":false,"delay_seconds":3},"scoring":{"window_short":10,"window_long":30,"weights":{"modified":3,"rename":4,"delete":3,"dirs":5,"ext_change":5,"ransom_ext":20,"high_entropy":8,"yara_match":40},"thresholds":{"warn":30,"high":60,"critical":80},"entropy_threshold":7.0,"entropy_enabled":true,"yara_enabled":true}}
POLICYEOF
    kill_daemon; start_daemon
    # exec -a rclone → cmdline 含 "rclone"；末位参数 "onedrive_1:backup"
    # 提供 remote:path 形态 → task_name=onedrive_1（脚本内不得出现冒号）
    bash -c '
    exec -a rclone python3 -c "
import shutil, sys
shutil.copy(sys.argv[2], \"'"$CL_DIR"'/synced.txt\")
" dummy "'"$YR_DIR"'/README_LOCKBIT.txt" "onedrive_1:backup" 2>/dev/null
    ' 2>/dev/null
    sleep $WAIT
    sleep 4  # YARA scan on CLOSE_WRITE
    yr26=$(grep -c YARA_MATCH "$LOG" 2>/dev/null || true)
    cb26=$(grep -c CLOUD_BLOCK_EXECUTED "$LOG" 2>/dev/null || true)
    if [ "${yr26:-0}" -ge 1 ] && [ "${cb26:-0}" -ge 1 ]; then
        pass
    else
        fail; echo "  diag: yara=$yr26 cloud_block=$cb26"; dump_diag
    fi
    clean_policy && :> "$BLOCKED"
    kill_daemon; start_daemon
    smb_restart
    rm -rf "$CL_DIR" 2>/dev/null || true

    # ================================================================
    # [27] CloudDrip — 慢速同步攻击：5s 间隔滴入 .locked 文件。
    #      10s 全局窗口下永远攒不够分；60s 云窗口 + NEW_FILE 勒索后缀
    #      计分（20/个）→ 第 4 个文件触发 CRITICAL → CLOUD_BLOCK。
    #      内容为低熵纯文本：不靠 YARA/熵，纯行为评分验证。
    # ================================================================
    echo -n "[27] CloudDrip"
    CD_DIR="/tmp/gfrguard-cloud-drip"
    rm -rf "$CD_DIR"; mkdir -p "$CD_DIR" && chmod 0777 "$CD_DIR"
    :> "$BLOCKED"
    cat > "$POLICY" << 'POLICYEOF'
{"store_path":"/var/lib/gf2000/rguard-store","log_path":"/var/log/gfrguard","log_level":"debug","mode":"permissive","scoring_config":"/etc/gf2000/rguard-scoring.json","ransom_extensions_config":"/etc/gf2000/ransom-extensions.json","protection":{"enabled":true,"smb":false,"ftp":false,"cloud_sync":true,"host":false},"monitor_path":{"ftp":[],"cloud_sync":["/tmp/gfrguard-cloud-drip"],"local":[]},"exceptions":{"files":[],"folders":[]},"whitelist":{"users":[],"ips":[]},"blacklist":{"users":[],"ips":[]},"space":{"max_usage_percent":80,"cleanup_days":30},"auto_restore":{"enabled":false,"delay_seconds":3},"scoring":{"window_short":10,"window_long":30,"cloud_sync":{"window_short":60,"window_long":180},"weights":{"modified":3,"rename":4,"delete":3,"dirs":5,"ext_change":5,"ransom_ext":20,"high_entropy":8,"yara_match":40},"thresholds":{"warn":30,"high":60,"critical":80},"entropy_threshold":7.0,"entropy_enabled":true,"yara_enabled":true}}
POLICYEOF
    # 脚本落盘（python 循环含冒号，内联 -c 会被 rclone cmdline 解析
    # 误当 remote:path —— 用脚本文件规避）
    cat > /tmp/gf_drip.py << 'PYEOF'
import time
for i in range(5):
    with open(f"/tmp/gfrguard-cloud-drip/doc{i}.locked", "w") as fh:
        fh.write(f"plain text drip {i}")
    time.sleep(5)
PYEOF
    kill_daemon; start_daemon
    bash -c 'exec -a rclone python3 /tmp/gf_drip.py "drip_task:backup"' 2>/dev/null
    sleep $WAIT
    cb27=$(grep -c CLOUD_BLOCK_EXECUTED "$LOG" 2>/dev/null || true)
    yr27=$(grep -c YARA_MATCH "$LOG" 2>/dev/null || true)
    if [ "${cb27:-0}" -ge 1 ] && [ "${yr27:-0}" -eq 0 ]; then
        pass
    else
        fail; echo "  diag: cloud_block=$cb27 yara=$yr27（yara 应为 0，纯行为评分）"; dump_diag
    fi
    clean_policy && :> "$BLOCKED"
    kill_daemon; start_daemon
    smb_restart
    rm -rf "$CD_DIR" /tmp/gf_drip.py 2>/dev/null || true
fi

echo ""
# ftp_stop
# rm -rf /srv/ftp "$VSFTPD_CONF" 2>/dev/null || true
echo "============================================"
echo " Results: $PASS passed, $FAIL failed"
echo "============================================"
exit $((FAIL > 0 ? 1 : 0))
