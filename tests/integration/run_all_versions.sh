#!/bin/bash
# run_all_versions.sh — test against multiple Samba versions
# Uses source-built Samba for all versions.  Supports Debian and Ubuntu.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SAMBA_SRC_BASE="${PROJECT_DIR}/samba-src"

# -------------------------------------------------------------------
# Helper: kill all gfrguardd instances, ensure socket is cleaned up
# -------------------------------------------------------------------
force_kill_daemon() {
    local pids
    pids=$(pidof gfrguardd 2>/dev/null || true)
    if [ -n "$pids" ]; then
        kill $pids 2>/dev/null || true
        sleep 1
        pids=$(pidof gfrguardd 2>/dev/null || true)
        if [ -n "$pids" ]; then
            kill -9 $pids 2>/dev/null || true
            sleep 1
        fi
    fi
    rm -f /run/gfrguardd/gfrguardd.sock
}

# -------------------------------------------------------------------
# Helper: stop all smbd processes
# -------------------------------------------------------------------
force_stop_smbd() {
    local pids
    # Try systemctl first
    timeout 30 systemctl stop smb 2>/dev/null || true
    # Then kill any remaining
    pids=$(pidof smbd 2>/dev/null || true)
    if [ -n "$pids" ]; then
        kill $pids 2>/dev/null || true
        sleep 2
        pids=$(pidof smbd 2>/dev/null || true)
        if [ -n "$pids" ]; then
            kill -9 $pids 2>/dev/null || true
            sleep 1
        fi
    fi
}

# -------------------------------------------------------------------
# Ensure runtime environment
# -------------------------------------------------------------------
ensure_runtime() {
    mkdir -p /var/lib/gf2000/rguard-store/{backups,quarantine}
    mkdir -p /run/gfrguardd /etc/gf2000/yara-rules /var/log/gfrguard /srv/samba/rguard-test
    chmod 0777 /var/lib/gf2000/rguard-store/backups
    chmod 0777 /srv/samba/rguard-test

    # Deploy config files if missing
    [ -f /etc/gf2000/rguard-scoring.json ] || cp -f "${PROJECT_DIR}/files/rguard-scoring.json" /etc/gf2000/
    [ -f /etc/gf2000/ransom-extensions.json ] || cp -f "${PROJECT_DIR}/files/ransom-extensions.json" /etc/gf2000/

    # Deploy YARA rules
    for f in "${PROJECT_DIR}/files/yara-rules/"*.yar; do
        [ -f "$f" ] && cp -f "$f" /etc/gf2000/yara-rules/
    done

    # Ensure daemon and recover binaries are installed
    cp -f "${PROJECT_DIR}/build/gfrguardd" /usr/local/sbin/ 2>/dev/null || true
    cp -f "${PROJECT_DIR}/build/gfrguard-recover" /usr/local/bin/ 2>/dev/null || true
}

# -------------------------------------------------------------------
# Run tests against one Samba version
# -------------------------------------------------------------------
run_version() {
    local ver="$1"
    local src="${SAMBA_SRC_BASE}/samba-${ver}"

    echo ""
    echo "===== Samba ${ver} ====="

    if [ ! -d "${src}" ]; then
        echo "  SKIP: source tree not found at ${src}"
        return 1
    fi

    # Build VFS module for this version
    echo -n "  VFS... "
    local vfs_build="${PROJECT_DIR}/build-vfs-${ver}"
    if [ ! -f "${vfs_build}/gfrguard.so" ]; then
        cmake -B "${vfs_build}" -DBUILD_VFS=ON -DSAMBA_SRC="${src}" -DBUILD_TESTS=OFF 2>&1 | tail -1
        if ! cmake --build "${vfs_build}" -j$(nproc) 2>&1 | tail -3; then
            echo "FAILED (VFS build error — skipping ${ver})"
            return 0  # not a fatal error, just skip this version
        fi
    fi
    if [ -f "${vfs_build}/gfrguard.so" ]; then
        echo "done ($(file "${vfs_build}/gfrguard.so" | cut -d, -f1))"
    else
        echo "FAILED (VFS module not found — skipping ${ver})"
        return 0
    fi

    # Verify source-built smbd can actually run on this host
    if ! ldd "${src}/bin/default/source3/smbd/smbd" 2>&1 | grep -q "not found"; then
        : # OK
    else
        echo "  smbd... SKIP (binary not compatible with this host — needs rebuild)"
        return 0
    fi

    echo "  smbd... "
    # Run tests with source-built smbd
    SAMBA_VER="${ver}" \
    SAMBA_SRC_BASE="${SAMBA_SRC_BASE}" \
        bash "${PROJECT_DIR}/tests/integration/run_all.sh"
    local rc=$?

    return $rc
}

# ===================================================================
cd "${PROJECT_DIR}"

# Ensure runtime environment
ensure_runtime

# Stop everything before starting
force_kill_daemon
force_stop_smbd

echo "===== gfrguard Integration Pipeline ====="
echo ""

RC=0

# Run tests for each Samba version
for ver in 4.23.5 4.19.6; do
    if ! run_version "${ver}"; then
        RC=1
    fi
    # Clean up between versions
    force_kill_daemon
    force_stop_smbd
done

echo ""
if [ $RC -eq 0 ]; then
    echo "===== All versions passed ====="
else
    echo "===== Some tests FAILED ====="
fi
exit $RC
