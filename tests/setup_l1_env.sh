#!/bin/bash
# setup_l1_env.sh — Build gfrguard + Samba for L3 integration testing
# Supports Debian/Ubuntu (apt) and RHEL/AlmaLinux/Rocky (dnf).
# Run once to set up the test environment.
set -euo pipefail

# ── OS detection ────────────────────────────────────────────────────────────
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "${ID,,}" in
            debian|ubuntu|linuxmint|pop) echo "debian" ;;
            rhel|centos|almalinux|rocky|fedora|amzn) echo "rhel" ;;
            *)
                if command -v apt-get &>/dev/null; then echo "debian"
                elif command -v dnf &>/dev/null; then echo "rhel"
                else echo "unknown"
                fi ;;
        esac
    elif command -v apt-get &>/dev/null; then echo "debian"
    elif command -v dnf &>/dev/null; then echo "rhel"
    else echo "unknown"
    fi
}

OS=$(detect_os)
if [ "$OS" = "unknown" ]; then
    echo "ERROR: Cannot detect OS. Only Debian/Ubuntu (apt) and RHEL/AlmaLinux (dnf) are supported."
    exit 1
fi
echo "=== Detected OS: ${OS} ==="

# ── Configurable paths ──────────────────────────────────────────────────────
SAMBA_VER="${SAMBA_VER:-$(smbd --version 2>/dev/null | grep -oP '[\d]+\.[\d]+\.[\d]+' || echo 4.19.6)}"
SAMBA_SRC="${SAMBA_SRC:-./samba-src/samba-${SAMBA_VER}}"
BUILD_DIR="${BUILD_DIR:-build}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
NPROC="${NPROC:-$(nproc)}"

echo "=== L1: Build Environment Setup ==="
echo "  Project dir: ${PROJECT_DIR}"
echo "  Build dir:   ${PROJECT_DIR}/${BUILD_DIR}"

# ── 1. Install system dependencies ──────────────────────────────────────────
echo "[1/5] Installing dependencies..."

install_debian() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq \
        gcc make cmake pkg-config \
        sqlite3 libsqlite3-dev \
        yara libyara-dev \
        python3-dev \
        bison flex \
        p7zip p7zip-full \
        samba samba-common-bin samba-dev \
        smbclient 2>&1 | tail -5
}

install_rhel() {
    dnf install -y \
        gcc make cmake pkg-config \
        sqlite sqlite-devel \
        yara yara-devel \
        python3-devel \
        bison flex \
        p7zip p7zip-plugins \
        samba samba-client samba-devel samba-common-tools 2>&1 | tail -5
}

case "$OS" in
    debian) install_debian ;;
    rhel)   install_rhel   ;;
esac

echo "   Dependencies installed."

# ── 2. Locate Samba source (for VFS internal headers) ──────────────────────
VFS_SAMBA_SRC=""
echo "[2/5] Locating Samba source for VFS headers..."

# Search order: samba-src/samba-<ver>, /tmp/samba-<ver>*, apt-source
_candidates=(
    "${PROJECT_DIR}/samba-src/samba-${SAMBA_VER}"
    "/tmp/samba-${SAMBA_VER}"*
)
# Also try samba-src/ trees that match prefix (e.g. samba-4.17.12+dfsg)
for _d in "${PROJECT_DIR}"/samba-src/samba-*; do
    [ -d "$_d" ] && _candidates+=("$_d")
done

for _d in "${_candidates[@]}"; do
    if [ -f "${_d}/bin/default/include/config.h" ]; then
        VFS_SAMBA_SRC="$_d"
        echo "   Found: ${VFS_SAMBA_SRC}"
        break
    fi
done

# If not found, try apt-get source + configure + make (Debian/Ubuntu)
if [ -z "${VFS_SAMBA_SRC}" ] && [ "$OS" = "debian" ]; then
    echo "   No pre-built Samba found, trying apt-get source..."
    _tmp_src="/tmp/samba-${SAMBA_VER}"
    if [ ! -d "${_tmp_src}" ]; then
        mkdir -p /tmp/samba-src && cd /tmp/samba-src
        # Detect distro codename for deb-src line
        . /etc/os-release 2>/dev/null || true
        _src_line="deb-src http://deb.debian.org/debian ${VERSION_CODENAME:-bookworm} main"
        if [ "${ID}" = "ubuntu" ]; then
            _src_line="deb-src http://archive.ubuntu.com/ubuntu ${VERSION_CODENAME:-noble} main"
        fi
        echo "${_src_line}" >> /etc/apt/sources.list.d/samba-src.list 2>/dev/null || true
        apt-get update -qq 2>/dev/null || true
        apt-get source samba 2>&1 | tail -3 || true
        cd "${PROJECT_DIR}"
        # apt-get source extracts as samba-<ver>+dfsg
        for _d in /tmp/samba-*; do
            [ -d "$_d" ] && _tmp_src="$_d" && break
        done
    fi
    if [ -d "${_tmp_src}" ] && [ ! -f "${_tmp_src}/bin/default/include/config.h" ]; then
        cd "${_tmp_src}"
        find . -name ".lock*" -delete 2>/dev/null || true
        PYTHONHASHSEED=1 python3 ./buildtools/bin/waf configure \
            --disable-python --without-ad-dc --without-ads \
            --without-json --without-libarchive --with-system-mitkrb5 2>&1 | tail -1
        PYTHONHASHSEED=1 python3 ./buildtools/bin/waf build -j${NPROC} 2>&1 | tail -1
        cd "${PROJECT_DIR}"
    fi
    [ -f "${_tmp_src}/bin/default/include/config.h" ] && VFS_SAMBA_SRC="${_tmp_src}"
fi

if [ -z "${VFS_SAMBA_SRC}" ]; then
    echo "   WARNING: Samba source headers not available — VFS module will NOT be built."
    echo "   Unit tests (L2) do not need Samba. Integration tests (L3) will need it."
else
    echo "   Samba source: ${VFS_SAMBA_SRC}"
fi

# ── 3. Build gfrguard with CMake ────────────────────────────────────────────
echo "[3/5] Building gfrguard with CMake..."

cd "${PROJECT_DIR}"
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

CMAKE_ARGS="-DCMAKE_BUILD_TYPE=Debug"
if [ -n "${VFS_SAMBA_SRC}" ]; then
    CMAKE_ARGS="${CMAKE_ARGS} -DBUILD_VFS=ON -DSAMBA_SRC=$(readlink -f "${VFS_SAMBA_SRC}")"
fi

cmake -B "${BUILD_DIR}" ${CMAKE_ARGS} 2>&1 | tail -3
cmake --build "${BUILD_DIR}" -j${NPROC} 2>&1 | tail -5

echo "   gfrguardd:        $(file "${BUILD_DIR}/gfrguardd" | cut -d, -f1)"
echo "   gfrguard-recover:  $(file "${BUILD_DIR}/gfrguard-recover" | cut -d, -f1)"
if [ -f "${BUILD_DIR}/gfrguard.so" ]; then
    echo "   gfrguard.so:      $(file "${BUILD_DIR}/gfrguard.so" | cut -d, -f1)"
fi

# ── 3b. Run unit tests ──────────────────────────────────────────────────────
echo "[3b] Running unit tests (ctest)..."
(cd "${BUILD_DIR}" && ctest --output-on-failure 2>&1) || {
    echo "WARNING: Some unit tests failed. Review output above."
}

# ── 4. Install ──────────────────────────────────────────────────────────────
echo "[4/5] Installing..."

# VFS module path varies by distro
case "$OS" in
    debian) VFS_DIR="/usr/lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)/samba/vfs" ;;
    rhel)   VFS_DIR="/usr/lib64/samba/vfs" ;;
esac

mkdir -p /usr/local/sbin /usr/local/bin "${VFS_DIR}"
cp -f "${BUILD_DIR}/gfrguardd" /usr/local/sbin/
cp -f "${BUILD_DIR}/gfrguard-recover" /usr/local/bin/
if [ -f "${BUILD_DIR}/gfrguard.so" ]; then
    cp -f "${BUILD_DIR}/gfrguard.so" "${VFS_DIR}/"
fi

# ── 5. Create runtime dirs and config ──────────────────────────────────────
echo "[5/5] Creating runtime environment..."
mkdir -p /var/lib/gf2000/rguard-store/{backups,quarantine}
mkdir -p /run/gfrguardd /etc/gf2000/yara-rules /var/log/gfrguard /srv/samba/rguard-test
chmod 0777 /var/lib/gf2000/rguard-store/backups

# Deploy config files
cp -f files/rguard-scoring.json /etc/gf2000/ 2>/dev/null || true
cp -f files/ransom-extensions.json /etc/gf2000/ 2>/dev/null || true
# Deploy all YARA rules (flat + vendor subdirs)
rm -rf /etc/gf2000/yara-rules/vendor
if [ -d files/yara-rules/vendor ]; then
    cp -rf files/yara-rules/vendor /etc/gf2000/yara-rules/
fi
for f in files/yara-rules/*.yar; do
    [ -f "$f" ] && cp -f "$f" /etc/gf2000/yara-rules/
done

# Policy JSON with inline scoring
cat > /etc/gf2000/rguard-policy.json << 'POLICYEOF'
{"store_path":"/var/lib/gf2000/rguard-store","log_path":"/var/log/gfrguard","log_level":"debug","mode":"permissive","scoring_config":"/etc/gf2000/rguard-scoring.json","ransom_extensions_config":"/etc/gf2000/ransom-extensions.json","exceptions":{"files":[],"folders":[]},"whitelist":{"users":[],"ips":[]},"blacklist":{"users":[],"ips":[]},"space":{"max_usage_percent":80,"cleanup_days":30},"auto_restore":{"enabled":false,"delay_seconds":3},"scoring":{"window_short":10,"window_long":30,"weights":{"modified":3,"rename":4,"delete":3,"dirs":5,"ext_change":5,"ransom_ext":20,"high_entropy":8,"yara_match":40},"thresholds":{"warn":30,"high":60,"critical":80},"entropy_threshold":7.0,"entropy_enabled":true,"yara_enabled":true}}
POLICYEOF

# Test Samba share config
if [ -f /etc/samba/smb.conf ] && ! grep -q 'rguard-test' /etc/samba/smb.conf 2>/dev/null; then
    VFS_OBJECTS="gfrguard"
    cat >> /etc/samba/smb.conf << SMBEOF

[rguard-test]
	path = /srv/samba/rguard-test
	read only = No
	guest ok = Yes
	vfs objects = ${VFS_OBJECTS}
	gfrguard:protect = yes
	gfrguard:store = /var/lib/gf2000/rguard-store
	gfrguard:policy = /etc/gf2000/rguard-policy.json
	gfrguard:mode = permissive
SMBEOF
fi

# Test user
id testuser >/dev/null 2>&1 || useradd -M testuser 2>/dev/null || true
if command -v smbpasswd &>/dev/null; then
    (echo testpass; echo testpass) | smbpasswd -a -s testuser 2>/dev/null || true
fi

# SELinux (RHEL only)
if [ "$OS" = "rhel" ]; then
    setenforce 0 2>/dev/null || true
fi

echo ""
echo "=== L1 environment ready ==="
echo "  OS:         ${OS}"
echo "  gfrguardd:  /usr/local/sbin/gfrguardd"
echo "  recover:    /usr/local/bin/gfrguard-recover"
echo "  VFS module: ${VFS_DIR}/gfrguard.so"
echo "  Build dir:  ${PROJECT_DIR}/${BUILD_DIR}"
echo ""
echo "  bash tests/integration/run_all.sh    # L3"
