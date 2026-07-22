/*
 * vfs_gfrguard.c - GF2000 anti-ransomware Samba VFS module.
 *
 * Responsibilities (per design doc 3.1.1):
 *   1. Read smb.conf "gfrguard:*" parameters at connect.
 *   2. Cache the blocked-session list from /run/gfrguardd/blocked.
 *   3. On openat/pwrite/ftruncate of an existing file in write mode -> first-write backup.
 *   4. On openat/renameat/unlinkat of a blocked session -> deny with EACCES.
 *   5. Asynchronously fire-and-forget a 4608-byte event to gfrguardd.
 *
 * Errors never propagate past this module (transparent fallback to NEXT).
 * Per Samba VFS conventions int callbacks return <0 with errno on failure;
 * the design's "NT_STATUS_ACCESS_DENIED" is mapped to errno=EACCES, return -1.
 */

#define __STDC_WANT_LIB_EXT1__ 1

#include "includes.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "auth.h"

#include "../common/rguard_protocol.h"
#include "../common/rguard_backup.h"
#include "../common/rguard_errors.h"
#include "../common/rguard_types.h"

/* Upper bound for the close-time full-content comparison: beyond this the
 * FNV two-pass costs more session latency than a rare false-positive
 * modified_count is worth. */
#define GFR_CONTENT_COMPARE_MAX (64 * 1024 * 1024)

#include <stdbool.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifndef GFRGUARD_DEBUG_LEVEL
#define GFRGUARD_DEBUG_LEVEL 5
#endif

#define GF_DEBUG(level, args) DEBUG(level, args)

#define BLOCKED_PATH_DEFAULT "/run/gfrguardd/blocked"

struct gfrguard_config {
    bool   protect;
    int    mode;                  /* 0=strict, 1=permissive */
    char   store_path[256];
    char   daemon_socket_path[256];
    int    sock_fd;
    struct sockaddr_un daemon_addr;

    /* Blocked-list cache */
    char   blocked_path[256];
    time_t blocked_mtime;
    long   blocked_mtime_ns;
    char  *blocked_content;       /* NUL-terminated, talloc'd */
    size_t blocked_size;
};

#define GFR_MODE_STRICT     0
#define GFR_MODE_PERMISSIVE 1

/* ---------- helpers ---------- */

static const char *session_user(vfs_handle_struct *handle)
{
    if (handle && handle->conn && handle->conn->session_info &&
        handle->conn->session_info->unix_info) {
        const char *u = handle->conn->session_info->unix_info->unix_name;
        if (u && *u) return u;
    }
    return "unknown";
}

static const char *session_ip(vfs_handle_struct *handle)
{
    if (handle && handle->conn && handle->conn->sconn &&
        handle->conn->sconn->remote_hostname) {
        return handle->conn->sconn->remote_hostname;
    }
    return "0.0.0.0";
}

static const char *share_name_of(vfs_handle_struct *handle)
{
    if (handle && handle->conn) {
        const char *s = lp_const_servicename(SNUM(handle->conn));
        if (s) return s;
    }
    return "unknown";
}

static int mkdir_p(const char *path, mode_t mode)
{
    char buf[RGUARD_PATH_MAX];
    snprintf(buf, sizeof(buf), "%s", path);
    for (char *p = buf + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(buf, mode) != 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }
    /* Create the final component. */
    if (mkdir(buf, mode) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

/* Refresh the blocked list cache via stat-mtime check.
 * Must use become_root because smbd worker runs as connected user
 * and the blocked file is owned by root (mode 0640). */
static void refresh_blocked_cache(struct gfrguard_config *cfg, TALLOC_CTX *mem)
{
    struct stat st;

    become_root();
    int sr = stat(cfg->blocked_path, &st);
    unbecome_root();

    if (sr != 0) {
        if (cfg->blocked_content) {
            TALLOC_FREE(cfg->blocked_content);
            cfg->blocked_size = 0;
        }
        cfg->blocked_mtime = 0;
        return;
    }
    /* Compare both seconds and nanoseconds to catch sub-second updates
     * (blocker uses atomic rename which always changes ctime/mtime). */
    if (st.st_mtim.tv_sec == cfg->blocked_mtime &&
        st.st_mtim.tv_nsec == cfg->blocked_mtime_ns &&
        cfg->blocked_content) {
        return;
    }

    become_root();
    int fd = open(cfg->blocked_path, O_RDONLY | O_CLOEXEC);
    unbecome_root();
    if (fd < 0) return;

    size_t cap = (size_t)st.st_size + 1;
    char *buf = talloc_array(mem, char, cap);
    if (!buf) { close(fd); return; }

    ssize_t n = read(fd, buf, cap - 1);
    close(fd);
    if (n < 0) { TALLOC_FREE(buf); return; }
    buf[n] = '\0';

    if (cfg->blocked_content) TALLOC_FREE(cfg->blocked_content);
    cfg->blocked_content = buf;
    cfg->blocked_size    = (size_t)n;
    cfg->blocked_mtime   = st.st_mtim.tv_sec;
    cfg->blocked_mtime_ns = st.st_mtim.tv_nsec;
}

/* Fire-and-forget notification to daemon: a connection/file-op was denied
 * because the session matched a blocked entry.  The daemon uses this to
 * log the event and update the DB.  Failure is silent — the block itself
 * is the primary action; this is best-effort telemetry. */
static void send_blocked_notify(struct gfrguard_config *cfg,
                                vfs_handle_struct *handle)
{
    if (!cfg || cfg->sock_fd < 0) return;

    struct rguard_event_msg msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_type   = RGUARD_MSG_VFS_BLOCKED;
    msg.proto_version = RGUARD_PROTO_VERSION;
    msg.source_type = RGUARD_SOURCE_SMB;
    msg.timestamp  = (int64_t)time(NULL);
    snprintf(msg.username,   sizeof(msg.username),   "%s", session_user(handle));
    snprintf(msg.client_ip,  sizeof(msg.client_ip),  "%s", session_ip(handle));
    snprintf(msg.share_name, sizeof(msg.share_name), "%s", share_name_of(handle));

    sendto(cfg->sock_fd, &msg, sizeof(msg), MSG_DONTWAIT | MSG_NOSIGNAL,
           (struct sockaddr *)&cfg->daemon_addr,
           (socklen_t)sizeof(cfg->daemon_addr));
}

static bool is_blocked(struct gfrguard_config *cfg, vfs_handle_struct *handle)
{
    refresh_blocked_cache(cfg, handle);
    if (!cfg->blocked_content || cfg->blocked_size == 0) return false;

    const char *ip = session_ip(handle);
    size_t iplen = strlen(ip);
    if (iplen == 0) return false;

    const char *p = cfg->blocked_content;
    const char *end = p + cfg->blocked_size;
    while (p < end) {
        const char *eol = memchr(p, '\n', (size_t)(end - p));
        size_t linelen = eol ? (size_t)(eol - p) : (size_t)(end - p);

        if (linelen == iplen && strncmp(p, ip, iplen) == 0) {
            send_blocked_notify(cfg, handle);
            return true;
        }

        if (!eol) break;
        p = eol + 1;
    }
    return false;
}

static int init_daemon_socket(struct gfrguard_config *cfg)
{
    cfg->sock_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (cfg->sock_fd < 0) return -1;
    /* Increase send buffer to reduce EAGAIN under burst. */
    int sndbuf = 4 * 1024 * 1024;
    setsockopt(cfg->sock_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    memset(&cfg->daemon_addr, 0, sizeof(cfg->daemon_addr));
    cfg->daemon_addr.sun_family = AF_UNIX;
    /* sun_path is ~108 bytes; a longer socket path is a misconfiguration.
     * Truncating it silently would send events into the void — fail loud. */
    size_t slen = strlen(cfg->daemon_socket_path);
    if (slen >= sizeof(cfg->daemon_addr.sun_path)) {
        GF_DEBUG(0, ("gfrguard: daemon socket path too long (%zu bytes): %s\n",
                     slen, cfg->daemon_socket_path));
        close(cfg->sock_fd);
        cfg->sock_fd = -1;
        return -1;
    }
    memcpy(cfg->daemon_addr.sun_path, cfg->daemon_socket_path, slen + 1);
    return 0;
}

static void send_event(struct gfrguard_config *cfg,
                       vfs_handle_struct *handle,
                       uint8_t op_type, uint16_t flags,
                       const char *relative_path,
                       const char *new_name,
                       const struct stat *st_or_null)
{
    if (cfg->sock_fd < 0) return;
    struct rguard_event_msg msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_type   = RGUARD_MSG_FILE_EVENT;
    msg.proto_version = RGUARD_PROTO_VERSION;
    msg.source_type = RGUARD_SOURCE_SMB;
    msg.op_type    = op_type;
    msg.flags     = flags;
    msg.timestamp = (int64_t)time(NULL);
    if (st_or_null) {
        msg.inode     = (uint64_t)st_or_null->st_ino;
        msg.file_size = (uint64_t)st_or_null->st_size;
        msg.mtime     = (int64_t)st_or_null->st_mtime;
        msg.file_uid  = (uint32_t)st_or_null->st_uid;
        msg.file_gid  = (uint32_t)st_or_null->st_gid;
        msg.file_mode = (uint32_t)st_or_null->st_mode;
    }
    snprintf(msg.username,   sizeof(msg.username),   "%s", session_user(handle));
    snprintf(msg.client_ip,  sizeof(msg.client_ip),  "%s", session_ip(handle));
    snprintf(msg.share_name, sizeof(msg.share_name), "%s", share_name_of(handle));
    if (relative_path) {
        /* Send absolute path so daemon can store it for restore. */
        snprintf(msg.file_path, sizeof(msg.file_path), "%s/%s",
                 handle->conn->connectpath, relative_path);
    }
    if (new_name) {
        snprintf(msg.new_name, sizeof(msg.new_name), "%s", new_name);
    }

    ssize_t r = -1;
    for (int attempt = 0; attempt < 3; attempt++) {
        r = sendto(cfg->sock_fd, &msg, sizeof(msg), MSG_DONTWAIT | MSG_NOSIGNAL,
                   (struct sockaddr *)&cfg->daemon_addr,
                   (socklen_t)sizeof(cfg->daemon_addr));
        if (r >= 0 || errno != EAGAIN) break;
        usleep(500);  /* 0.5ms backoff before retry */
    }
    if (r < 0) {
        GF_DEBUG(0, ("gfrguard: sendto daemon FAILED: %s (fd=%d path=%s)\n",
                     strerror(errno), cfg->sock_fd, cfg->daemon_socket_path));
    }
}

/* Compute backup_path = <store>/backups/<share>/<rel>.
 * rel is the canonical share-relative path (fsp->fsp_name->base_name).
 * The old implementation recovered rel by strstr("/<share>/") on the
 * absolute path — wrong whenever an upper directory happened to contain
 * the share name, silently landing the preimage under a bogus relative
 * path that restore can never match. */
static int compute_backup_path(const struct gfrguard_config *cfg,
                               const char *share, const char *rel,
                               char *out, size_t outlen)
{
    if (!rel || !*rel) return -1;
    int n = snprintf(out, outlen, "%s/backups/%s/%s",
                     cfg->store_path, share, rel);
    return (n > 0 && (size_t)n < outlen) ? 0 : -1;
}

static int do_backup(struct gfrguard_config *cfg, const char *src_path,
                     const char *share, const char *rel, struct stat *st_out)
{
    struct stat st;
    if (stat(src_path, &st) != 0) {
        GF_DEBUG(0, ("gfrguard: do_backup stat('%s') failed: %s\n",
                     src_path, strerror(errno)));
        return RGUARD_ERR_BACKUP;
    }
    if (st_out) *st_out = st;

    char backup[RGUARD_PATH_MAX];
    if (compute_backup_path(cfg, share, rel, backup, sizeof(backup)) != 0) {
        GF_DEBUG(0, ("gfrguard: do_backup path too long for '%s'\n", src_path));
        return RGUARD_ERR_BACKUP;
    }

    /* Elevate to root for store directory access (smbd runs as root,
     * but seteuid'd to the SMB user for file I/O). */
    become_root();

    /* First copy wins: an existing backup is the oldest — most likely
     * pre-attack — version.  Never replace it: a later write may
     * already be ransomware ciphertext, and overwriting the only good
     * copy would make restore return ciphertext. */
    struct stat bst;
    if (stat(backup, &bst) == 0) {
        unbecome_root();
        return RGUARD_OK;
    }

    /* mkdir parent dirs of backup. */
    char parent[RGUARD_PATH_MAX];
    snprintf(parent, sizeof(parent), "%s", backup);
    char *slash = strrchr(parent, '/');
    if (slash) {
        *slash = '\0';
        if (mkdir_p(parent, 0755) != 0) {
            GF_DEBUG(0, ("gfrguard: do_backup mkdir_p('%s') failed: %s\n",
                         parent, strerror(errno)));
            unbecome_root();
            return RGUARD_ERR_BACKUP;
        }
    }

    /* src_path is client-controlled: O_NOFOLLOW keeps a symlink swap from
     * making root copy an arbitrary host file into the backup area, and the
     * fstat on the opened fd closes the stat→open window. */
    int sfd = open(src_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (sfd < 0) {
        GF_DEBUG(0, ("gfrguard: do_backup open src '%s' failed: %s\n",
                     src_path, strerror(errno)));
        unbecome_root();
        return RGUARD_ERR_BACKUP;
    }
    struct stat fst;
    if (fstat(sfd, &fst) != 0 || !S_ISREG(fst.st_mode)) {
        close(sfd);
        unbecome_root();
        return RGUARD_ERR_BACKUP;
    }
    int dfd = open(backup, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (dfd < 0) {
        close(sfd);
        if (errno == EEXIST) {
            /* Race: another thread created the backup between our
             * stat() and open().  That's fine — backup is current. */
            unbecome_root(); return RGUARD_OK;
        }
        GF_DEBUG(0, ("gfrguard: do_backup create '%s' failed: %s\n",
                     backup, strerror(errno)));
        unbecome_root();
        return RGUARD_ERR_BACKUP;
    }

    /* reflink → copy_file_range → read/write (rguard_backup.h).
     * fst (fstat of sfd), not the pre-open stat — same inode, no race. */
    int rc = (rguard_copy_fd(sfd, dfd, fst.st_size) == 0) ? RGUARD_OK
                                                          : RGUARD_ERR_BACKUP;

    fsync(dfd);
    close(sfd);
    close(dfd);

    if (rc == RGUARD_OK) {
        struct timespec times[2];
        times[0].tv_sec = fst.st_atime; times[0].tv_nsec = 0;
        times[1].tv_sec = fst.st_mtime; times[1].tv_nsec = 0;
        (void)utimensat(AT_FDCWD, backup, times, 0);
    } else {
        unlink(backup);
    }

    unbecome_root();
    return rc;
}

/* Deferred-backup result, shared by pwrite/ftruncate. */
enum gf_defer_rc {
    GF_DEFER_DENY       = -1,  /* strict deny: event sent, errno=ENOSPC */
    GF_DEFER_UNRESOLVED = 0,   /* path unresolvable/overflow: nothing done */
    GF_DEFER_DONE       = 1,   /* backup attempted (see fst->backup_done) */
};

/* pwrite/ftruncate share the same deferred-backup logic: a procfd-reopen
 * openat could not know the real path, so the first destructive callback
 * after it must resolve relative_path and run do_backup.  On strict-mode
 * failure the helper sends the event and sets errno=ENOSPC itself. */
static enum gf_defer_rc
gf_deferred_backup(struct gfrguard_config *cfg, vfs_handle_struct *handle,
                   files_struct *fsp, struct rguard_file_state *fst,
                   uint8_t op_type, uint16_t *flags)
{
    if (fst->backup_failed)
        return GF_DEFER_DONE;   /* permissive failure already reported once */

    /* Resolve deferred relative_path if it was not available at openat time. */
    if (fst->relative_path[0] == '\0' && fsp->fsp_name &&
        fsp->fsp_name->base_name &&
        strncmp(fsp->fsp_name->base_name, "/proc/", 6) != 0) {
        snprintf(fst->relative_path, sizeof(fst->relative_path), "%s",
                 fsp->fsp_name->base_name);
        GF_DEBUG(0, ("gfrguard: deferred backup resolved path='%s'\n",
                     fst->relative_path));
    }
    if (fst->relative_path[0] == '\0')
        return GF_DEFER_UNRESOLVED;

    char full[RGUARD_PATH_MAX];
    struct stat st;
    int w = snprintf(full, sizeof(full), "%s/%s",
                     handle->conn->connectpath, fst->relative_path);
    if (w < 0 || (size_t)w >= sizeof(full)) {
        /* Overflow — backing up the wrong file is worse than none. */
        return GF_DEFER_UNRESOLVED;
    }

    int rc = do_backup(cfg, full, fst->share_name, fst->relative_path, &st);
    if (rc == RGUARD_OK) {
        fst->backup_done = true;
        *flags |= RGUARD_FLAG_BACKED_UP;
        return GF_DEFER_DONE;
    }
    fst->backup_failed = true;
    *flags |= RGUARD_FLAG_BACKUP_FAILED;
    if (cfg->mode == GFR_MODE_STRICT) {
        send_event(cfg, handle, op_type, *flags, fst->relative_path, NULL, NULL);
        errno = ENOSPC;
        return GF_DEFER_DENY;
    }
    return GF_DEFER_DONE;
}

/* ---------- VFS callbacks ---------- */

static int gf_connect(vfs_handle_struct *handle, const char *svc, const char *user)
{
    int rc = SMB_VFS_NEXT_CONNECT(handle, svc, user);
    if (rc < 0) return rc;

    struct gfrguard_config *cfg = talloc_zero(handle, struct gfrguard_config);
    if (!cfg) {
        SMB_VFS_NEXT_DISCONNECT(handle);
        errno = ENOMEM;
        return -1;
    }
    cfg->sock_fd = -1;

    cfg->protect = lp_parm_bool(SNUM(handle->conn), "gfrguard", "protect", true);

    const char *s = lp_parm_const_string(SNUM(handle->conn), "gfrguard",
                                         "store", "/var/lib/gf2000/rguard-store");
    snprintf(cfg->store_path, sizeof(cfg->store_path), "%s", s);

    s = lp_parm_const_string(SNUM(handle->conn), "gfrguard", "daemon_socket",
                             "/run/gfrguardd/gfrguardd.sock");
    snprintf(cfg->daemon_socket_path, sizeof(cfg->daemon_socket_path), "%s", s);

    const char *mode = lp_parm_const_string(SNUM(handle->conn), "gfrguard",
                                            "mode", "strict");
    cfg->mode = strequal(mode, "permissive") ? GFR_MODE_PERMISSIVE : GFR_MODE_STRICT;

    snprintf(cfg->blocked_path, sizeof(cfg->blocked_path), "%s",
             BLOCKED_PATH_DEFAULT);

    if (cfg->protect) {
        become_root();
        struct stat st;
        int st_rc = stat(cfg->store_path, &st);
        int acc_rc = access(cfg->store_path, W_OK);
        unbecome_root();
        if (st_rc != 0 || acc_rc != 0) {
            GF_DEBUG(0, ("gfrguard: store '%s' not writable\n", cfg->store_path));
            if (cfg->mode == GFR_MODE_STRICT) {
                SMB_VFS_NEXT_DISCONNECT(handle);
                errno = EACCES;
                return -1;
            }
            cfg->protect = false;
        }
    }

    SMB_VFS_HANDLE_SET_DATA(handle, cfg, NULL,
                            struct gfrguard_config, return -1);

    /* Check blocked list. (Blacklist/whitelist/exceptions are handled
     * centrally by the daemon — VFS only enforces the blocked-file cache.) */
    if (cfg->protect) {
        init_daemon_socket(cfg);

        const char *conn_user = session_user(handle);
        const char *conn_ip   = session_ip(handle);
        char skey[RGUARD_SESSION_KEY_LEN];
        rguard_make_session_key(skey, sizeof(skey), conn_user, conn_ip);

        if (is_blocked(cfg, handle)) {
            GF_DEBUG(0, ("gfrguard: connect DENIED (blocked) session '%s'\n", skey));
            SMB_VFS_NEXT_DISCONNECT(handle);
            errno = EACCES;
            return -1;
        }
    }

    GF_DEBUG(0, ("gfrguard: connected svc=%s user=%s protect=%d mode=%d store=%s\n",
                 svc ? svc : "?", user ? user : "?",
                 (int)cfg->protect, cfg->mode, cfg->store_path));
    return 0;
}

static void gf_disconnect(vfs_handle_struct *handle)
{
    struct gfrguard_config *cfg = NULL;
    SMB_VFS_HANDLE_GET_DATA(handle, cfg, struct gfrguard_config,
                            { SMB_VFS_NEXT_DISCONNECT(handle); return; });
    if (cfg && cfg->sock_fd >= 0) {
        close(cfg->sock_fd);
        cfg->sock_fd = -1;
    }
    SMB_VFS_NEXT_DISCONNECT(handle);
}

static struct gfrguard_config *get_cfg(vfs_handle_struct *handle)
{
    struct gfrguard_config *cfg = NULL;
    SMB_VFS_HANDLE_GET_DATA(handle, cfg, struct gfrguard_config, return NULL);
    return cfg;
}

static const char *fname_str(const struct smb_filename *smb_fname)
{
    return (smb_fname && smb_fname->base_name) ? smb_fname->base_name : "?";
}

static int gf_openat(vfs_handle_struct *handle,
                     const struct files_struct *dirfsp,
                     const struct smb_filename *smb_fname,
                     struct files_struct *fsp,
                     const struct vfs_open_how *how)
{
    struct gfrguard_config *cfg = get_cfg(handle);
    if (!cfg || !cfg->protect) {
        return SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
    }

    const int oflags = how ? how->flags : 0;

    /* Skip path-walk opens (O_PATH, O_DIRECTORY, read-only). */
    if (oflags & O_PATH) {
        return SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
    }

    bool write_mode  = (oflags & (O_WRONLY | O_RDWR)) != 0;
    bool create_trunc = (oflags & (O_CREAT | O_TRUNC)) == (O_CREAT | O_TRUNC);
    bool append_only  = (oflags & O_APPEND) != 0;

    if (!write_mode && !create_trunc) {
        return SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
    }

    /* Check blocked BEFORE open. Use fsp->fsp_name which Samba sets before
     * calling the VFS openat callback (canonical share-relative path). */
    const char *rel = (fsp && fsp->fsp_name && fsp->fsp_name->base_name)
                      ? fsp->fsp_name->base_name
                      : fname_str(smb_fname);

    /* Detect internal reopen via /proc/self/fd/N — Samba upgrading a pathref
     * fd to a real fd.  The smb_fname passed will be /proc/self/fd/N but
     * fsp->fsp_name should still hold the canonical share-relative path.
     * If rel itself is a /proc path, we cannot do backup here; defer to
     * pwrite/ftruncate. */
    bool is_procfd_reopen = (strncmp(fname_str(smb_fname), "/proc/", 6) == 0);
    if (is_procfd_reopen && strncmp(rel, "/proc/", 6) == 0) {
        /* Both smb_fname and fsp_name point to /proc — cannot determine
         * real path.  Still let the open proceed and mark for deferred backup. */

        /* Check blocked even on procfd-reopen. */
        char skey_pfd[RGUARD_SESSION_KEY_LEN];
        rguard_make_session_key(skey_pfd, sizeof(skey_pfd),
                         session_user(handle), session_ip(handle));
        if (is_blocked(cfg, handle)) {
            GF_DEBUG(0, ("gfrguard: openat BLOCKED (procfd) session '%s'\n",
                         skey_pfd));
            errno = EACCES;
            return -1;
        }

        GF_DEBUG(0, ("gfrguard: openat procfd-reopen, rel also /proc, "
                     "deferring backup. smb='%s' fspname='%s'\n",
                     fname_str(smb_fname), rel));
        int result = SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);
        if (result >= 0) {
            /* After successful open, fsp->fsp_name may now be correct.
             * Try to get the real path for FSP extension. */
            const char *real_rel = (fsp->fsp_name && fsp->fsp_name->base_name &&
                                    strncmp(fsp->fsp_name->base_name, "/proc/", 6) != 0)
                                   ? fsp->fsp_name->base_name : NULL;
            struct rguard_file_state *fst = (struct rguard_file_state *)
                VFS_ADD_FSP_EXTENSION(handle, fsp, struct rguard_file_state, NULL);
            if (fst) {
                memset(fst, 0, sizeof(*fst));
                fst->is_risky      = true;
                fst->backup_done   = false;
                fst->backup_failed = false;
                char skey2[RGUARD_SESSION_KEY_LEN];
                rguard_make_session_key(skey2, sizeof(skey2),
                                 session_user(handle), session_ip(handle));
                snprintf(fst->session_key, sizeof(fst->session_key), "%s", skey2);
                snprintf(fst->share_name, sizeof(fst->share_name), "%s", share_name_of(handle));
                if (real_rel) {
                    snprintf(fst->relative_path, sizeof(fst->relative_path), "%s", real_rel);
                } else {
                    fst->relative_path[0] = '\0';  /* will be resolved in pwrite */
                }
            }
            GF_DEBUG(0, ("gfrguard: openat procfd-reopen attached ext, "
                         "real_rel='%s'\n", real_rel ? real_rel : "(deferred)"));
        }
        return result;
    }

    char skey[RGUARD_SESSION_KEY_LEN];
    rguard_make_session_key(skey, sizeof(skey),
                     session_user(handle), session_ip(handle));

    if (is_blocked(cfg, handle)) {
        GF_DEBUG(0, ("gfrguard: openat BLOCKED session '%s' file '%s'\n",
                     skey, rel));
        errno = EACCES;
        return -1;
    }

    /* Save errno — our stat/backup must not corrupt it for NEXT. */
    int saved_errno = errno;

    /* Stat the real file to determine if it exists (risky = overwrite). */
    struct stat st;
    char full_path[RGUARD_PATH_MAX];
    snprintf(full_path, sizeof(full_path), "%s/%s",
             handle->conn->connectpath, rel);
    bool exists = (stat(full_path, &st) == 0 && S_ISREG(st.st_mode));
    /* O_APPEND is kernel-enforced: all writes go to EOF regardless of offset.
     * Append never destroys existing data, so it is not a ransomware vector.
     * O_TRUNC always destroys data, so create_trunc overrides append_only. */
    bool risky = exists && ((write_mode && !append_only) || create_trunc);

    GF_DEBUG(0, ("gfrguard: openat rel='%s' smb='%s' fspname='%s' "
                 "cwd='%s' conn='%s' full='%s' "
                 "flags=0x%x exists=%d risky=%d\n",
                 rel, fname_str(smb_fname),
                 (fsp && fsp->fsp_name) ? fsp->fsp_name->base_name : "(null)",
                 (handle->conn && handle->conn->cwd_fsp && handle->conn->cwd_fsp->fsp_name)
                     ? handle->conn->cwd_fsp->fsp_name->base_name : "(null)",
                 handle->conn->connectpath ? handle->conn->connectpath : "(null)",
                 full_path, oflags, (int)exists, (int)risky));

    uint16_t flags = 0;
    int backup_rc = RGUARD_OK;
    if (risky) {
        flags |= RGUARD_FLAG_RISKY;
        backup_rc = do_backup(cfg, full_path, share_name_of(handle), rel, &st);
        if (backup_rc == RGUARD_OK) flags |= RGUARD_FLAG_BACKED_UP;
        else flags |= RGUARD_FLAG_BACKUP_FAILED;
        GF_DEBUG(0, ("gfrguard: openat backup rc=%d for '%s'\n",
                     backup_rc, rel));
    }

    if (risky && backup_rc != RGUARD_OK && cfg->mode == GFR_MODE_STRICT) {
        int ev_errno = errno;
        send_event(cfg, handle, RGUARD_OP_WRITE, flags, rel, NULL, &st);
        errno = ev_errno;
        GF_DEBUG(0, ("gfrguard: openat backup FAILED (strict) deny '%s'\n", rel));
        errno = ENOSPC;
        return -1;
    }

    /* Restore errno before calling next VFS module. */
    errno = saved_errno;

    int result = SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);

    /* Attach per-file state only after successful open and only for risky files. */
    if (result >= 0 && risky) {
        struct rguard_file_state *fst = (struct rguard_file_state *)
            VFS_ADD_FSP_EXTENSION(handle, fsp, struct rguard_file_state, NULL);
        if (fst) {
            memset(fst, 0, sizeof(*fst));
            fst->is_risky      = true;
            fst->backup_done   = (backup_rc == RGUARD_OK);
            fst->backup_failed = (backup_rc != RGUARD_OK);
            snprintf(fst->session_key,   sizeof(fst->session_key),   "%s", skey);
            snprintf(fst->share_name,    sizeof(fst->share_name),    "%s", share_name_of(handle));
            snprintf(fst->relative_path, sizeof(fst->relative_path), "%s", rel);
            /* Store backup_path for close-time content comparison. */
            if (fst->backup_done) {
                compute_backup_path(cfg, share_name_of(handle), rel,
                                    fst->backup_path, sizeof(fst->backup_path));
            }
        }
    }

    /* Send event — preserve errno so Samba sees the correct value. */
    int post_errno = errno;
    if (risky) {
        send_event(cfg, handle, RGUARD_OP_WRITE, flags, rel, NULL, &st);
    } else if (!exists && (oflags & O_CREAT) && result >= 0) {
        /* New file creation — track for cleanup on restore.
         * VFS no longer checks ransomware extensions here; daemon
         * does that centrally from its policy. */
        uint16_t nf_flags = RGUARD_FLAG_NEW_FILE;

        send_event(cfg, handle, RGUARD_OP_OPEN, nf_flags, rel, NULL, NULL);

        /* Track ALL new files so CLOSE is sent for daemon-side
         * YARA / entropy analysis.  (backup_done is set true but
         * backup_path stays empty — nothing to back up, and the
         * close-time CONTENT_SAME check is skipped.) */
        struct rguard_file_state *nfst = (struct rguard_file_state *)
            VFS_ADD_FSP_EXTENSION(handle, fsp, struct rguard_file_state, NULL);
        if (nfst) {
            memset(nfst, 0, sizeof(*nfst));
            nfst->is_risky      = true;
            nfst->backup_done   = true;   /* no backup needed for new files */
            nfst->backup_failed = false;
            snprintf(nfst->session_key,   sizeof(nfst->session_key),   "%s", skey);
            snprintf(nfst->share_name,    sizeof(nfst->share_name),    "%s", share_name_of(handle));
            snprintf(nfst->relative_path, sizeof(nfst->relative_path), "%s", rel);
        }
    }
    errno = post_errno;

    return result;
}

static ssize_t gf_pwrite(vfs_handle_struct *handle, files_struct *fsp,
                         const void *data, size_t n, off_t offset)
{
    struct gfrguard_config *cfg = get_cfg(handle);
    if (!cfg || !cfg->protect) {
        return SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
    }

    struct rguard_file_state *fst = (struct rguard_file_state *)
        VFS_FETCH_FSP_EXTENSION(handle, fsp);

    /* If file is not risky or backup already handled, just pass through.
     * But always check blocked — session may have been blocked since openat. */
    if (!fst || !fst->is_risky) {
        return SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
    }

    /* Check if session was blocked since open. */
    if (is_blocked(cfg, handle)) {
        errno = EACCES;
        return -1;
    }

    /* Backup already done at openat — no need to send duplicate RISKY events. */
    if (fst->backup_done) {
        return SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
    }

    uint16_t flags = RGUARD_FLAG_RISKY;
    enum gf_defer_rc drc = gf_deferred_backup(cfg, handle, fsp, fst,
                                              RGUARD_OP_WRITE, &flags);
    if (drc == GF_DEFER_DENY)
        return -1;
    if (drc == GF_DEFER_UNRESOLVED) {
        /* Still can't resolve — skip backup but don't mark failed. */
        GF_DEBUG(0, ("gfrguard: pwrite cannot resolve path, skip backup\n"));
        return SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
    }
    ssize_t r = SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
    int pw_errno = errno;
    /* One WRITE event per file handle — in permissive mode a failed
     * backup must not turn every pwrite of a large file into another
     * RISKY event (thousands per file flood the scoring window and the
     * datagram buffer). */
    if (!fst->event_sent) {
        fst->event_sent = true;
        send_event(cfg, handle, RGUARD_OP_WRITE, flags,
                   fst->relative_path, NULL, NULL);
    }
    errno = pw_errno;
    return r;
}

static int gf_ftruncate(vfs_handle_struct *handle, files_struct *fsp, off_t len)
{
    struct gfrguard_config *cfg = get_cfg(handle);
    if (!cfg || !cfg->protect) {
        return SMB_VFS_NEXT_FTRUNCATE(handle, fsp, len);
    }
    struct rguard_file_state *fst = (struct rguard_file_state *)
        VFS_FETCH_FSP_EXTENSION(handle, fsp);

    /* ftruncate on an untracked file (no FSP or not marked risky at open).
     * This catches O_APPEND evasion: open("file", O_WRONLY|O_APPEND) passes
     * the openat risky check (append doesn't overwrite), then ftruncate(0)
     * silently destroys all data.  ftruncate is inherently destructive —
     * always treat it as a potential attack vector regardless of open flags. */
    if (!fst || !fst->is_risky) {
        const char *rel = (fsp && fsp->fsp_name && fsp->fsp_name->base_name)
                          ? fsp->fsp_name->base_name : NULL;
        if (!rel || strncmp(rel, "/proc/", 6) == 0) {
            return SMB_VFS_NEXT_FTRUNCATE(handle, fsp, len);
        }

        char skey[RGUARD_SESSION_KEY_LEN];
        rguard_make_session_key(skey, sizeof(skey),
                         session_user(handle), session_ip(handle));
        if (is_blocked(cfg, handle)) {
            errno = EACCES;
            return -1;
        }

        char full[RGUARD_PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", handle->conn->connectpath, rel);
        struct stat st;
        if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) {
            return SMB_VFS_NEXT_FTRUNCATE(handle, fsp, len);
        }

        const char *share = share_name_of(handle);
        int backup_rc = do_backup(cfg, full, share, rel, &st);
        uint16_t flags = RGUARD_FLAG_RISKY;
        if (backup_rc == RGUARD_OK) flags |= RGUARD_FLAG_BACKED_UP;
        else flags |= RGUARD_FLAG_BACKUP_FAILED;

        /* Attach FSP so pwrite skips duplicate events and close sends
         * CLOSE for YARA scan. */
        fst = (struct rguard_file_state *)
            VFS_ADD_FSP_EXTENSION(handle, fsp, struct rguard_file_state, NULL);
        if (fst) {
            memset(fst, 0, sizeof(*fst));
            fst->is_risky      = true;
            fst->backup_done   = (backup_rc == RGUARD_OK);
            fst->backup_failed = (backup_rc != RGUARD_OK);
            snprintf(fst->session_key,   sizeof(fst->session_key),   "%s", skey);
            snprintf(fst->share_name,    sizeof(fst->share_name),    "%s", share);
            snprintf(fst->relative_path, sizeof(fst->relative_path), "%s", rel);
            if (fst->backup_done) {
                compute_backup_path(cfg, share, rel,
                                    fst->backup_path, sizeof(fst->backup_path));
            }
        }

        if (backup_rc != RGUARD_OK && cfg->mode == GFR_MODE_STRICT) {
            send_event(cfg, handle, RGUARD_OP_TRUNCATE, flags, rel, NULL, &st);
            errno = ENOSPC;
            return -1;
        }

        int r = SMB_VFS_NEXT_FTRUNCATE(handle, fsp, len);
        int ft_errno = errno;
        send_event(cfg, handle, RGUARD_OP_TRUNCATE, flags, rel, NULL, NULL);
        errno = ft_errno;
        return r;
    }

    /* Check if session was blocked since open. */
    if (is_blocked(cfg, handle)) {
        errno = EACCES;
        return -1;
    }

    /* If backup already done at openat, no need to send another RISKY event
     * for the ftruncate — the file is already protected. */
    if (fst->backup_done) {
        return SMB_VFS_NEXT_FTRUNCATE(handle, fsp, len);
    }

    uint16_t flags = RGUARD_FLAG_RISKY;
    enum gf_defer_rc drc = gf_deferred_backup(cfg, handle, fsp, fst,
                                              RGUARD_OP_TRUNCATE, &flags);
    if (drc == GF_DEFER_DENY)
        return -1;
    int r = SMB_VFS_NEXT_FTRUNCATE(handle, fsp, len);
    int ft_errno = errno;
    send_event(cfg, handle, RGUARD_OP_TRUNCATE, flags,
               fst->relative_path, NULL, NULL);
    errno = ft_errno;
    return r;
}

#if SMB_VFS_INTERFACE_VERSION >= 50
static int gf_renameat(vfs_handle_struct *handle,
                       files_struct *srcfsp,
                       const struct smb_filename *smb_fname_src,
                       files_struct *dstfsp,
                       const struct smb_filename *smb_fname_dst,
                       const struct vfs_rename_how *how)
#else
static int gf_renameat(vfs_handle_struct *handle,
                       files_struct *srcfsp,
                       const struct smb_filename *smb_fname_src,
                       files_struct *dstfsp,
                       const struct smb_filename *smb_fname_dst)
#endif
{
    struct gfrguard_config *cfg = get_cfg(handle);
#if SMB_VFS_INTERFACE_VERSION >= 50
    (void)how;
#endif
    if (!cfg || !cfg->protect) {
#if SMB_VFS_INTERFACE_VERSION >= 50
        return SMB_VFS_NEXT_RENAMEAT(handle, srcfsp, smb_fname_src,
                                     dstfsp, smb_fname_dst, how);
#else
        return SMB_VFS_NEXT_RENAMEAT(handle, srcfsp, smb_fname_src,
                                     dstfsp, smb_fname_dst);
#endif
    }
    char skey[RGUARD_SESSION_KEY_LEN];
    rguard_make_session_key(skey, sizeof(skey),
                     session_user(handle), session_ip(handle));
    if (is_blocked(cfg, handle)) {
        GF_DEBUG(0, ("gfrguard: renameat BLOCKED '%s'\n", skey));
        errno = EACCES; return -1;
    }

    const char *src_raw = fname_str(smb_fname_src);
    const char *dst_raw = fname_str(smb_fname_dst);

    /* Copy strings before SMB_VFS_NEXT_RENAMEAT — Samba may modify the
     * underlying smb_filename buffers during the lower-level rename. */
    char src[RGUARD_PATH_MAX], dst[RGUARD_PATH_MAX];
    snprintf(src, sizeof(src), "%s", src_raw);
    snprintf(dst, sizeof(dst), "%s", dst_raw);
	GF_DEBUG(0, ("gfrguard: renameat raw '%s' => '%s'\n", src_raw, dst_raw));
    GF_DEBUG(0, ("gfrguard: renameat '%s' => '%s'\n", src, dst));

    /* Flags (EXT_CHANGE, RANSOM_EXT) are determined by the daemon
     * centrally — VFS just sends the raw rename event. */
    uint16_t flags = 0;

#if SMB_VFS_INTERFACE_VERSION >= 50
    int r = SMB_VFS_NEXT_RENAMEAT(handle, srcfsp, smb_fname_src,
                                  dstfsp, smb_fname_dst, how);
#else
    int r = SMB_VFS_NEXT_RENAMEAT(handle, srcfsp, smb_fname_src,
                                  dstfsp, smb_fname_dst);
#endif
    int rn_errno = errno;
	GF_DEBUG(0, ("gfrguard: SMB_VFS_NEXT_RENAMEAT '%s' => '%s'\n", src_raw, dst_raw));
    send_event(cfg, handle, RGUARD_OP_RENAME, flags, src, dst, NULL);
    errno = rn_errno;
    return r;
}

static int gf_unlinkat(vfs_handle_struct *handle,
                       struct files_struct *dirfsp,
                       const struct smb_filename *smb_fname,
                       int flags)
{
    struct gfrguard_config *cfg = get_cfg(handle);
    if (!cfg || !cfg->protect) {
        return SMB_VFS_NEXT_UNLINKAT(handle, dirfsp, smb_fname, flags);
    }
    char skey[RGUARD_SESSION_KEY_LEN];
    rguard_make_session_key(skey, sizeof(skey),
                     session_user(handle), session_ip(handle));
    if (is_blocked(cfg, handle)) {
        GF_DEBUG(0, ("gfrguard: unlinkat BLOCKED '%s'\n", skey));
        errno = EACCES; return -1;
    }

    const char *rel = fname_str(smb_fname);
    GF_DEBUG(0, ("gfrguard: unlinkat '%s'\n", rel));

    /* Backup the file before deletion so it can be restored. */
    uint16_t ev_flags = 0;
    char full_path[RGUARD_PATH_MAX];
    snprintf(full_path, sizeof(full_path), "%s/%s",
             handle->conn->connectpath, rel);
    struct stat st;
    if (stat(full_path, &st) == 0 && S_ISREG(st.st_mode)) {
        ev_flags |= RGUARD_FLAG_RISKY;
        int brc = do_backup(cfg, full_path, share_name_of(handle), rel, &st);
        if (brc == RGUARD_OK) {
            ev_flags |= RGUARD_FLAG_BACKED_UP;
        } else {
            ev_flags |= RGUARD_FLAG_BACKUP_FAILED;
            if (cfg->mode == GFR_MODE_STRICT) {
                send_event(cfg, handle, RGUARD_OP_DELETE, ev_flags,
                           rel, NULL, &st);
                errno = EACCES;
                return -1;
            }
        }
    }

    int r = SMB_VFS_NEXT_UNLINKAT(handle, dirfsp, smb_fname, flags);
    int ul_errno = errno;
    send_event(cfg, handle, RGUARD_OP_DELETE, ev_flags, rel, NULL,
               (ev_flags & RGUARD_FLAG_RISKY) ? &st : NULL);
    errno = ul_errno;
    return r;
}

static int gf_close(vfs_handle_struct *handle, files_struct *fsp)
{
    struct gfrguard_config *cfg = get_cfg(handle);
    if (!cfg || !cfg->protect) {
        return SMB_VFS_NEXT_CLOSE(handle, fsp);
    }
    struct rguard_file_state *fst = (struct rguard_file_state *)
        VFS_FETCH_FSP_EXTENSION(handle, fsp);

    uint16_t close_flags = 0;

    /* Content hash dedup: compare backup with current file on close.
     * If content is identical, the write was a no-op overwrite (same data),
     * so send CONTENT_SAME flag to let daemon reduce modified_count. */
    if (fst && fst->backup_done && fst->backup_path[0] != '\0' &&
        fst->relative_path[0] != '\0') {
        char cur_path[RGUARD_PATH_MAX];
        int w = snprintf(cur_path, sizeof(cur_path), "%s/%s",
                         handle->conn->connectpath, fst->relative_path);

        /* Overflow: skip the comparison, keep the modified_count —
         * a false positive beats comparing against the wrong file. */
        bool same = false;
        if (w >= 0 && (size_t)w < sizeof(cur_path)) {
            become_root();
            struct stat st_bk, st_cur;
            /* Sizes must match, and the file must be small enough that a
            * two-pass full read won't stall the SMB session — comparing a
            * multi-GB file inline costs 2× its size in disk I/O while the
            * client waits on close.  Large files keep their modified_count
            * (a rare false positive beats a blocked session). */
            if (stat(fst->backup_path, &st_bk) == 0 &&
                stat(cur_path, &st_cur) == 0 &&
                st_bk.st_size == st_cur.st_size &&
                st_bk.st_size <= GFR_CONTENT_COMPARE_MAX) {
                /* Sizes match — compare content with FNV-1a hash. */
                int fd_bk = open(fst->backup_path, O_RDONLY | O_CLOEXEC);
                int fd_cur = open(cur_path, O_RDONLY | O_CLOEXEC);
                if (fd_bk >= 0 && fd_cur >= 0) {
                    uint64_t h_bk = 14695981039346656037ULL;
                    uint64_t h_cur = 14695981039346656037ULL;
                    char buf_bk[8192], buf_cur[8192];
                    ssize_t n_bk, n_cur;
                    same = true;
                    while ((n_bk = read(fd_bk, buf_bk, sizeof(buf_bk))) > 0) {
                        n_cur = read(fd_cur, buf_cur, sizeof(buf_cur));
                        if (n_cur != n_bk) { same = false; break; }
                        for (ssize_t i = 0; i < n_bk; i++) {
                            h_bk ^= (unsigned char)buf_bk[i];
                            h_bk *= 1099511628211ULL;
                            h_cur ^= (unsigned char)buf_cur[i];
                            h_cur *= 1099511628211ULL;
                        }
                    }
                    if (same && h_bk != h_cur) same = false;
                    /* Verify cur file is also at EOF */
                    if (same) {
                        n_cur = read(fd_cur, buf_cur, 1);
                        if (n_cur != 0) same = false;
                    }
                }
                if (fd_bk >= 0) close(fd_bk);
                if (fd_cur >= 0) close(fd_cur);
            }
            unbecome_root();
        }

        if (same) {
            close_flags |= RGUARD_FLAG_CONTENT_SAME;
            GF_DEBUG(0, ("gfrguard: close CONTENT_SAME '%s'\n",
                         fst->relative_path));
        }
    }

    /* Send CLOSE event for every tracked (is_risky) file so the daemon can
     * run YARA / entropy analysis on the final file content.  This covers:
     *   - Overwrite pattern:  backup_done=true  (existing file, backed up)
     *   - Delete+create pattern: backup_done=true, backup_path empty (new
     *     file with RANSOM_EXT — nothing to back up, but close-time YARA
     *     scan inspects the encrypted content)
     *   - Failed backup (permissive): backup_done=false, backup_failed=true
     * Untracked closes (dir handles, metadata reads, read-only files) are
     * skipped — they never have an FSP extension attached. */
    if (fst && fst->is_risky) {
        int cl_errno = errno;
        send_event(cfg, handle, RGUARD_OP_CLOSE, close_flags,
                   fst->relative_path, NULL, NULL);
        errno = cl_errno;
    }
    return SMB_VFS_NEXT_CLOSE(handle, fsp);
}

static int gf_mkdirat(vfs_handle_struct *handle,
                      struct files_struct *dirfsp,
                      const struct smb_filename *smb_fname,
                      mode_t mode)
{
    struct gfrguard_config *cfg = get_cfg(handle);
    if (!cfg || !cfg->protect) {
        return SMB_VFS_NEXT_MKDIRAT(handle, dirfsp, smb_fname, mode);
    }

    char skey[RGUARD_SESSION_KEY_LEN];
    rguard_make_session_key(skey, sizeof(skey),
                     session_user(handle), session_ip(handle));
    if (is_blocked(cfg, handle)) {
        GF_DEBUG(0, ("gfrguard: mkdirat BLOCKED '%s'\n", skey));
        errno = EACCES;
        return -1;
    }

    int r = SMB_VFS_NEXT_MKDIRAT(handle, dirfsp, smb_fname, mode);
    if (r == 0) {
        /* Track new directory for cleanup on restore. */
        const char *rel = fname_str(smb_fname);
        uint16_t flags = RGUARD_FLAG_NEW_FILE;
        send_event(cfg, handle, RGUARD_OP_OPEN, flags, rel, NULL, NULL);
    }
    return r;
}

/* ---------- registration ---------- */

static struct vfs_fn_pointers vfs_gfrguard_fns = {
    .connect_fn    = gf_connect,
    .disconnect_fn = gf_disconnect,
    .openat_fn     = gf_openat,
    .pwrite_fn     = gf_pwrite,
    .ftruncate_fn  = gf_ftruncate,
    .renameat_fn   = gf_renameat,
    .unlinkat_fn   = gf_unlinkat,
    .mkdirat_fn    = gf_mkdirat,
    .close_fn      = gf_close,
};

NTSTATUS samba_init_module(TALLOC_CTX *ctx)
{
	(void)ctx;
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "gfrguard",
				&vfs_gfrguard_fns);
}
