/*
 * gfrguardd_fanotify.c — Common fanotify infrastructure.
 *
 * Two fanotify fds:
 *   g_fan_fd        FAN_CLASS_CONTENT → FAN_OPEN_PERM → perm pthread
 *   g_fan_notify_fd FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME
 *                   → CLOSE_WRITE/MODIFY/CREATE/DELETE/RENAME → main thread
 *
 * The perm thread handles FAN_OPEN_PERM quickly (backup + ALLOW/DENY)
 * and queues events to the main thread via a SOCK_DGRAM socketpair for
 * process_msg.  This avoids deadlock: when the main thread's
 * YARA/entropy scans open monitored files, the resulting FAN_OPEN_PERM
 * is handled by the perm thread independently.
 *
 * The notify fd is a FID group: dirent events (CREATE/DELETE/RENAME)
 * require it, and ALL its events carry a parent-dir file handle + name
 * instead of an open fd.  Paths are reconstructed via open_by_handle_at
 * on a per-channel mount fd.  The permission group must not use FID
 * reporting flags: the kernel rejects FID reporting with
 * FAN_CLASS_CONTENT and rejects permission masks on a FID group.
 *
 * Marks are per-directory inode marks, applied recursively: channel
 * setup walks the tree with nftw; new directories are marked from their
 * CREATE/RENAME events before handler dispatch.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "gfrguardd_fanotify.h"
#include "gfrguardd_fangate.h"
#include "gfrguardd_session.h"
#include "../common/rguard_protocol.h"
#include "../common/rguard_backup.h"
#include "../common/rguard_config.h"
#include "../common/rguard_errors.h"
#include "../common/rguard_hash.h"
#include "../common/rguard_log.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <pthread.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/types.h>

extern void process_msg(const struct rguard_event_msg *msg,
                         sqlite3 *db, struct session_table *st,
                         struct rguard_policy *policy,
                         int *daily_seq, time_t *day_anchor);

/* ── module state ─────────────────────────────────────────────────────── */

static int  g_fan_fd        = -1;  /* FAN_CLASS_CONTENT: FAN_OPEN_PERM */
static int  g_fan_notify_fd = -1;  /* FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME */
static int  g_epoll_fd      = -1;
static int  g_pipe_fds[2]   = {-1, -1};  /* perm→main SOCK_DGRAM socketpair */
static pthread_t g_perm_thread;
static volatile int g_perm_quit = 0;

static struct fanotify_channel g_channels[FANOTIFY_MAX_CHANNELS];
static int  g_ch_count = 0;

/* Per-channel runtime state, parallel to g_channels.  Keeps the public
 * fanotify_channel struct (and the ftp/cloud/local modules) unchanged. */
struct fan_channel_rt {
    char   real_path[RGUARD_MONITOR_PATH_LEN]; /* realpath(mark_path) */
    int    mount_fd;   /* O_RDONLY|O_DIRECTORY fd for open_by_handle_at */
    fsid_t fsid;       /* statfs(real_path).f_fsid */
    /* Written by the main thread (setup/retry timer), read by the perm
     * thread (find_channel) — atomic, not a plain bool. */
    _Atomic bool pending;
    bool   is_dir;
};
static struct fan_channel_rt g_chrt[FANOTIFY_MAX_CHANNELS];

static struct fangate g_gate;      /* (session, inode) flood gate */
static int g_need_rewalk = 0;      /* queue overflow → re-walk all trees */

/* Perm mask never changes; notify mask depends on FID support. */
#define FAN_GFR_PERM_MASK   (FAN_OPEN_PERM | FAN_EVENT_ON_CHILD)
#define FAN_GFR_NOTIFY_MASK (FAN_CLOSE_WRITE | FAN_MODIFY | FAN_CREATE | \
                             FAN_DELETE | FAN_RENAME | \
                             FAN_ONDIR | FAN_EVENT_ON_CHILD)

static struct sqlite3       *g_db         = NULL;
static struct session_table *g_sessions   = NULL;
static struct rguard_policy *g_policy     = NULL;
static int                  *g_daily_seq  = NULL;
static time_t               *g_day_anchor = NULL;

/* ── helpers ──────────────────────────────────────────────────────────── */

int fanotify_resolve_path(int event_fd, char *out, size_t out_len)
{
    if (!out || out_len == 0) return -1;
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", event_fd);
    ssize_t n = readlink(link, out, out_len - 1);
    if (n < 0) return -1;
    if ((size_t)n >= out_len - 1) return -1;   /* truncated — unusable */
    out[n] = '\0';
    return 0;
}

static int path_prefix_match(const char *path, const char *prefix)
{
    size_t plen = strlen(prefix);
    if (strncmp(path, prefix, plen) != 0) return 0;
    return (path[plen] == '\0' || path[plen] == '/') ? (int)plen : 0;
}

static struct fanotify_channel *find_channel(const char *path)
{
    struct fanotify_channel *best = NULL;
    int best_len = 0;
    for (int i = 0; i < g_ch_count; i++) {
        if (g_chrt[i].pending) continue;
        /* Match against the canonical path — events resolve through
         * /proc or file handles, which never contain symlinks. */
        const char *mp = g_chrt[i].real_path[0] ? g_chrt[i].real_path
                                                : g_channels[i].mark_path;
        if (!mp) continue;
        int m = path_prefix_match(path, mp);
        if (m > best_len) { best_len = m; best = &g_channels[i]; }
    }
    return best;
}

static void write_fanotify_response(int event_fd, enum fan_action resp)
{
    /* = {0} first: designated init zeroes members but not padding,
     * and this struct is written straight to the kernel. */
    struct fanotify_response fr = {0};
    fr.fd       = event_fd;
    fr.response = (resp == FAN_RES_ALLOW) ? FAN_ALLOW : FAN_DENY;
    if (g_fan_fd < 0) return;
    ssize_t w = write(g_fan_fd, &fr, sizeof(fr));
    if (w != (ssize_t)sizeof(fr)) {
        /* An unanswered FAN_OPEN_PERM hangs the opening process
         * forever — a failed response write must scream, not be
         * swallowed. */
        char det[96];
        snprintf(det, sizeof(det), "{\"fd\":%d,\"errno\":%d}",
                 event_fd, errno);
        rguard_log_write(LOG_ERROR, "FANOTIFY_RESP_FAILED", NULL, det);
    }
}

/* ── init / destroy ───────────────────────────────────────────────────── */

int fanotify_module_init(int epoll_fd)
{
    /* Do not add FID reporting flags here: FAN_CLASS_CONTENT + FID is
     * rejected by the kernel, which would disable perm protection. */
    g_fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
                              O_RDONLY | O_LARGEFILE);
    if (g_fan_fd < 0) {
        rguard_log_write(LOG_ERROR, "FANOTIFY_INIT_FAILED", NULL, "{}");
        return -1;
    }

    /* FID group: required for dirent events (CREATE/DELETE/RENAME).
     * Event-fd open flags are meaningless here — no fds are returned. */
    g_fan_notify_fd = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC |
                                     FAN_NONBLOCK | FAN_REPORT_DFID_NAME, 0);
    if (g_fan_notify_fd < 0) {
        rguard_log_write(LOG_ERROR, "FANOTIFY_NOTIFY_INIT_FAILED", NULL, "{}");
        close(g_fan_fd); g_fan_fd = -1;
        return -1;
    }

    /* Perm→main event queue.  SOCK_DGRAM socketpair, NOT a pipe:
     * rguard_event_msg (4608 B) exceeds PIPE_BUF (4096), so nonblocking
     * pipe writes could be partial and desync the reader.  Datagrams
     * keep message boundaries at any size. */
    if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                   g_pipe_fds) < 0) {
        rguard_log_write(LOG_ERROR, "FANOTIFY_PIPE_FAILED", NULL, "{}");
        close(g_fan_fd); g_fan_fd = -1;
        close(g_fan_notify_fd); g_fan_notify_fd = -1;
        return -1;
    }

    g_epoll_fd = epoll_fd;

    fangate_init(&g_gate);
    for (int i = 0; i < FANOTIFY_MAX_CHANNELS; i++) {
        memset(&g_chrt[i], 0, sizeof(g_chrt[i]));
        g_chrt[i].mount_fd = -1;
    }

    /* Add notify fd + pipe read end to the main thread's epoll set */
    struct epoll_event ev = { .events = EPOLLIN };
    ev.data.fd = g_fan_notify_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, g_fan_notify_fd, &ev) < 0) {
        rguard_log_write(LOG_ERROR, "EPOLL_ADD_FAILED", NULL,
                         "{\"fd\":\"notify\"}");
        close(g_fan_fd); g_fan_fd = -1;
        close(g_fan_notify_fd); g_fan_notify_fd = -1;
        close(g_pipe_fds[0]); close(g_pipe_fds[1]);
        return -1;
    }
    ev.data.fd = g_pipe_fds[0];
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, g_pipe_fds[0], &ev) < 0) {
        rguard_log_write(LOG_ERROR, "EPOLL_ADD_FAILED", NULL,
                         "{\"fd\":\"queue\"}");
        close(g_fan_fd); g_fan_fd = -1;
        close(g_fan_notify_fd); g_fan_notify_fd = -1;
        close(g_pipe_fds[0]); close(g_pipe_fds[1]);
        return -1;
    }

    {
        char det[128];
        snprintf(det, sizeof(det),
                 "{\"perm_fd\":%d,\"notify_fd\":%d}",
                 g_fan_fd, g_fan_notify_fd);
        rguard_log_write(LOG_INFO, "FANOTIFY_INIT_OK", NULL, det);
    }
    return 0;
}

void fanotify_module_destroy(void)
{
    fanotify_stop_perm_thread();

    /* Tree marks cannot be enumerated per path — flush each group.
     * (FAN_MARK_FLUSH removes all inode marks; path args are ignored.) */
    if (g_fan_fd >= 0)
        fanotify_mark(g_fan_fd, FAN_MARK_FLUSH, 0, AT_FDCWD, NULL);
    if (g_fan_notify_fd >= 0)
        fanotify_mark(g_fan_notify_fd, FAN_MARK_FLUSH, 0, AT_FDCWD, NULL);

    if (g_fan_fd >= 0)       { close(g_fan_fd); g_fan_fd = -1; }
    if (g_fan_notify_fd >= 0) {
        epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, g_fan_notify_fd, NULL);
        close(g_fan_notify_fd); g_fan_notify_fd = -1;
    }
    if (g_pipe_fds[0] >= 0) {
        epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, g_pipe_fds[0], NULL);
        close(g_pipe_fds[0]); g_pipe_fds[0] = -1;
        close(g_pipe_fds[1]); g_pipe_fds[1] = -1;
    }
    fanotify_channels_clear();
}

/* ── mark management ──────────────────────────────────────────────────── */

int fanotify_mark_add(const char *path)
{
    if (!path) return -1;
    int err = 0;

    if (g_fan_fd >= 0 &&
        fanotify_mark(g_fan_fd, FAN_MARK_ADD, FAN_GFR_PERM_MASK,
                      AT_FDCWD, path) < 0) {
        err = errno;
        if (err != ENOSPC) {  /* ENOSPC is aggregated by the tree walker */
            char det[512];
            snprintf(det, sizeof(det),
                     "{\"path\":\"%s\",\"errno\":%d,\"fd\":\"perm\"}", path, err);
            rguard_log_write(LOG_ERROR, "FANOTIFY_MARK_FAILED", NULL, det);
        }
    }

    if (g_fan_notify_fd >= 0) {
        if (fanotify_mark(g_fan_notify_fd, FAN_MARK_ADD, FAN_GFR_NOTIFY_MASK,
                          AT_FDCWD, path) < 0) {
            err = errno;
            if (err != ENOSPC) {
                char det[512];
                snprintf(det, sizeof(det),
                         "{\"path\":\"%s\",\"errno\":%d,\"fd\":\"notify\"}",
                         path, err);
                rguard_log_write(LOG_ERROR, "FANOTIFY_MARK_FAILED", NULL, det);
            }
        }
    }

    if (err) { errno = err; return -1; }
    return 0;
}

void fanotify_mark_remove(const char *path)
{
    /* Single directory only — tree-wide removal is FAN_MARK_FLUSH
     * (see fanotify_module_destroy / fanotify_reload_marks). */
    if (!path) return;
    if (g_fan_fd >= 0)
        fanotify_mark(g_fan_fd, FAN_MARK_REMOVE, FAN_GFR_PERM_MASK,
                      AT_FDCWD, path);
    if (g_fan_notify_fd >= 0)
        fanotify_mark(g_fan_notify_fd, FAN_MARK_REMOVE,
                      FAN_GFR_NOTIFY_MASK,
                      AT_FDCWD, path);
}

/* ── recursive tree marks ─────────────────────────────────────────────── */

/* Walk context — MAIN THREAD ONLY (setup runs before the perm thread
 * starts; runtime calls come only from the notify drain). */
static int g_walk_marked, g_walk_enospc;

static int mark_tree_cb(const char *fpath, const struct stat *sb,
                        int typeflag, struct FTW *ftwbuf)
{
    (void)sb; (void)ftwbuf;
    if (typeflag != FTW_D) return 0;
    if (fanotify_mark_add(fpath) == 0) g_walk_marked++;
    else if (errno == ENOSPC)          g_walk_enospc++;
    return 0;  /* never abort the walk */
}

int fanotify_mark_tree_add(const char *root_dir)
{
    if (!root_dir) return -1;
    g_walk_marked = g_walk_enospc = 0;
    /* FTW_PHYS: symlink escapes would break fsid→channel resolution.
     * FTW_MOUNT: sub-mounts have a foreign fsid — cannot be resolved. */
    nftw(root_dir, mark_tree_cb, 32, FTW_PHYS | FTW_MOUNT);
    if (g_walk_enospc) {
        char det[600];
        snprintf(det, sizeof(det),
                 "{\"root\":\"%s\",\"failed\":%d,"
                 "\"hint\":\"raise fs.fanotify.max_user_marks\"}",
                 root_dir, g_walk_enospc);
        rguard_log_write(LOG_WARN, "FANOTIFY_MARK_ENOSPC", NULL, det);
    }
    return g_walk_marked;
}

/* ── channel runtime activation ───────────────────────────────────────── */

static int channel_rt_activate(int idx)
{
    struct fan_channel_rt *rt = &g_chrt[idx];
    const char *mp = g_channels[idx].mark_path;

    if (!realpath(mp, rt->real_path)) {
        rt->pending = true;
        char det[512];
        snprintf(det, sizeof(det), "{\"path\":\"%s\",\"errno\":%d}", mp, errno);
        rguard_log_write(LOG_INFO, "FANOTIFY_CHANNEL_PENDING", NULL, det);
        return -1;
    }

    struct stat st;
    if (stat(rt->real_path, &st) != 0) { rt->pending = true; return -1; }
    rt->is_dir = S_ISDIR(st.st_mode);

    /* mount_fd anchors open_by_handle_at for this channel's filesystem:
     * the directory itself, or the parent for a single-file path. */
    if (rt->is_dir) {
        rt->mount_fd = open(rt->real_path,
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    } else {
        char parent[RGUARD_MONITOR_PATH_LEN];
        snprintf(parent, sizeof(parent), "%s", rt->real_path);
        char *sl = strrchr(parent, '/');
        if (sl && sl != parent) *sl = '\0';
        else snprintf(parent, sizeof(parent), "/");
        rt->mount_fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    }
    if (rt->mount_fd < 0) {
        rt->pending = true;
        char det[512];
        snprintf(det, sizeof(det), "{\"path\":\"%.470s\",\"errno\":%d}",
                 rt->real_path, errno);
        rguard_log_write(LOG_ERROR, "FANOTIFY_CHANNEL_SETUP_FAILED", NULL, det);
        return -1;
    }

    struct statfs sfs;
    if (statfs(rt->real_path, &sfs) != 0) {
        close(rt->mount_fd); rt->mount_fd = -1;
        rt->pending = true;
        return -1;
    }
    memcpy(&rt->fsid, &sfs.f_fsid, sizeof(rt->fsid));

    int marked = rt->is_dir ? fanotify_mark_tree_add(rt->real_path)
                            : (fanotify_mark_add(rt->real_path) == 0 ? 1 : 0);
    rt->pending = false;

    {
        char det[600];
        snprintf(det, sizeof(det), "{\"path\":\"%.550s\",\"dirs_marked\":%d}",
                 rt->real_path, marked);
        rguard_log_write(LOG_INFO, "FANOTIFY_CHANNEL_ACTIVE", NULL, det);
    }
    return 0;
}

int fanotify_retry_pending_channels(void)
{
    int activated = 0;
    for (int i = 0; i < g_ch_count; i++)
        if (g_chrt[i].pending && channel_rt_activate(i) == 0)
            activated++;
    return activated;
}

int fanotify_reload_marks(const struct fanotify_channel *channels, int n)
{
    if (g_fan_fd >= 0)
        fanotify_mark(g_fan_fd, FAN_MARK_FLUSH, 0, AT_FDCWD, NULL);
    if (g_fan_notify_fd >= 0)
        fanotify_mark(g_fan_notify_fd, FAN_MARK_FLUSH, 0, AT_FDCWD, NULL);
    fanotify_channels_clear();
    fangate_reset(&g_gate);

    for (int i = 0; i < n && g_ch_count < FANOTIFY_MAX_CHANNELS; i++) {
        if (!channels[i].mark_path) continue;
        fanotify_channel_setup(&channels[i]);
    }
    rguard_log_write(LOG_INFO, "FANOTIFY_MARKS_RELOADED", NULL, "{}");
    return 0;
}

/* ── channel registration ─────────────────────────────────────────────── */

int fanotify_channel_register(const struct fanotify_channel *ch)
{
    if (!ch || !ch->handler || !ch->mark_path) return -1;
    if (g_ch_count >= FANOTIFY_MAX_CHANNELS) return -1;
    int idx = g_ch_count++;
    g_channels[idx] = *ch;
    memset(&g_chrt[idx], 0, sizeof(g_chrt[idx]));
    g_chrt[idx].mount_fd = -1;
    g_chrt[idx].pending  = true;
    return idx;
}

int fanotify_channel_setup(const struct fanotify_channel *ch)
{
    /* Register first, then activate: a missing monitor path stays
     * registered as pending and is retried on the main-loop timer. */
    int idx = fanotify_channel_register(ch);
    if (idx < 0) return -1;
    return channel_rt_activate(idx);
}

void fanotify_channels_clear(void)
{
    for (int i = 0; i < g_ch_count; i++) {
        if (g_chrt[i].mount_fd >= 0) close(g_chrt[i].mount_fd);
        memset(&g_chrt[i], 0, sizeof(g_chrt[i]));
        g_chrt[i].mount_fd = -1;
    }
    g_ch_count = 0;
}

/* ── perm thread ──────────────────────────────────────────────────────── */

static int fanotify_drain_perm(void)
{
    int fd = g_fan_fd;
    /* Drain even with zero channels: a reload may leave FAN_OPEN_PERM
     * marks behind, and an unanswered perm event hangs the opening
     * process forever.  No channel → find_channel returns NULL → the
     * response stays FAN_RES_ALLOW. */
    if (fd < 0) return 0;

    struct {
        struct fanotify_event_metadata hdr;
        char space[4096 - sizeof(struct fanotify_event_metadata)];
    } buf;

    int processed = 0;
    for (;;) {
        ssize_t nr = read(fd, &buf, sizeof(buf));
        if (nr <= 0) break;

        const char *ptr = (const char *)&buf;
        const char *end = ptr + nr;

        while (ptr < end) {
            const struct fanotify_event_metadata *meta =
                (const struct fanotify_event_metadata *)ptr;
            if (meta->event_len < sizeof(*meta)) break;
            if (ptr + meta->event_len > end) break;

            struct fanotify_event ev = {0};
            ev.mask     = meta->mask;
            ev.event_fd = meta->fd;
            ev.pid      = meta->pid;

            if (fanotify_resolve_path(meta->fd, ev.path, sizeof(ev.path)) < 0) {
                if (meta->mask & FAN_OPEN_PERM)
                    write_fanotify_response(meta->fd, FAN_RES_ALLOW);
                if (meta->fd >= 0) close(meta->fd);
                ptr += meta->event_len;
                continue;
            }

            struct fanotify_channel *ch = find_channel(ev.path);
            enum fan_action resp = FAN_RES_ALLOW;
            if (ch && ch->handler)
                resp = ch->handler(&ev, ch->mark_path, ch->user_data);

            if (meta->mask & FAN_OPEN_PERM)
                write_fanotify_response(meta->fd, resp);

            if (meta->fd >= 0) close(meta->fd);
            processed++;
            ptr += meta->event_len;
        }
    }
    return processed;
}

static void *perm_thread_fn(void *arg)
{
    (void)arg;

    int ep = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = g_fan_fd };
    epoll_ctl(ep, EPOLL_CTL_ADD, g_fan_fd, &ev);

    rguard_log_write(LOG_INFO, "FANOTIFY_PERM_THREAD_START", NULL, "{}");

    while (!g_perm_quit) {
        struct epoll_event evs[1];
        int n = epoll_wait(ep, evs, 1, 500);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n > 0) fanotify_drain_perm();
    }

    close(ep);
    rguard_log_write(LOG_INFO, "FANOTIFY_PERM_THREAD_STOP", NULL, "{}");
    return NULL;
}

int fanotify_start_perm_thread(void)
{
    g_perm_quit = 0;
    int rc = pthread_create(&g_perm_thread, NULL, perm_thread_fn, NULL);
    if (rc != 0) {
        {
            char det[48];
            snprintf(det, sizeof(det), "{\"errno\":%d}", rc);
            rguard_log_write(LOG_ERROR, "FANOTIFY_THREAD_FAILED", NULL, det);
        }
        return -1;
    }
    return 0;
}

void fanotify_stop_perm_thread(void)
{
    g_perm_quit = 1;
    if (g_perm_thread) {
        void *ret = NULL;
        pthread_join(g_perm_thread, &ret);
        g_perm_thread = 0;
    }
}

/* ── event queue (perm thread → main thread) ─────────────────────────── */

void fanotify_queue_event(const struct rguard_event_msg *msg)
{
    if (g_pipe_fds[1] < 0 || !msg) return;
    ssize_t w = write(g_pipe_fds[1], msg, sizeof(*msg));
    if (w != (ssize_t)sizeof(*msg)) {
        /* Queue full or error: the event is dropped — at least count it
         * so a perm-thread flood doesn't vanish silently. */
        static unsigned long dropped;
        if (++dropped % 1000 == 1) {
            char det[64];
            snprintf(det, sizeof(det), "{\"dropped_total\":%lu}", dropped);
            rguard_log_write(LOG_WARN, "EVENT_QUEUE_DROP", NULL, det);
        }
    }
}

int fanotify_get_pipe_fd(void)  { return g_pipe_fds[0]; }
int fanotify_get_notify_fd(void) { return g_fan_notify_fd; }

int fanotify_process_queued(void)
{
    if (g_pipe_fds[0] < 0) return 0;
    struct rguard_event_msg msg;
    ssize_t nr = read(g_pipe_fds[0], &msg, sizeof(msg));
    if (nr != (ssize_t)sizeof(msg)) return (nr < 0 && errno == EAGAIN) ? 0 : -1;

    process_msg(&msg, g_db, g_sessions, g_policy, g_daily_seq, g_day_anchor);
    return 1;
}

/* ── notify event dispatch (main thread) ─────────────────────────────── */

/* ── FID drain: path reconstruction + dispatch ──────────────────────── */

static void dispatch_one(uint64_t mask, pid_t pid,
                         const char *path, const char *new_path)
{
    struct fanotify_event ev = {0};
    ev.mask     = mask;
    ev.event_fd = -1;
    ev.pid      = pid;
    snprintf(ev.path, sizeof(ev.path), "%s", path);
    if (new_path) {
        snprintf(ev.new_path, sizeof(ev.new_path), "%s", new_path);
        const char *new_name = strrchr(new_path, '/');
        snprintf(ev.new_name, sizeof(ev.new_name), "%s",
                 new_name ? new_name + 1 : new_path);
    }

    struct fanotify_channel *ch = find_channel(ev.path);
    if (ch && ch->handler)
        ch->handler(&ev, ch->mark_path, ch->user_data);
}

/* Decompose a (possibly kernel-merged) mask into single-op dispatches. */
static void dispatch_notify(uint64_t mask, pid_t pid,
                            const char *full)
{
    uint64_t ondir = mask & FAN_ONDIR;

    static const uint64_t op_bits[] =
        { FAN_CREATE, FAN_MODIFY, FAN_CLOSE_WRITE, FAN_DELETE };
    for (size_t i = 0; i < sizeof(op_bits) / sizeof(op_bits[0]); i++)
        if (mask & op_bits[i])
            dispatch_one(op_bits[i] | ondir, pid, full, NULL);
}

static const struct fanotify_event_info_fid *
find_name_record(const struct fanotify_event_metadata *meta, uint8_t info_type)
{
    size_t off = meta->metadata_len;
    while (off + sizeof(struct fanotify_event_info_header) <= meta->event_len) {
        const struct fanotify_event_info_header *hdr =
            (const struct fanotify_event_info_header *)
                ((const char *)meta + off);
        if (hdr->len < sizeof(*hdr)) break;  /* corrupt record guard */
        if (hdr->info_type == info_type)
            return (const struct fanotify_event_info_fid *)hdr;
        off += hdr->len;
    }
    return NULL;
}

static int channel_index_by_fsid(const __kernel_fsid_t *fsid)
{
    for (int i = 0; i < g_ch_count; i++) {
        if (g_chrt[i].pending || g_chrt[i].mount_fd < 0) continue;
        if (memcmp(&g_chrt[i].fsid, fsid, sizeof(g_chrt[i].fsid)) == 0)
            return i;
    }
    return -1;
}

static int resolve_name_record(const struct fanotify_event_info_fid *fid,
                               char *dirpath, size_t dirpath_len,
                               const char **name)
{
    int ci = channel_index_by_fsid(&fid->fsid);
    if (ci < 0) return -1;

    const struct file_handle *fh = (const struct file_handle *)fid->handle;
    *name = (const char *)fh->f_handle + fh->handle_bytes;

    int dirfd = open_by_handle_at(g_chrt[ci].mount_fd,
                                  (struct file_handle *)fh,
                                  O_RDONLY | O_PATH | O_CLOEXEC);
    if (dirfd < 0) return -1;
    int rc = fanotify_resolve_path(dirfd, dirpath, dirpath_len);
    close(dirfd);
    return rc;
}

static void join_dir_name(char *full, size_t full_len,
                          const char *dirpath, const char *name)
{
    if (name[0] == '.' && name[1] == '\0')
        snprintf(full, full_len, "%s", dirpath);
    else
        snprintf(full, full_len, "%s/%s", dirpath, name);
}

static int process_rename_event(const struct fanotify_event_metadata *meta)
{
    const struct fanotify_event_info_fid *old_fid =
        find_name_record(meta, FAN_EVENT_INFO_TYPE_OLD_DFID_NAME);
    const struct fanotify_event_info_fid *new_fid =
        find_name_record(meta, FAN_EVENT_INFO_TYPE_NEW_DFID_NAME);
    if (!old_fid && !new_fid) return 0;

    char old_dir[RGUARD_PATH_MAX], new_dir[RGUARD_PATH_MAX];
    const char *old_name = NULL, *new_name = NULL;
    bool have_old = old_fid &&
        resolve_name_record(old_fid, old_dir, sizeof(old_dir), &old_name) == 0;
    bool have_new = new_fid &&
        resolve_name_record(new_fid, new_dir, sizeof(new_dir), &new_name) == 0;
    if (!have_old && !have_new) return 0;

    char old_full[RGUARD_PATH_MAX], new_full[RGUARD_PATH_MAX];
    if (have_old)
        join_dir_name(old_full, sizeof(old_full), old_dir, old_name);
    if (have_new)
        join_dir_name(new_full, sizeof(new_full), new_dir, new_name);

    if ((meta->mask & FAN_ONDIR) && have_new)
        fanotify_mark_tree_add(new_full);

    dispatch_one(FAN_RENAME | (meta->mask & FAN_ONDIR),
                 (pid_t)meta->pid, have_old ? old_full : new_full,
                 have_new ? new_full : NULL);
    return 1;
}

/* Handle one FID event.  Returns 1 if dispatched, 0 if skipped. */
static int process_fid_event(const struct fanotify_event_metadata *meta)
{
    /* FID groups deliver FAN_NOFD; close defensively if not. */
    if (meta->fd >= 0) close(meta->fd);

    if (meta->mask & FAN_Q_OVERFLOW) {
        rguard_log_write(LOG_WARN, "FANOTIFY_QUEUE_OVERFLOW", NULL, "{}");
        g_need_rewalk = 1;   /* dirs created in the lost window need marks */
        return 0;
    }
    /* The daemon's own backup/restore writes must not feed scoring. */
    if ((pid_t)meta->pid == getpid()) return 0;

    if (meta->mask & FAN_RENAME)
        return process_rename_event(meta);

    const struct fanotify_event_info_fid *fid =
        find_name_record(meta, FAN_EVENT_INFO_TYPE_DFID_NAME);
    if (!fid) return 0;

    char dirpath[RGUARD_PATH_MAX];
    const char *name;
    if (resolve_name_record(fid, dirpath, sizeof(dirpath), &name) < 0)
        return 0;

    char full[RGUARD_PATH_MAX];
    join_dir_name(full, sizeof(full), dirpath, name);

    /* Mark new directories BEFORE handler dispatch so nothing inside
     * the new tree escapes monitoring. */
    if ((meta->mask & FAN_ONDIR) && (meta->mask & FAN_CREATE))
        fanotify_mark_tree_add(full);

    dispatch_notify(meta->mask, (pid_t)meta->pid, full);
    return 1;
}

static int fanotify_drain_notify(void)
{
    int fd = g_fan_notify_fd;
    if (fd < 0 || g_ch_count == 0) return 0;

    /* FID events are variable-length (metadata + info records, worst
     * case ~420 bytes each) — size for a healthy batch. */
    static char buf[16384] __attribute__((aligned(8)));
    int processed = 0;

    for (;;) {
        ssize_t nr = read(fd, buf, sizeof(buf));
        if (nr <= 0) break;

        const struct fanotify_event_metadata *meta =
            (const struct fanotify_event_metadata *)buf;
        while (FAN_EVENT_OK(meta, nr)) {
            if (meta->vers != FANOTIFY_METADATA_VERSION) {
                rguard_log_write(LOG_ERROR, "FANOTIFY_VERSION_MISMATCH",
                                 NULL, "{}");
                return processed;
            }
            processed += process_fid_event(meta);
            meta = FAN_EVENT_NEXT(meta, nr);
        }
    }


    if (g_need_rewalk) {
        g_need_rewalk = 0;
        for (int i = 0; i < g_ch_count; i++)
            if (!g_chrt[i].pending && g_chrt[i].is_dir &&
                g_chrt[i].real_path[0])
                fanotify_mark_tree_add(g_chrt[i].real_path);
    }
    return processed;
}

int fanotify_poll(void)
{
    return fanotify_drain_notify();
}

/* ── event submission ─────────────────────────────────────────────────── */

bool fanotify_submit_event(const struct rguard_event_msg *msg,
                           const char *session_key)
{
    if (!msg || !g_db || !g_sessions || !g_policy) return false;
    process_msg(msg, g_db, g_sessions, g_policy, g_daily_seq, g_day_anchor);
    struct session_state *s = session_find_or_create(g_sessions, session_key);
    return (s && s->is_blocked);
}

/* ── shared helpers ───────────────────────────────────────────────────── */

bool fanotify_gate_allow(const char *session_key, const char *path,
                         uint8_t source_type)
{
    uint64_t key = path ? rguard_fnv1a64(path, strlen(path)) : 0;
    int window = 0;
    if (g_policy) {
        window = g_policy->scoring.window_short;
        /* Gate window MUST match the channel's scoring window, or a
         * file gets re-counted every global window inside the longer
         * cloud window. */
        if (source_type == RGUARD_SOURCE_CLOUD_SYNC &&
            g_policy->scoring.cloud_window_short > 0)
            window = g_policy->scoring.cloud_window_short;
    }
    /* MONOTONIC, not REALTIME: an NTP step-back would make
     * now - last_sent negative and suppress (session, file) events
     * for far longer than the window. */
    struct timespec tsn;
    clock_gettime(CLOCK_MONOTONIC, &tsn);
    return fangate_allow(&g_gate, session_key, key,
                         (int64_t)tsn.tv_sec, window);
}

int fanotify_do_backup(int src_fd, const char *file_path,
                       const char *store_path, const char *channel_dir)
{
    struct stat st;
    if (fstat(src_fd, &st) < 0) return RGUARD_ERR_BACKUP;

    char bk[RGUARD_PATH_MAX];
    int w = snprintf(bk, sizeof(bk), "%s/backups/%s/%s",
                     store_path, channel_dir, file_path);
    /* Deep paths must fail loudly — a truncated backup path means the
     * copy lands somewhere the DB doesn't know about and restore can
     * never find it. */
    if (w < 0 || (size_t)w >= sizeof(bk)) {
        char det[300];
        snprintf(det, sizeof(det), "{\"path\":\"%.250s\"}", file_path);
        rguard_log_write(LOG_WARN, "BACKUP_PATH_TRUNCATED", NULL, det);
        return RGUARD_ERR_BACKUP;
    }

    {
        char tmp[RGUARD_PATH_MAX], *slash;
        snprintf(tmp, sizeof(tmp), "%s", bk);
        slash = strrchr(tmp, '/');
        if (slash) {
            *slash = '\0';
            char *p = tmp + 1;
            while (*p) {
                if (*p == '/') { *p = '\0'; mkdir(tmp, 0755); *p = '/'; }
                p++;
            }
            mkdir(tmp, 0755);
        }
    }

    int dst_fd = open(bk, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (dst_fd < 0) {
        if (errno == EEXIST) return RGUARD_OK;
        return RGUARD_ERR_BACKUP;
    }

    /* reflink → copy_file_range → read/write (rguard_backup.h) */
    int copy_rc = rguard_copy_fd(src_fd, dst_fd, st.st_size);

    fsync(dst_fd);
    close(dst_fd);

    if (copy_rc != 0) {
        unlink(bk);
        return RGUARD_ERR_BACKUP;
    }
    return RGUARD_OK;
}

void fanotify_build_event_msg(const struct fanotify_event *ev,
                              uint8_t source_type,
                              struct rguard_event_msg *msg)
{
    memset(msg, 0, sizeof(*msg));
    msg->msg_type   = RGUARD_MSG_FILE_EVENT;
    msg->proto_version = RGUARD_PROTO_VERSION;
    msg->source_type = source_type;
    msg->op_type    = RGUARD_OP_OPEN;
    msg->flags      = RGUARD_FLAG_RISKY;
    msg->timestamp  = (int64_t)time(NULL);
    snprintf(msg->file_path, sizeof(msg->file_path), "%s", ev->path);
}

bool fanotify_fill_notify_msg(const struct fanotify_event *ev,
                              const char *session_key,
                              struct rguard_event_msg *msg)
{
    uint64_t op = ev->mask & (FAN_MODIFY | FAN_CREATE | FAN_CLOSE_WRITE |
                              FAN_DELETE | FAN_RENAME);

    /* Stat the destination after rename; the source path is gone. */
    char statpath[RGUARD_PATH_MAX];
    snprintf(statpath, sizeof(statpath), "%s",
             (ev->mask & FAN_RENAME) && ev->new_path[0]
                 ? ev->new_path : ev->path);

    struct stat st;
    bool have_st = (stat(statpath, &st) == 0);
    if (have_st) {  /* DELETE / unpaired FROM: gone, zeroed metadata is fine */
        msg->inode     = (uint64_t)st.st_ino;
        msg->file_size = (uint64_t)st.st_size;
        msg->mtime     = (int64_t)st.st_mtime;
        msg->file_uid  = (uint32_t)st.st_uid;
        msg->file_gid  = (uint32_t)st.st_gid;
        msg->file_mode = (uint32_t)st.st_mode;
    }

    switch (op) {
    case FAN_MODIFY:
        /* One RISKY write per (session, file) per scoring window —
         * matches the VFS module's per-open-handle dedup.  Covers both
         * write() and truncate (ATTR_SIZE raises FS_MODIFY). */
        if (!fanotify_gate_allow(session_key, ev->path, msg->source_type))
            return false;
        msg->op_type = RGUARD_OP_WRITE;
        msg->flags   = RGUARD_FLAG_RISKY;
        break;
    case FAN_CREATE:  /* new file or mkdir — VFS new-file parity */
        msg->op_type = RGUARD_OP_OPEN;
        msg->flags   = RGUARD_FLAG_NEW_FILE;
        break;
    case FAN_DELETE:
        msg->op_type = RGUARD_OP_DELETE;
        msg->flags   = 0;
        break;
    case FAN_RENAME:
        msg->op_type = RGUARD_OP_RENAME;
        msg->flags   = 0;
        snprintf(msg->new_name, sizeof(msg->new_name), "%s", ev->new_name);
        break;
    case FAN_CLOSE_WRITE:
        msg->op_type = RGUARD_OP_CLOSE;   /* YARA / entropy scan entry */
        msg->flags   = 0;
        break;
    default:
        return false;
    }
    return true;
}

void fanotify_set_daemon_ctx(struct sqlite3 *db, struct session_table *st,
                              struct rguard_policy *policy,
                              int *daily_seq, time_t *day_anchor)
{
    g_db = db; g_sessions = st; g_policy = policy;
    g_daily_seq = daily_seq; g_day_anchor = day_anchor;
}

struct sqlite3 *fanotify_get_db(void)              { return g_db; }
struct session_table *fanotify_get_session_table(void) { return g_sessions; }
