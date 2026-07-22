/*
 * gfrguardd_ftp.c — FTP anti-ransomware handler (fanotify).
 *
 * Resolves vsftpd child PID → user@ip via /proc/<pid>/status (UID) and
 * /proc/<pid>/net/tcp (remote IP).  Backs up files from fanotify event_fd,
 * then feeds events into process_msg() for unified scoring/blocking.
 *
 * session_key format: "user@ip" (local user) or "ftp@ip" (anonymous)
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "gfrguardd_ftp.h"
#include "gfrguardd_fanchannel.h"
#include "../common/rguard_protocol.h"
#include "../common/rguard_config.h"
#include "../common/rguard_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <arpa/inet.h>

/* ── /proc PID → session resolution ────────────────────────────────────
 *
 * Strategy (per ftp_approach_evaluation.md §2):
 *
 *   1. PRIMARY — Parse /proc/<pid>/cmdline.
 *      vsftpd rewrites the worker process title (setproctitle_enable=YES,
 *      OFF by default — deployments MUST enable it) to:
 *        vsftpd: <client_ip>: connected            (pre-login)
 *        vsftpd: <client_ip>/<username>: <action>  (post-login)
 *      The IP/user separator is '/', NOT ": " — see vsftpd-3.0.5
 *      privops.c:setup_username_globals() and sysdeputil.c:
 *      vsf_sysutil_setproctitle().  This gives us real IP *and* real
 *      username in one read, including virtual users (which share a
 *      single UID and would be invisible to getpwuid).
 *      Caveat: the title lives in the original argv+env space, so it may
 *      be truncated mid-string; the parser must tolerate that.
 *
 *   2. FALLBACK — socket-inode mapping for IP + /proc/<pid>/status for UID.
 *      Only used when cmdline is unavailable or unparseable.
 *      - Read /proc/<pid>/fd/ → find socket:[inode] symlinks
 *      - Match inode against /proc/<pid>/net/tcp, then /proc/net/tcp
 *        (isolate_network=YES puts the worker in an empty netns while
 *        the socket stays in the listener's netns) → extract remote IP
 *      - Read /proc/<pid>/status → extract UID → getpwuid → username       */

/* Parse vsftpd cmdline: "vsftpd: 1.2.3.4/alice: STOR /path/to/file"
 * The IP/user separator is '/' (vsftpd-3.0.5 privops.c); the action is
 * separated by ": " and is NOT parsed — we only need IP and username.
 * A title truncated inside the username still yields usable data; a
 * pre-login title ("vsftpd: <ip>: connected", no '/') has no username
 * and fails over to the fallback resolvers.
 * Returns 0 on success, -1 on failure. */
static int ftp_parse_cmdline(pid_t pid, char *username, size_t ulen,
                              char *client_ip, size_t iplen)
{
    char path[64], buf[512];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;

    /* cmdline is \0-separated; vsftpd rewrites the first token.
     * Collapse \0 to space for string parsing. */
    for (ssize_t i = 0; i < n - 1; i++)
        if (buf[i] == '\0') buf[i] = ' ';
    buf[n] = '\0';

    /* Debug: log the resolved cmdline for diagnostics (escaped — the
     * cmdline is user-controlled and could break the JSON structure). */
    {
        char head_esc[256];
        rguard_json_escape(head_esc, sizeof(head_esc), buf);
        char det[580];
        snprintf(det, sizeof(det),
                 "{\"pid\":%d,\"cmdline_len\":%zd,\"head\":\"%.120s\"}",
                 pid, n, head_esc);
        rguard_log_write(LOG_DEBUG, "FTP_CMDLINE_READ", NULL, det);
    }

    /* Pattern: "vsftpd: <IP>/<user>[: <action> ...]"
     * Neither IPv4 nor IPv6 addresses contain '/', so the first slash
     * unambiguously splits IP from username. */
    const char *prefix = "vsftpd: ";
    const char *p = buf;
    if (strncmp(p, prefix, strlen(prefix)) != 0) return -1;
    p += strlen(prefix);

    const char *slash = strchr(p, '/');
    if (!slash || slash == p) return -1;   /* pre-login or foreign proctitle */

    size_t ip_len = (size_t)(slash - p);
    if (ip_len >= iplen) return -1;        /* truncated title cut the IP */
    memcpy(client_ip, p, ip_len);
    client_ip[ip_len] = '\0';

    /* Username: from '/' to the ": " before the action, or to end of
     * string when truncation ate the action separator. */
    const char *user_start = slash + 1;
    const char *user_end = strstr(user_start, ": ");
    if (!user_end) user_end = user_start + strlen(user_start);
    size_t user_len = (size_t)(user_end - user_start);
    if (user_len == 0 || user_len >= ulen) return -1;
    memcpy(username, user_start, user_len);
    username[user_len] = '\0';

    return 0;
}

/* Pure parser: scan /proc/net/tcp(6) text for a line whose inode matches
 * one of inodes[] and format its remote address.
 *
 * v4: address is host-order hex of the little-endian wire value —
 *     "0100007F" is 127.0.0.1, printed from the low byte up.
 * v6: 32 hex chars = 4 × 32-bit words, each word's bytes reversed
 *     ("00000000000000000000000001000000" is ::1).
 *
 * Returns 0 on match, -1 when no line matches. */
int ftp_tcp_find_remote(const char *text, const unsigned long *inodes,
                        int ninode, char *ip_out, size_t iplen)
{
    const char *lp = strchr(text, '\n');  /* skip header */
    if (!lp) return -1;
    lp++;

    while (*lp) {
        char line[384];
        const char *eol = strchr(lp, '\n');
        size_t llen = eol ? (size_t)(eol - lp) : strlen(lp);
        if (llen >= sizeof(line)) llen = sizeof(line) - 1;
        memcpy(line, lp, llen); line[llen] = '\0';

        /* sl local rem st txq:rxq tr:when retr uid timeout inode */
        char rem[80] = "";
        unsigned long ino = 0;
        int parsed = sscanf(line, "%*d: %*s %79s %*s %*s %*s %*s %*s %*s %lu",
                            rem, &ino);
        if (parsed == 2 && ino > 0) {
            for (int i = 0; i < ninode; i++) {
                if (inodes[i] != ino) continue;
                char *colon = strchr(rem, ':');
                if (!colon) return -1;
                size_t hlen = (size_t)(colon - rem);
                if (hlen == 8) {
                    unsigned int a = 0;
                    if (sscanf(rem, "%x", &a) != 1) return -1;
                    snprintf(ip_out, iplen, "%u.%u.%u.%u",
                             a & 0xff, (a >> 8) & 0xff,
                             (a >> 16) & 0xff, (a >> 24) & 0xff);
                    return 0;
                }
                if (hlen == 32) {
                    unsigned char b[16];
                    for (int w = 0; w < 4; w++) {
                        unsigned int word = 0;
                        if (sscanf(rem + w * 8, "%8x", &word) != 1) return -1;
                        b[w * 4 + 0] = (unsigned char)(word & 0xff);
                        b[w * 4 + 1] = (unsigned char)((word >> 8) & 0xff);
                        b[w * 4 + 2] = (unsigned char)((word >> 16) & 0xff);
                        b[w * 4 + 3] = (unsigned char)((word >> 24) & 0xff);
                    }
                    if (!inet_ntop(AF_INET6, b, ip_out, iplen)) return -1;
                    return 0;
                }
                return -1;
            }
        }
        if (!eol) break;
        lp = eol + 1;
    }
    return -1;
}

/* Read a whole /proc file (grows to EOF; single 4KB reads truncate on
 * busy hosts and silently break inode matching). */
static char *read_proc_file(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    size_t cap = 8192, len = 0;
    char *buf = malloc(cap);
    if (!buf) { close(fd); return NULL; }
    for (;;) {
        if (len + 4096 + 1 > cap) {
            if (cap >= 4 * 1024 * 1024) break;   /* cap at 4MB */
            cap *= 2;
            char *t = realloc(buf, cap);
            if (!t) break;
            buf = t;
        }
        ssize_t n = read(fd, buf + len, cap - 1 - len);
        if (n < 0) {
            if (errno == EINTR) continue;
            free(buf); close(fd); return NULL;
        }
        if (n == 0) break;
        len += (size_t)n;
    }
    close(fd);
    buf[len] = '\0';
    return buf;
}

/* Fallback: extract remote IP via socket-inode mapping.
 * Reads /proc/<pid>/fd/ → finds socket:[inode] → matches the inode in a
 * /proc net/tcp table → extracts remote address.
 *
 * Table choice matters: vsftpd ≥3.0 defaults isolate_network=YES, which
 * CLONE_NEWNET's every session into a private, EMPTY netns — so
 * /proc/<pid>/net/tcp shows nothing while the (inherited, still-living)
 * connection socket stays registered in the LISTENER's netns, which the
 * daemon shares.  Try the target's table first, then our own. */
static int ftp_resolve_ip_by_fd(pid_t pid, char *client_ip, size_t iplen)
{
    /* d_name is a decimal fd, but the buffer must fit the worst case
     * the kernel allows (255) to keep snprintf provably truncation-free. */
    char path[320], link[64];
    DIR *d = NULL;
    struct dirent *de;
    unsigned long inodes[32];
    int ninode = 0;

    /* Collect socket inodes from /proc/<pid>/fd/ */
    snprintf(path, sizeof(path), "/proc/%d/fd", pid);
    d = opendir(path);
    if (!d) goto fail;

    while ((de = readdir(d)) != NULL && ninode < 32) {
        if (de->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "/proc/%d/fd/%s", pid, de->d_name);
        ssize_t nr = readlink(path, link, sizeof(link) - 1);
        if (nr <= 0) continue;
        link[nr] = '\0';
        /* Look for "socket:[<inode>]" */
        const char *sock = strstr(link, "socket:[");
        if (sock) {
            unsigned long ino = strtoul(sock + 8, NULL, 10);
            if (ino > 0) inodes[ninode++] = ino;
        }
    }
    closedir(d);
    d = NULL;
    if (ninode == 0) goto fail;

    /* v4 then v6, target netns then daemon netns — a full read each,
     * no 4KB truncation. */
    for (int v = 0; v < 2; v++) {
        for (int self = 0; self < 2; self++) {
            if (self)
                snprintf(path, sizeof(path), "/proc/net/%s", v ? "tcp6" : "tcp");
            else
                snprintf(path, sizeof(path), "/proc/%d/net/%s", pid,
                         v ? "tcp6" : "tcp");
            char *text = read_proc_file(path);
            if (!text) continue;
            int rc = ftp_tcp_find_remote(text, inodes, ninode, client_ip, iplen);
            free(text);
            if (rc == 0) return 0;
        }
    }

fail:
    if (d) closedir(d);
    snprintf(client_ip, iplen, "0.0.0.0");
    return -1;
}

/* Fallback: get username from UID via /proc/<pid>/status */
static int ftp_resolve_uid(pid_t pid, char *username, size_t ulen)
{
    char path[64], buf[512];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';

    uid_t uid = (uid_t)-1;
    const char *lp = buf;
    while (*lp) {
        if (strncmp(lp, "Uid:", 4) == 0) {
            sscanf(lp + 4, "%u", &uid);
            break;
        }
        lp = strchr(lp, '\n');
        if (!lp) break;
        lp++;
    }
    if (uid == (uid_t)-1) return -1;

    struct passwd *pw = getpwuid(uid);
    if (pw && pw->pw_name)
        snprintf(username, ulen, "%s", pw->pw_name);
    else
        snprintf(username, ulen, "ftp");
    return 0;
}

/* Main entry: try cmdline first (handles virtual users), fall back to
 * status + socket-inode mapping.  Returns 0 on success. */
static int ftp_resolve_session(pid_t pid, char *username, size_t ulen,
                                char *client_ip, size_t iplen)
{
    /* Buffers must be defined on every path: the fallback resolvers
     * leave them untouched when the process is already gone. */
    username[0] = '\0';
    client_ip[0] = '\0';

    /* 1. Primary: parse vsftpd cmdline (catches virtual users) */
    if (ftp_parse_cmdline(pid, username, ulen, client_ip, iplen) == 0)
        return 0;

    /* 2. Fallback: socket-inode for IP + UID for username */
    int ip_rc  = ftp_resolve_ip_by_fd(pid, client_ip, iplen);
    int uid_rc = ftp_resolve_uid(pid, username, ulen);
    return (ip_rc == 0 && uid_rc == 0) ? 0 : -1;
}

/* ── external callback from process_msg() ────────────────────────────── */

/* Called when CRITICAL → ftp-specific blocking: kill the vsftpd child.
 *
 * PID-reuse guard (M16): comm=="vsftpd" alone is not enough — the pid
 * may have been recycled into ANOTHER vsftpd child (a different client
 * session) between the event and the kill.  expected_start is the
 * /proc/<pid>/stat starttime captured at resolve time; a mismatch means
 * the original offender is gone and we kill nothing.
 * expected_start == 0 disables the check (starttime unknown). */
void ftp_block_execute(pid_t pid, unsigned long long expected_start)
{
    char comm[64] = {0};
    unsigned long long now_start = 0;
    if (fan_proc_stat(pid, comm, sizeof(comm), &now_start) != 0)
        return;   /* process gone — nothing to kill */
    if (strncmp(comm, "vsftpd", 6) != 0)
        return;
    if (expected_start && now_start != expected_start)
        return;   /* pid recycled — different session, not our offender */

    kill(pid, SIGTERM);
    /* 500ms grace → SIGKILL, in a detached reaper child — the
     * event loop must never sleep.  Reaped by
     * restore_reap_children() in the main loop. */
    pid_t reaper = fork();
    if (reaper == 0) {
        usleep(500000);
        if (kill(pid, 0) == 0) kill(pid, SIGKILL);
        _exit(0);
    }
    if (reaper < 0)
        kill(pid, SIGKILL);
}

/* ── fanotify channel ops ────────────────────────────────────────────── */

static bool ftp_resolve(const struct fanotify_event *ev,
                        struct fan_channel_ctx *ctx)
{
    /* Fallback: ONE fixed unknown-session so scoring accumulates
     * instead of scattering one session per file path.  "unknown"
     * is not a valid IP, so the blocked-file gate rejects it. */
    if (ev->pid <= 0 ||
        ftp_resolve_session(ev->pid, ctx->username, sizeof(ctx->username),
                            ctx->client_ip, sizeof(ctx->client_ip)) != 0) {
        snprintf(ctx->username,  sizeof(ctx->username),  "ftp");
        snprintf(ctx->client_ip, sizeof(ctx->client_ip), "unknown");
    }
    /* Capture starttime for the kill re-check (M16 PID-reuse guard). */
    fan_proc_stat(ev->pid, NULL, 0, &ctx->proc_start);
    snprintf(ctx->share_name, sizeof(ctx->share_name), "ftp");
    return true;
}

static void ftp_block(const struct fanotify_event *ev,
                      const struct fan_channel_ctx *ctx)
{
    ftp_block_execute(ev->pid, ctx->proc_start);
}

static const struct fan_channel_ops ftp_ops = {
    .source_type = RGUARD_SOURCE_FTP,
    .backup_dir  = "ftp",
    .resolve     = ftp_resolve,
    .block       = ftp_block,
};

static struct fan_channel ftp_channel = { .ops = &ftp_ops };

/* ── module lifecycle ────────────────────────────────────────────────── */

int ftp_module_init(const struct rguard_policy *policy)
{
    if (!policy) return -1;
    if (!policy->protection.ftp) return 0;

    ftp_channel.policy = (struct rguard_policy *)policy;

    for (int i = 0; i < policy->ftp_paths.monitor_count; i++) {
        struct fanotify_channel ch = {
            .mark_path = policy->ftp_paths.monitor_path[i],
            .handler   = fan_channel_dispatch,
            .user_data = &ftp_channel,
        };
        if (fanotify_channel_setup(&ch) != 0) {
            char det[320];
            snprintf(det, sizeof(det), "{\"path\":\"%.256s\"}", ch.mark_path);
            rguard_log_write(LOG_ERROR, "CHANNEL_SETUP_FAILED", NULL, det);
        }
    }
    rguard_log_write(LOG_INFO, "FTP_CHANNEL_READY", NULL, "{}");
    return 0;
}

void ftp_module_destroy(void)
{
    /* Fanotify marks removed globally */
}
