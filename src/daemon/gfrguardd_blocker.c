#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "gfrguardd_blocker.h"
#include "../common/rguard_db.h"
#include "../common/rguard_log.h"
#include "../common/rguard_proc.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/file.h>

/* Serialize read-modify-write of the blocked file: gfrguardd (execute,
 * sync) and gfrguard-recover (unblock) can rewrite it concurrently.
 * Returns a lock fd — closing it releases the lock.  O_CLOEXEC keeps it
 * out of forked helpers. */
static int blocked_lock(const char *path)
{
    char lockpath[RGUARD_PATH_MAX];
    snprintf(lockpath, sizeof(lockpath), "%s.lock", path);
    int fd = open(lockpath, O_WRONLY | O_CREAT | O_CLOEXEC, 0640);
    if (fd < 0) return -1;
    if (flock(fd, LOCK_EX) != 0) { close(fd); return -1; }
    return fd;
}

static int read_file_text(const char *path, char **out, size_t *out_len)
{
    *out = NULL; *out_len = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) return 0;
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -1; }
    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf) { close(fd); return -1; }
    /* Single read() can return short — loop to EOF or buffer full. */
    size_t off = 0, cap = (size_t)st.st_size;
    for (;;) {
        ssize_t n = read(fd, buf + off, cap - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd); free(buf); return -1;
        }
        if (n == 0) break;
        off += (size_t)n;
        if (off == cap) break;
    }
    close(fd);
    buf[off] = '\0';
    *out = buf;
    *out_len = off;
    return 0;
}

static int write_atomic(const char *path, const char *data, size_t len)
{
    char tmp[RGUARD_PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0640);
    if (fd < 0) return -1;
    while (len > 0) {
        ssize_t w = write(fd, data, len);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) { close(fd); unlink(tmp); return -1; }
        data += w; len -= (size_t)w;
    }
    if (fsync(fd) != 0) { close(fd); unlink(tmp); return -1; }
    if (close(fd) != 0) { unlink(tmp); return -1; }
    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
    /* fsync the parent dir so the rename itself survives a crash. */
    char dir[RGUARD_PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) {
        if (slash == dir) slash[1] = '\0';
        else *slash = '\0';
        int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd >= 0) { fsync(dfd); close(dfd); }
    }
    return 0;
}

static bool line_exists(const char *content, size_t len, const char *key)
{
    if (!content) return false;
    size_t klen = strlen(key);
    const char *p = content;
    const char *end = content + len;
    while (p < end) {
        const char *eol = memchr(p, '\n', (size_t)(end - p));
        size_t ll = eol ? (size_t)(eol - p) : (size_t)(end - p);
        if (ll == klen && strncmp(p, key, klen) == 0) return true;
        if (!eol) break;
        p = eol + 1;
    }
    return false;
}

/* The blocked file holds one bare IP per line; its only online
 * consumer is the VFS module refusing SMB sessions from those IPs.
 * Write only a real client IP — cloud/local sessions pass NULL or a
 * non-IP placeholder (task name, "local:<pid>"), and inet_pton turns
 * them all away at the same gate. */
static bool valid_client_ip(const char *ip)
{
    if (!ip || !*ip) return false;
    struct in_addr a4;
    struct in6_addr a6;
    return inet_pton(AF_INET, ip, &a4) == 1 ||
           inet_pton(AF_INET6, ip, &a6) == 1;
}

int blocker_execute(struct sqlite3 *db, const char *blocked_path,
                    const char *client_ip, const char *event_id,
                    const char *share_name, const char *status)
{
    if (!blocked_path) return -1;

    if (valid_client_ip(client_ip)) {
        int lfd = blocked_lock(blocked_path);
        if (lfd < 0) return -1;
        char *content = NULL;
        size_t len = 0;
        /* A read failure (EACCES/EIO/...) must NOT fall through to the
         * append path: content==NULL would look like an empty file and
         * write_atomic would rebuild it with just this one IP, silently
         * dropping every existing blocked entry. */
        if (read_file_text(blocked_path, &content, &len) != 0) {
            close(lfd);
            return -1;
        }

        if (!line_exists(content, len, client_ip)) {
            size_t iplen = strlen(client_ip);
            char *new_buf = malloc(len + iplen + 2);
            if (!new_buf) { free(content); close(lfd); return -1; }
            if (content && len) memcpy(new_buf, content, len);
            if (len > 0 && new_buf[len - 1] != '\n') {
                new_buf[len++] = '\n';
            }
            memcpy(new_buf + len, client_ip, iplen);
            len += iplen;
            new_buf[len++] = '\n';
            int rc = write_atomic(blocked_path, new_buf, len);
            free(new_buf);
            free(content);
            close(lfd);
            if (rc != 0) return -1;
        } else {
            free(content);
            close(lfd);
        }
    }

    /* smbcontrol smbd close-share <sharename> — force-close existing connections. */
    if (share_name && *share_name) {
        pid_t pid = fork();
        if (pid == 0) {
            execlp("smbcontrol", "smbcontrol", "smbd", "close-share",
                   share_name, (char *)NULL);
            _exit(127);
        } else if (pid > 0) {
            int st = 0;
            /* A hung smbcontrol must not stall the event thread. */
            rguard_wait_timeout(pid, 5000, &st);
        } else {
            rguard_log_write(LOG_ERROR, "BLOCKER_FORK_FAILED", NULL,
                             "{\"helper\":\"smbcontrol\"}");
        }
    }

    if (db && event_id && *event_id) {
        char ts[40];
        time_t t = time(NULL);
        struct tm tm; localtime_r(&t, &tm);
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm);
        const char *blk_status = (status && *status) ? status : "blocked";
        db_update_event(db, event_id, 0, 0, 0, "blocked", blk_status, ts);
    }
    return 0;
}

/*
 * Rebuild the blocked file from current manual + auto blacklist IPs.
 *
 * Format is one IP per line (no wildcards).  CIDR / IP-range entries are
 * excluded — they are evaluated by the daemon at event time.
 *
 * User blacklist is NOT written to the blocked file; it is checked by
 * scorer_is_blacklisted at event time and triggers blocker_execute
 * (which adds the specific IP to the blocked file for that session).
 */
void blocker_sync_blacklist(const char *blocked_path,
                            const struct rguard_blacklist *bl)
{
    if (!blocked_path || !bl) return;

    /* Estimate size: max 64+64 IPs, each ≤ 48 chars + newline */
    size_t cap = (size_t)(bl->ip_count + bl->auto_ip_count) * 64 + 256;
    char *buf = malloc(cap);
    if (!buf) return;
    size_t len = 0;

    /* ---- manual IPs ---- */
    for (int i = 0; i < bl->ip_count; i++) {
        const char *s = bl->ips[i].ip;
        if (!s[0]) continue;
        if (strchr(s, '/') || strchr(s, '-')) continue;  /* CIDR/range → skip */
        size_t slen = strlen(s);
        if (len + slen + 2 > cap) { cap += 4096; char *t = realloc(buf, cap); if (!t) { free(buf); return; } buf = t; }
        memcpy(buf + len, s, slen); len += slen; buf[len++] = '\n';
    }

    /* ---- auto IPs ---- */
    for (int i = 0; i < bl->auto_ip_count; i++) {
        const char *s = bl->auto_ips[i].ip;
        if (!s[0]) continue;
        if (strchr(s, '/') || strchr(s, '-')) continue;
        size_t slen = strlen(s);
        if (len + slen + 2 > cap) { cap += 4096; char *t = realloc(buf, cap); if (!t) { free(buf); return; } buf = t; }
        memcpy(buf + len, s, slen); len += slen; buf[len++] = '\n';
    }

    /* Full-file overwrite still needs the lock: it must not interleave
     * with an execute/unblock append. */
    int lfd = blocked_lock(blocked_path);
    if (lfd >= 0) {
        write_atomic(blocked_path, buf, len);
        close(lfd);
    }
    free(buf);
}
/* Remove the exact IP line from blocked_path atomically.
 * Returns 0 when a line was removed, 1 when no matching line exists,
 * -1 on error. */
int blocker_unblock(const char *blocked_path, const char *ip)
{
    if (!blocked_path || !ip) return -1;
    int lfd = blocked_lock(blocked_path);
    if (lfd < 0) return -1;
    char *content = NULL; size_t len = 0;
    if (read_file_text(blocked_path, &content, &len) != 0) { close(lfd); return -1; }
    if (!content) { close(lfd); return 1; }

    char *out = malloc(len + 1);
    if (!out) { free(content); close(lfd); return -1; }
    size_t out_len = 0;
    size_t klen = strlen(ip);
    bool found = false;

    const char *p = content;
    const char *end = content + len;
    while (p < end) {
        const char *eol = memchr(p, '\n', (size_t)(end - p));
        size_t ll = eol ? (size_t)(eol - p) : (size_t)(end - p);
        bool drop = (ll == klen && strncmp(p, ip, klen) == 0);
        if (drop) {
            found = true;
        } else {
            memcpy(out + out_len, p, ll);
            out_len += ll;
            out[out_len++] = '\n';
        }
        if (!eol) break;
        p = eol + 1;
    }
    if (!found) { free(out); free(content); close(lfd); return 1; }
    int rc = write_atomic(blocked_path, out, out_len);
    free(out);
    free(content);
    close(lfd);
    return rc;
}
