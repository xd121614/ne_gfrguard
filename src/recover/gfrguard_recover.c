/*
 * gfrguard-recover - CLI file recovery / unblock tool.
 *
 * Subcommands:
 *   restore --event <id> [--auto]   Restore all backed-up files for an event.
 *   unblock <ip>                    Remove an IP from the blocked list.
 *   status                          Show summary of pending/blocked state.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <limits.h>
#include <sqlite3.h>

#include "../common/rguard_db.h"
#include "../common/rguard_errors.h"
#include "../common/rguard_log.h"
#include "../common/rguard_protocol.h"
#include "../daemon/gfrguardd_blocker.h"

#ifndef STORE_PATH
#define STORE_PATH  "/var/lib/gf2000/rguard-store"
#endif
#ifndef DB_PATH
#define DB_PATH     STORE_PATH "/index.db"
#endif
#ifndef LOG_PATH
#define LOG_PATH    "/var/log/gfrguard"
#endif
#ifndef BLOCKED_PATH
#define BLOCKED_PATH "/run/gfrguardd/blocked"
#endif
#ifndef QUARANTINE_PATH
#define QUARANTINE_PATH STORE_PATH "/quarantine"
#endif

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static int mkdir_p(const char *path, mode_t mode)
{
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

/* Paths from the event DB are attacker-influenceable (the attacker
 * picks filenames via SMB and can swap path components after the
 * fact).  Refuse anything but a canonical absolute path before doing
 * root-privileged writes. */
static bool valid_restore_path(const char *path)
{
    size_t len;
    if (!path || path[0] != '/') return false;
    len = strlen(path);
    if (strstr(path, "/../") != NULL) return false;
    if (len >= 3 && strcmp(path + len - 3, "/..") == 0) return false;
    return true;
}

/* Copy src to dst without ever following symlinks (O_NOFOLLOW on both
 * ends); ownership/mode are set on the open fd, so a path swap between
 * open() and fchown() cannot retarget a system file. */
static int copy_file(const char *src, const char *dst, mode_t mode,
                     uid_t uid, gid_t gid)
{
    int sfd = open(src, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (sfd < 0) return -1;

    int dfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                   mode & 0777);
    if (dfd < 0) { close(sfd); return -1; }

    char buf[65536];
    ssize_t n;
    for (;;) {
        n = read(sfd, buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        ssize_t w = 0;
        while (w < n) {
            ssize_t k = write(dfd, buf + w, (size_t)(n - w));
            if (k < 0 && errno == EINTR) continue;
            if (k <= 0) { close(sfd); close(dfd); return -1; }
            w += k;
        }
    }
    int rc = (n < 0) ? -1 : 0;
    if (rc == 0) {
        if (fchown(dfd, uid, gid) != 0 || fchmod(dfd, mode & 0777) != 0) {
            fprintf(stderr, "  WARN: fchown/fchmod failed: %s: %s\n",
                    dst, strerror(errno));
        }
    }
    close(sfd);
    close(dfd);
    return rc;
}

/* Quarantine must never silently overwrite an earlier copy — that is
 * evidence.  If the target exists, append ".N" until the slot is free. */
static void quarantine_unique(char *path, size_t n)
{
    struct stat st;
    if (lstat(path, &st) != 0) return;
    char base[PATH_MAX];
    snprintf(base, sizeof(base), "%s", path);
    for (int i = 1; i < 100; i++) {
        int w = snprintf(path, n, "%s.%d", base, i);
        if (w < 0 || (size_t)w >= n) return;  /* no room — keep original */
        if (lstat(path, &st) != 0) return;
    }
}

static void iso8601_now(char *buf, size_t len)
{
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}

/* ------------------------------------------------------------------ */
/* Restore callback context                                           */
/* ------------------------------------------------------------------ */

struct restore_ctx {
    sqlite3 *db;
    const char *event_id;
    bool auto_mode;
    int total;
    int success;
    int fail;
};

static int restore_one(const struct rguard_protected_file *pf, void *arg)
{
	// TODO 修复的文件如果在新建的文件列表里，则不恢复（删除动作已在 delete_created_one 完成）
    struct restore_ctx *ctx = arg;
    ctx->total++;

    if (strcmp(pf->restore_status, "pending") != 0) return 0;

    if (!valid_restore_path(pf->original_path)) {
        fprintf(stderr, "  FAIL: unsafe path: %s\n", pf->original_path);
        char ts[40]; iso8601_now(ts, sizeof(ts));
        db_update_restore_status(ctx->db, pf->id, "failed", ts);
        ctx->fail++;
        return 0;
    }

    struct stat bst;
    if (stat(pf->backup_path, &bst) != 0) {
        fprintf(stderr, "  FAIL: backup missing: %s\n", pf->backup_path);
        char ts[40]; iso8601_now(ts, sizeof(ts));
        db_update_restore_status(ctx->db, pf->id, "failed", ts);
        ctx->fail++;
        return 0;
    }

    /* Quarantine the corrupted file before overwriting with backup.
     * lstat: never follow symlinks — the path may have been swapped
     * for a symlink to a system file after the event was recorded. */
    struct stat cur_st;
    if (lstat(pf->original_path, &cur_st) == 0) {
        /* Build quarantine path: quarantine/<event_id>/<relative_portion> */
        const char *rel = pf->original_path;
        /* Try to strip common prefix to keep path short. */
        if (rel[0] == '/') rel++;
        char qpath[PATH_MAX];
        int qw = snprintf(qpath, sizeof(qpath), "%s/%s/%s",
                          QUARANTINE_PATH, pf->event_id, rel);
        /* Overflow: skip quarantine entirely — restoring without a
         * quarantine copy beats moving evidence to the wrong path. */
        if (qw >= 0 && (size_t)qw < sizeof(qpath)) {
        /* Ensure quarantine subdirectory exists. */
        char qdir[PATH_MAX];
        snprintf(qdir, sizeof(qdir), "%s", qpath);
        char *qsl = strrchr(qdir, '/');
        if (qsl) { *qsl = '\0'; mkdir_p(qdir, 0755); }
        /* Move (or copy) corrupted file to quarantine.  rename() moves
         * a symlink itself, not its target; the copy fallback is only
         * safe for regular files. */
        quarantine_unique(qpath, sizeof(qpath));
        if (rename(pf->original_path, qpath) != 0) {
            /* rename may fail across filesystems — fallback to copy+unlink. */
            if (S_ISREG(cur_st.st_mode) &&
                copy_file(pf->original_path, qpath, cur_st.st_mode,
                          cur_st.st_uid, cur_st.st_gid) == 0) {
                unlink(pf->original_path);
            }
            /* Non-fatal: proceed with restore even if quarantine fails. */
        }
        }
    }

    /* Ensure target directory exists */
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", pf->original_path);
    char *sl = strrchr(dir, '/');
    if (sl) { *sl = '\0'; mkdir_p(dir, 0755); }

    if (copy_file(pf->backup_path, pf->original_path,
                  (mode_t)pf->file_mode,
                  (uid_t)pf->file_uid, (gid_t)pf->file_gid) != 0) {
        fprintf(stderr, "  FAIL: copy failed: %s\n", pf->original_path);
        char ts[40]; iso8601_now(ts, sizeof(ts));
        db_update_restore_status(ctx->db, pf->id, "failed", ts);
        ctx->fail++;
        return 0;
    }

    char ts[40]; iso8601_now(ts, sizeof(ts));
    db_update_restore_status(ctx->db, pf->id, "restored", ts);
    unlink(pf->backup_path);
    ctx->success++;
    if (!ctx->auto_mode)
        printf("  OK: %s\n", pf->original_path);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Delete ransomware-created files callback                           */
/* ------------------------------------------------------------------ */

struct delete_created_ctx {
    sqlite3 *db;
    const char *event_id;
    int deleted;
    int failed;
    bool auto_mode;
};

static int delete_created_one(long long id, const char *file_path, void *arg)
{
    struct delete_created_ctx *ctx = arg;

    if (!valid_restore_path(file_path)) {
        ctx->failed++;
        if (!ctx->auto_mode)
            fprintf(stderr, "  FAIL DEL: unsafe path: %s\n", file_path);
        return 0;
    }

    struct stat fst;
    if (lstat(file_path, &fst) != 0) {
        /* File already gone — count it handled, keep the DB record. */
        ctx->deleted++;
        return 0;
    }
    int rc = -1;
    if (S_ISREG(fst.st_mode)) {
        const char *rel = file_path;
        if (rel[0] == '/') rel++;
        char qpath[PATH_MAX];
        snprintf(qpath, sizeof(qpath), "%s/%s/%s",
                 QUARANTINE_PATH, ctx->event_id, rel);

        char qdir[PATH_MAX];
        snprintf(qdir, sizeof(qdir), "%s", qpath);
        char *qsl = strrchr(qdir, '/');

        if (qsl) { *qsl = '\0'; mkdir_p(qdir, 0755); }
        quarantine_unique(qpath, sizeof(qpath));
        rc = rename(file_path, qpath);
        if (rc != 0) {
            if (copy_file(file_path, qpath, fst.st_mode,
                          fst.st_uid, fst.st_gid) == 0) {
                rc = unlink(file_path);
            }
        }
    } else if (S_ISLNK(fst.st_mode)) {
        /* Never follow a symlink — just remove the link itself. */
        rc = unlink(file_path);
    } else if (S_ISDIR(fst.st_mode)) {
        /* Ransomware-created dirs: rmdir only (must be empty).  A
         * non-empty attacker-named tree is NOT ours to recursively
         * delete — leave it and count the failure. */
        rc = rmdir(file_path);
    }
    if (rc == 0) {
        ctx->deleted++;
        if (!ctx->auto_mode)
            printf("  DEL: %s\n", file_path);
    } else {
        ctx->failed++;
        if (!ctx->auto_mode)
            fprintf(stderr, "  FAIL DEL: %s: %s\n", file_path, strerror(errno));
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Subcommands                                                         */
/* ------------------------------------------------------------------ */

static int cmd_restore(sqlite3 *db, int argc, char **argv)
{
    const char *event_id = NULL;
    bool auto_mode = false;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--event") == 0 && i + 1 < argc)
            event_id = argv[++i];
        else if (strcmp(argv[i], "--auto") == 0)
            auto_mode = true;
    }
    if (!event_id) {
        fprintf(stderr, "Usage: gfrguard-recover restore --event <id> [--auto]\n");
        return 1;
    }

    /* Delete ransomware-created files (e.g. README.html ransom notes). */
    struct delete_created_ctx dc = { .db = db, .event_id = event_id, .auto_mode = auto_mode };
    db_query_created_by_event(db, event_id, delete_created_one, &dc);

    struct restore_ctx ctx = { .db = db, .event_id = event_id,
                               .auto_mode = auto_mode };
    db_query_by_event(db, event_id, restore_one, &ctx);

    if (ctx.total == 0 && dc.deleted == 0) {
        fprintf(stderr, "No files found for event '%s'\n", event_id);
        return 1;
    }

    /* Update event record */
    char ts[40]; iso8601_now(ts, sizeof(ts));
    db_update_event(db, event_id, ctx.success, 0, 0, "restored", "resolved", ts);

    if (!auto_mode) {
        printf("Restore complete: %d OK, %d failed out of %d total."
               " Created files deleted: %d.\n",
               ctx.success, ctx.fail, ctx.total, dc.deleted);
    }
    return (ctx.fail > 0) ? 2 : 0;
}

static int cmd_unblock(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "Usage: gfrguard-recover unblock <ip>\n");
        return 1;
    }
    int rc = blocker_unblock(BLOCKED_PATH, argv[0]);
    if (rc == 0) {
        printf("Unblocked: %s\n", argv[0]);
        return 0;
    }
    if (rc == 1) {
        fprintf(stderr, "Not in blocked list: %s\n", argv[0]);
        return 1;
    }
    fprintf(stderr, "Failed to unblock: %s\n", strerror(errno));
    return 1;
}

static int cmd_status(sqlite3 *db)
{
    long long pending = 0;
    db_count_pending(db, &pending);

    /* Count blocked sessions — read to EOF; a busy daemon can hold
     * thousands of entries, far past one 4095-byte read. */
    int blocked_count = 0;
    int fd = open(BLOCKED_PATH, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        char buf[4096];
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0)
            for (ssize_t i = 0; i < n; i++)
                if (buf[i] == '\n') blocked_count++;
        close(fd);
    }
    printf("Pending restores : %lld\n", pending);
    printf("Blocked sessions : %d\n", blocked_count);
    if (blocked_count > 0) {
        fd = open(BLOCKED_PATH, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            char buf[4096];
            ssize_t n;
            while ((n = read(fd, buf, sizeof(buf))) > 0)
                fwrite(buf, 1, (size_t)n, stdout);
            close(fd);
            printf("  (list above)\n");
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

static void usage(void)
{
    fprintf(stderr,
        "Usage: gfrguard-recover <command> [options]\n"
        "\n"
        "Commands:\n"
        "  restore --event <id> [--auto]   Restore files for an event\n"
        "  unblock <ip>                    Remove an IP from the blocked list\n"
        "  status                          Show pending/blocked summary\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) { usage(); return 1; }

    const char *cmd = argv[1];

    if (strcmp(cmd, "unblock") == 0) {
        return cmd_unblock(argc - 2, argv + 2);
    }

    sqlite3 *db = NULL;
    if (db_open(DB_PATH, &db) != RGUARD_OK) {
        fprintf(stderr, "Failed to open database: %s\n", DB_PATH);
        return 1;
    }

    int rc;
    if (strcmp(cmd, "restore") == 0) {
        rc = cmd_restore(db, argc - 2, argv + 2);
    } else if (strcmp(cmd, "status") == 0) {
        rc = cmd_status(db);
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage();
        rc = 1;
    }

    db_close(db);
    return rc;
}
