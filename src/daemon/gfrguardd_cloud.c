/*
 * gfrguardd_cloud.c — Cloud-sync anti-ransomware handler (fanotify).
 *
 * Identifies rclone bisync processes via /proc/PID/cmdline, extracting
 * the task_name from "remote:path" arguments.  session_key = "cloud:<task_name>".
 *
 * Blocking: FAN_DENY + neo-croner delete --task-name <NAME>
 *           + kill(process tree, SIGTERM) + save task config to DB.
 * Recovery: gfrguard-recover cloud-restore --task-name <NAME>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "gfrguardd_cloud.h"
#include "gfrguardd_fanchannel.h"
#include "../common/rguard_proc.h"
#include "../common/rguard_protocol.h"
#include "../common/rguard_config.h"
#include "../common/rguard_db.h"
#include "../common/rguard_errors.h"
#include "../common/rguard_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdbool.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/wait.h>

/* sqlite3 is forward-declared in rguard_db.h; we only need opaque pointers. */

/* ── rclone task resolution ──────────────────────────────────────────── */

/* Parse /proc/<pid>/cmdline to find "remote:path" and extract task_name
 * (the part before ':').  cmdline uses '\0' as separator.
 * Returns 0 on success, -1 if not an rclone process. */
static int cloud_resolve_task(pid_t pid, char *task_name, size_t tn_len)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    /* Read cmdline — null-separated tokens */
    char buf[4096];
    size_t nr = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (nr == 0) return -1;
    buf[nr] = '\0';

    /* Must be an rclone process — check argv[0]'s basename, not some
     * random argument that happens to contain the string. */
    const char *base = strrchr(buf, '/');
    base = base ? base + 1 : buf;
    if (strcmp(base, "rclone") != 0)
        return -1;

    /* Scan for "remote:path" or "<name>:<path>" pattern in the tokens */
    const char *p = buf;
    const char *end = buf + nr;
    while (p < end) {
        size_t toklen = strlen(p);

        /* Find ':' — "remote:path" format */
        const char *colon = memchr(p, ':', toklen);
        if (colon) {
            size_t name_len = (size_t)(colon - p);
            /* Skip flags like --password-command=... and http:// URLs */
            if (name_len > 0 && p[0] != '-' && p[0] != '/' &&
                strncmp(p, "http", 4) != 0 && strncmp(p, "https", 5) != 0) {
                size_t copy_len = name_len < tn_len - 1 ? name_len : tn_len - 1;
                memcpy(task_name, p, copy_len);
                task_name[copy_len] = '\0';
                return 0;
            }
        }
        p += toklen + 1;
    }

    return -1;
}

/* ── user resolution (mock — wire to real lookup later) ──────────────── */

/* Resolve the human-readable owner of a cloud-sync task.
 * TODO: replace with real lookup (e.g. neo-croner query, config DB, or
 * /proc/<pid>/environ parsing).  For now every task maps to "cloud". */
const char *cloud_resolve_user(const char *task_name)
{
    (void)task_name;
    return "cloud";
}

/* ── process tree kill ───────────────────────────────────────────────── */

/* Check if a process still exists (kill(pid, 0) succeeds). */
static bool proc_alive(pid_t pid)
{
    return pid > 1 && kill(pid, 0) == 0;
}

/* Recursively collect all descendant PIDs via /proc/<pid>/task/<tid>/children.
 * Returns 1 when the tree overflowed max_pids (caller logs + still kills
 * what was collected — partial kills beat a silent skip). */
static int collect_children(pid_t root, pid_t *pids, int max_pids, int *n)
{
    if (*n >= max_pids) return 1;

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task/%d/children", root, root);

    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char line[4096];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; }
    fclose(f);

    int overflow = 0;
    /* children file contains space-separated PIDs */
    char *saveptr = NULL;
    char *token = strtok_r(line, " \t\n", &saveptr);
    while (token) {
        if (*n >= max_pids) { overflow = 1; break; }
        pid_t child = (pid_t)atoi(token);
        if (child > 1) {
            pids[(*n)++] = child;
            if (collect_children(child, pids, max_pids, n))
                overflow = 1;
        }
        token = strtok_r(NULL, " \t\n", &saveptr);
    }
    return overflow;
}

/* Kill a process tree rooted at `pid`.
 * 1. Collect all descendant PIDs via /proc/x/children
 * 2. SIGTERM all (reverse order, children first)
 * 3. A detached reaper child waits 2s, SIGKILLs survivors, then
 *    SIGTERM+SIGKILLs the root — the event loop must never sleep,
 *    so the grace period lives in the child. */
static void cloud_kill_process_tree(pid_t pid)
{
    if (!proc_alive(pid)) return;

    pid_t pids[256];
    int n = 0;

    /* Collect all descendants (children, grandchildren, ...) */
    if (collect_children(pid, pids, 256, &n)) {
        char det[96];
        snprintf(det, sizeof(det),
                 "{\"root\":%d,\"collected\":%d,\"cap\":256}", pid, n);
        rguard_log_write(LOG_WARN, "PROC_TREE_TRUNCATED", NULL, det);
    }

    /* SIGTERM all descendants — reverse order (deepest first) */
    for (int i = n - 1; i >= 0; i--) {
        if (proc_alive(pids[i])) {
            kill(pids[i], SIGTERM);
        }
    }

    pid_t reaper = fork();
    if (reaper < 0) {
        /* No reaper — kill the root now rather than leave it running. */
        kill(pid, SIGTERM);
        kill(pid, SIGKILL);
        return;
    }
    if (reaper > 0)
        return;   /* reaped by restore_reap_children() in the main loop */

    /* Reaper child: inherited copy of pids/n/pid. */
    usleep(2000000);

    /* SIGKILL any survivors */
    for (int i = n - 1; i >= 0; i--) {
        if (proc_alive(pids[i])) {
            kill(pids[i], SIGKILL);
        }
    }

    /* Kill the root itself */
    if (proc_alive(pid)) {
        kill(pid, SIGTERM);
        usleep(500000);
        if (proc_alive(pid)) {
            kill(pid, SIGKILL);
        }
    }
    _exit(0);
}

/* ── neo-croner integration ──────────────────────────────────────────── */

/* task_name comes from the process cmdline — attacker-controlled.
 * Only a conservative charset is accepted.  execvp already removes the
 * shell from the equation, but garbage names can never match a real
 * task anyway, so reject them early. */
static bool valid_task_name(const char *s)
{
    if (!s || !*s)
        return false;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (!isalnum(*p) && *p != '_' && *p != '.' && *p != '-')
            return false;
    }
    return true;
}

/* Query neo-croner for a task's expression and command.
 * Runs: neo-croner query --task-name <NAME>   (fork+execvp, no shell)
 * Parses stdout lines like:
 *   Expression:     0 x/1 x x x
 *   Command:        main.py netdisk execute_sync_task '...'
 * Returns 0 on success (both expression and command parsed).
 * Hard timeout: a hung neo-croner gets SIGKILL — the event thread
 * must never block forever on an external helper (M9). */
#ifndef NEO_CRONER_TIMEOUT_MS
#define NEO_CRONER_TIMEOUT_MS 5000
#endif
int neo_croner_query(const char *task_name,
                     char *expression, size_t elen,
                     char *command, size_t clen)
{
    expression[0] = '\0';
    command[0] = '\0';

    if (!valid_task_name(task_name))
        return -1;

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) < 0)
        return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        /* Child: stdout → pipe, stderr → /dev/null. */
        int devnull = open("/dev/null", O_WRONLY);
        dup2(pipefd[1], STDOUT_FILENO);
        if (devnull >= 0)
            dup2(devnull, STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execlp("neo-croner", "neo-croner", "query",
               "--task-name", task_name, (char *)NULL);
        _exit(127);
    }

    close(pipefd[1]);

    /* Read with a hard deadline (idle timeout — progress resets it). */
    char buf[8192];
    size_t len = 0;
    int idle = 0;
    bool failed = false;
    for (;;) {
        struct pollfd pfd = { .fd = pipefd[0], .events = POLLIN };
        int pr = poll(&pfd, 1, 100);
        if (pr < 0) {
            if (errno == EINTR) continue;
            failed = true;
            break;
        }
        if (pr > 0) {
            ssize_t n = read(pipefd[0], buf + len, sizeof(buf) - 1 - len);
            if (n > 0) {
                len += (size_t)n;
                idle = 0;
                if (len >= sizeof(buf) - 1) break;   /* full — parse what we have */
            } else if (n == 0) {
                break;                                /* EOF — child closed stdout */
            } else if (errno != EINTR && errno != EAGAIN) {
                failed = true;
                break;
            }
        }
        idle += 100;
        if (idle >= NEO_CRONER_TIMEOUT_MS) {
            failed = true;
            break;
        }
    }
    close(pipefd[0]);
    buf[len] = '\0';

    int status = 0;
    if (failed) {
        kill(pid, SIGKILL);
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
            ;
        return -1;
    }
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
        ;

    /* Parse "Expression: ..." / "Command: ..." lines. */
    char *save = NULL;
    for (char *line = strtok_r(buf, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        if (strncmp(line, "Expression:", 11) == 0) {
            const char *val = line + 11;
            while (*val == ' ' || *val == '\t') val++;
            snprintf(expression, elen, "%s", val);
        } else if (strncmp(line, "Command:", 8) == 0) {
            const char *val = line + 8;
            while (*val == ' ' || *val == '\t') val++;
            snprintf(command, clen, "%s", val);
        }
    }

    return (expression[0] && command[0]) ? 0 : -1;
}

/* Run: neo-croner delete --task-name <NAME>   (fork+execvp, no shell) */
int neo_croner_delete(const char *task_name)
{
    if (!valid_task_name(task_name))
        return -1;

    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0)
            dup2(devnull, STDERR_FILENO);
        execlp("neo-croner", "neo-croner", "delete",
               "--task-name", task_name, (char *)NULL);
        _exit(127);
    }

    int status = 0;
    if (rguard_wait_timeout(pid, NEO_CRONER_TIMEOUT_MS, &status) != 0)
        return -1;

    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

/* ── complete block flow ─────────────────────────────────────────────── */

/* Full cloud channel block:
 *   1. Query neo-croner for task expression + command
 *   2. Save task config to DB (for recovery)
 *   3. Delete neo-croner task
 *   4. Kill the process tree */
static void cloud_block_task(const char *task_name, pid_t trigger_pid,
                             const char *event_id, struct sqlite3 *db)
{
    char expression[256] = {0};
    char command[4096] = {0};
    char ts[40];
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm);

    /* 1. Query neo-croner for task config (best effort — may not exist) */
    int queried = (neo_croner_query(task_name, expression, sizeof(expression),
                                    command, sizeof(command)) == 0);

    /* 2. Save task config to DB for recovery */
    if (db) {
        db_save_cloud_task_config(db, event_id, task_name,
                                  expression[0] ? expression : "",
                                  command[0] ? command : "", ts);
    }

    /* expression/command come from an external tool's stdout — escape
     * before embedding in JSON (task_name is charset-whitelisted already). */
    char expr_esc[512], cmd_esc[600];
    rguard_json_escape(expr_esc, sizeof(expr_esc),
                       expression[0] ? expression : "(unavailable)");
    rguard_json_escape(cmd_esc, sizeof(cmd_esc),
                       command[0] ? command : "(unavailable)");
    char det[4096];
    snprintf(det, sizeof(det),
             "{\"task\":\"%s\",\"expression\":\"%s\",\"command\":\"%.256s\","
             "\"queried\":%s,\"event_id\":\"%s\",\"saved_to_db\":%s}",
             task_name, expr_esc, cmd_esc,
             queried ? "true" : "false",
             event_id ? event_id : "",
             db ? "true" : "false");
    rguard_log_write(LOG_WARN, "CLOUD_BLOCK_EXECUTED", task_name, det);

    /* 3. Delete neo-croner task */
    if (neo_croner_delete(task_name) == 0) {
        rguard_log_write(LOG_INFO, "CLOUD_TASK_DELETED", task_name, "{}");
    } else {
        rguard_log_write(LOG_WARN, "CLOUD_TASK_DELETE_FAILED", task_name,
                         "{\"reason\":\"neo-croner unavailable or delete failed\"}");
    }

    /* 4. Kill process tree */
    cloud_kill_process_tree(trigger_pid);
}

/* ── fanotify channel ops ─────────────────────────────────────────────── */

static bool cloud_resolve(const struct fanotify_event *ev,
                          struct fan_channel_ctx *ctx)
{
    /* Resolve rclone task — the sync process is alive for perm events
     * (kernel-blocked) and normally still alive for notify events. */
    char task_name[128];
    if (cloud_resolve_task(ev->pid, task_name, sizeof(task_name)) < 0)
        return false;  /* not an rclone process / already exited */

    /* Exclude rclone's own temporary files (applies to perm AND notify).
     * Only the exact rclone patterns — a loose ".tmp" match would let
     * ransomware name its output "*.tmp" and walk right past. */
    const char *fname = strrchr(ev->path, '/');
    fname = fname ? fname + 1 : ev->path;
    if (strstr(fname, ".partial~") || strstr(fname, ".rclone-tmp"))
        return false;

    /* task_name[128] is wider than the ctx fields — bound the copies
     * explicitly (the msg fields they feed are the same widths, so this
     * truncation is inherent to the protocol, just now provably safe). */
    snprintf(ctx->username,   sizeof(ctx->username),   "%.63s",
             cloud_resolve_user(task_name));
    snprintf(ctx->client_ip,  sizeof(ctx->client_ip),  "%.47s", task_name);
    snprintf(ctx->share_name, sizeof(ctx->share_name), "%.63s", task_name);
    return true;
}

static void cloud_block(const struct fanotify_event *ev,
                        const struct fan_channel_ctx *ctx)
{
    /* Session blocked — cloud-specific blocking: neo-croner delete +
     * kill process tree + save config to DB.  share_name carries the
     * rclone task name. */
    struct session_table *st = fanotify_get_session_table();
    struct sqlite3 *db = fanotify_get_db();
    const char *evt_id = NULL;
    if (st) {
        struct session_state *s = session_find_or_create(st, ctx->skey);
        if (s && s->current_event_id[0])
            evt_id = s->current_event_id;
    }
    cloud_block_task(ctx->share_name, ev->pid, evt_id, db);
}

static const struct fan_channel_ops cloud_ops = {
    .source_type = RGUARD_SOURCE_CLOUD_SYNC,
    .backup_dir  = "cloud",
    .resolve     = cloud_resolve,
    .block       = cloud_block,
};

static struct fan_channel cloud_channel = { .ops = &cloud_ops };

/* ── lifecycle ───────────────────────────────────────────────────────── */

int cloud_module_init(const struct rguard_policy *policy)
{
    if (!policy) return -1;
    if (!policy->protection.cloud_sync) return 0;

    cloud_channel.policy = (struct rguard_policy *)policy;

    for (int i = 0; i < policy->cloud_paths.monitor_count; i++) {
        struct fanotify_channel ch = {
            .mark_path = policy->cloud_paths.monitor_path[i],
            .handler   = fan_channel_dispatch,
            .user_data = &cloud_channel,
        };
        if (fanotify_channel_setup(&ch) != 0) {
            char det[320];
            snprintf(det, sizeof(det), "{\"path\":\"%.256s\"}", ch.mark_path);
            rguard_log_write(LOG_ERROR, "CHANNEL_SETUP_FAILED", NULL, det);
        }
    }
    rguard_log_write(LOG_INFO, "CLOUD_CHANNEL_READY", NULL, "{}");
    return 0;
}

void cloud_module_destroy(void) {}
