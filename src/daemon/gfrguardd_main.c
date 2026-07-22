/*
 * gfrguardd_main.c - main entry + epoll loop.
 *
 * Workflow per design 3.1.2:
 *   parse args -> config_load -> log_init -> db_open -> create /run/gfrguardd
 *   -> bind AF_UNIX SOCK_DGRAM -> epoll(socket, timerfd 60s)
 *   -> for each event: build session_key, whitelist?, generate event_id,
 *      db_insert_event, FLAG_BACKED_UP -> db_insert_protected_file,
 *      session_find_or_create, session_check_window, session_update,
 *      scorer_calculate, CRITICAL -> blocker_execute + restore_trigger_auto,
 *      SUSPICIOUS/HIGH -> SCORE_ESCALATION
 *   timerfd -> space_check
 *   SIGHUP -> config_load reload, SIGTERM -> graceful exit
 */

#define _POSIX_C_SOURCE 200809L
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "gfrguardd_session.h"
#include "gfrguardd_scorer.h"
#include "gfrguardd_blocker.h"
#include "gfrguardd_restore.h"
#include "gfrguardd_space.h"
#include "gfrguardd_entropy.h"
#include "gfrguardd_yara.h"
#include "gfrguardd_fanotify.h"
#include "gfrguardd_ftp.h"
#include "gfrguardd_cloud.h"
#include "gfrguardd_local.h"

#include "../common/rguard_protocol.h"
#include "../common/rguard_config.h"
#include "../common/rguard_db.h"
#include "../common/rguard_log.h"
#include "../common/rguard_errors.h"
#include "../common/rguard_hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

#include <sqlite3.h>

#define DEFAULT_CONFIG     "/etc/gf2000/rguard-policy.json"
#ifndef RUN_DIR
#define RUN_DIR            "/run/gfrguardd"
#endif
#define BLOCKED_PATH       RUN_DIR "/blocked"
#define DAEMON_SOCKET      RUN_DIR "/gfrguardd.sock"
#define LOG_FILENAME       "gfrguard.log"

static volatile sig_atomic_t g_quit_flag   = 0;
static volatile sig_atomic_t g_reload_flag = 0;
/* Config path remembered for process_msg: auto-blacklist persistence
 * writes verdicts back to the policy file.  NULL in unit tests → skip. */
static const char *g_config_path = NULL;

static void sig_handler(int sig)
{
    if (sig == SIGTERM || sig == SIGINT) g_quit_flag = 1;
    else if (sig == SIGHUP) g_reload_flag = 1;
}

static void install_signals(void)
{
    struct sigaction sa = {0};
    sa.sa_handler = sig_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);

    struct sigaction sn = {0};
    sn.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sn, NULL);
    /* leave SIGCHLD default so waitpid can be called from main loop */
}

static int ensure_dir(const char *path, mode_t mode)
{
    if (mkdir(path, mode) == 0) return 0;
    if (errno == EEXIST) {
        chmod(path, mode);
        return 0;
    }
    return -1;
}

static int ensure_blocked_file(void)
{
    int fd = open(BLOCKED_PATH, O_WRONLY | O_CREAT | O_CLOEXEC, 0640);
    if (fd < 0) return -1;
    fchmod(fd, 0640);
    close(fd);
    return 0;
}

static int parse_log_level(const char *s)
{
    if (!s) return LOG_INFO;
    if (strcmp(s, "debug") == 0) return LOG_DEBUG;
    if (strcmp(s, "info")  == 0) return LOG_INFO;
    if (strcmp(s, "warn")  == 0) return LOG_WARN;
    if (strcmp(s, "error") == 0) return LOG_ERROR;
    return LOG_INFO;
}

static int init_log(const struct rguard_policy *p)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", p->log_path, LOG_FILENAME);
    return rguard_log_init(path, "gfrguardd", parse_log_level(p->log_level));
}

static int bind_dgram_socket(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    unlink(path);
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd); return -1;
    }
    /* Increase receive buffer to handle burst of VFS events (each 1024 bytes).
     * Default ~200KB may overflow with >100 concurrent file ops. */
    int bufsize = 4 * 1024 * 1024;  /* 4MB = ~4000 events queued */
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    /* Allow smbd worker processes (running as share user) to sendto. */
    chmod(path, 0666);
    return fd;
}

static void make_event_id(char *out, size_t n, int *daily_seq,
                         time_t *day_anchor, sqlite3 *db)
{
    time_t now = time(NULL);
    struct tm tm; localtime_r(&now, &tm);
    char date_buf[16];
    strftime(date_buf, sizeof(date_buf), "%Y%m%d", &tm);
    /* On day change (or first call where day_anchor==0), seed the sequence
     * from the database so we never collide with pre-reboot event IDs. */
    struct tm anchor; localtime_r(day_anchor, &anchor);
    if (anchor.tm_year != tm.tm_year || anchor.tm_yday != tm.tm_yday) {
        int db_max = 0;
        db_get_max_daily_seq(db, date_buf, &db_max);
        *daily_seq = db_max;
        *day_anchor = now;
    }
    (*daily_seq)++;
    snprintf(out, n, "evt-%s-%03d", date_buf, *daily_seq);
}

static void iso8601_now(char *out, size_t n)
{
    time_t t = time(NULL);
    struct tm tm; localtime_r(&t, &tm);
    strftime(out, n, "%Y-%m-%dT%H:%M:%S", &tm);
}

static const char *level_str(int l)
{
    switch (l) {
    case RISK_CRITICAL:   return "CRITICAL";
    case RISK_HIGH:       return "HIGH";
    case RISK_SUSPICIOUS: return "SUSPICIOUS";
    default:              return "NORMAL";
    }
}

/* SIGHUP: full config reload.  Fanotify marks are rebuilt from scratch
 * so monitor-path and protection-switch changes take effect without a
 * restart.  The perm thread is stopped during the swap — it reads the
 * channel table without locks; the kernel queues perm events meanwhile
 * (SIGHUP is a rare admin action, the brief stall is acceptable). */
static void daemon_reload(const char *config_path, struct rguard_policy *policy)
{
    struct rguard_policy np;
    if (config_load(config_path, &np) == RGUARD_OK) {
        *policy = np;
        rguard_log_set_level(parse_log_level(policy->log_level));
        rguard_log_write(LOG_INFO, "CONFIG_LOADED", NULL, "{\"reload\":true}");
        blocker_sync_blacklist(BLOCKED_PATH, &policy->blacklist);

        if (fanotify_get_notify_fd() >= 0) {
            fanotify_stop_perm_thread();
            fanotify_reload_marks(NULL, 0);  /* FLUSH both fds + clear channels */
            ftp_module_init(policy);
            cloud_module_init(policy);
            local_module_init(policy);
            /* A dead perm thread with live FAN_OPEN_PERM marks hangs
             * every opener — retry once, then scream. */
            if (fanotify_start_perm_thread() != 0 &&
                fanotify_start_perm_thread() != 0) {
                rguard_log_write(LOG_ERROR, "PERM_THREAD_DEAD",
                                 NULL, "{\"action\":\"perm events unanswered after reload\"}");
            }
        }
    } else {
        rguard_log_write(LOG_ERROR, "CONFIG_ERROR", NULL, "{\"reload\":true}");
    }
    yara_engine_reload(YARA_RULES_DIR);
}


void process_msg(const struct rguard_event_msg *msg,
                 sqlite3 *db, struct session_table *st,
                 struct rguard_policy *policy,
                 int *daily_seq, time_t *day_anchor)
{
    char skey[SESSION_KEY_LEN];
    rguard_make_session_key(skey, sizeof(skey), msg->username, msg->client_ip);

    /* ── VFS blocked notification (VFS denied a connection/file-op) ──
     * Pure telemetry — the IP is already in the blocked file (that's why
     * the VFS denied access).  Just log and record the event. */
    if (msg->msg_type == RGUARD_MSG_VFS_BLOCKED) {
        char det[512];
        snprintf(det, sizeof(det),
                 "{\"reason\":\"blocked_ip\",\"share\":\"%.60s\"}",
                 msg->share_name);
        rguard_log_write(LOG_WARN, "VFS_BLOCKED", skey, det);

        struct session_state *bs = session_find_or_create(st, skey);
        if (bs && bs->current_event_id[0] == '\0') {
            make_event_id(bs->current_event_id, sizeof(bs->current_event_id),
                          daily_seq, day_anchor, db);
        }
        if (bs && bs->current_event_id[0]) {
            struct rguard_event_record ev = {0};
            snprintf(ev.event_id,    sizeof(ev.event_id),    "%s", bs->current_event_id);
            snprintf(ev.session_key, sizeof(ev.session_key), "%s", skey);
            snprintf(ev.username,    sizeof(ev.username),    "%s", msg->username);
            snprintf(ev.client_ip,   sizeof(ev.client_ip),   "%s", msg->client_ip);
            iso8601_now(ev.started_at, sizeof(ev.started_at));
            snprintf(ev.action_taken, sizeof(ev.action_taken), "%s", "blocked");
            snprintf(ev.status,       sizeof(ev.status),       "%s", "blocked_ip");
            db_upsert_event(db, &ev);
        }
        return;
    }

    /* Log every received VFS message for diagnostics. */
    {
        char det[600];
        snprintf(det, sizeof(det),
                 "{\"op\":%u,\"flags\":0x%04x,\"path\":\"%.300s\","
                 "\"new_name\":\"%.100s\",\"share\":\"%.60s\"}",
                 msg->op_type, msg->flags, msg->file_path,
                 msg->new_name, msg->share_name);
        rguard_log_write(LOG_DEBUG, "MSG_RECV", skey, det);
    }

    /* --- Protection master / sub-switch gating --- */
    if (!policy->protection.enabled) {
        rguard_log_write(LOG_DEBUG, "PROTECTION_OFF", skey,
                         "{\"reason\":\"master_switch\"}");
        return;
    }

    switch (msg->source_type) {
    case RGUARD_SOURCE_SMB:
        if (!policy->protection.smb) {
            rguard_log_write(LOG_DEBUG, "PROTECTION_OFF", skey,
                             "{\"reason\":\"smb_sub_switch\"}");
            return;
        }
        break;
    case RGUARD_SOURCE_CLOUD_SYNC:
        if (!policy->protection.cloud_sync) {
            rguard_log_write(LOG_DEBUG, "PROTECTION_OFF", skey,
                             "{\"reason\":\"cloud_sub_switch\"}");
            return;
        }
        break;
    case RGUARD_SOURCE_FTP:
        if (!policy->protection.ftp) {
            rguard_log_write(LOG_DEBUG, "PROTECTION_OFF", skey,
                             "{\"reason\":\"ftp_sub_switch\"}");
            return;
        }
        break;
    case RGUARD_SOURCE_HOST:
        if (!policy->protection.host) {
            rguard_log_write(LOG_DEBUG, "PROTECTION_OFF", skey,
                             "{\"reason\":\"host_sub_switch\"}");
            return;
        }
        break;
    default:
        /* source_type == 0: legacy VFS module that doesn't set it.
         * Treat as SMB for backward compatibility. */
        if (!policy->protection.smb) {
            rguard_log_write(LOG_DEBUG, "PROTECTION_OFF", skey,
                             "{\"reason\":\"smb_sub_switch(legacy)\"}");
            return;
        }
        break;
    }

    /* File-extension filter: when not in "all" mode, only events for
     * listed extensions pass through. */
    if (!policy->file_ext.all && msg->file_path[0] != '\0') {
        const char *ext = strrchr(msg->file_path, '.');
        bool matched = false;
        if (ext && policy->file_ext.manual_count > 0) {
            for (int i = 0; i < policy->file_ext.manual_count; i++) {
                if (strcasecmp(ext, policy->file_ext.manual[i]) == 0) {
                    matched = true;
                    break;
                }
            }
        }
        if (!matched) {
            char det[512];
            snprintf(det, sizeof(det),
                     "{\"path\":\"%.200s\",\"ext\":\"%s\"}",
                     msg->file_path, ext ? ext : "(none)");
            rguard_log_write(LOG_DEBUG, "EXT_FILTER_SKIP", skey, det);
            return;
        }
    }

    if (scorer_is_excepted(policy, msg->file_path)) {
        char det[512];
        snprintf(det, sizeof(det),
                 "{\"op\":%u,\"path\":\"%.400s\"}",
                 msg->op_type, msg->file_path);
        rguard_log_write(LOG_DEBUG, "EXCEPTION_BYPASS", skey, det);
        return;
    }

    if (scorer_is_whitelisted(policy, msg->username, msg->client_ip)) {
        char det[256];
        snprintf(det, sizeof(det),
                 "{\"op\":%u,\"path\":\"%.200s\"}",
                 msg->op_type, msg->file_path);
        rguard_log_write(LOG_DEBUG, "WHITELIST_BYPASS", skey, det);
        return;
    }

    if (scorer_is_blacklisted(policy, msg->username, msg->client_ip)) {
        /* IP match is the stronger signal; otherwise it was the user. */
        bool bl_ip   = scorer_is_blacklisted(policy, NULL, msg->client_ip);
        const char *blk_status = bl_ip ? "blocked_ip" : "blocked_user";

        char det[256];
        snprintf(det, sizeof(det),
                 "{\"op\":%u,\"path\":\"%.200s\",\"reason\":\"%s\"}",
                 msg->op_type, msg->file_path, blk_status);
        rguard_log_write(LOG_WARN, "BLACKLIST_BLOCK", skey, det);

        /* Immediately block blacklisted sessions */
        struct session_state *bs = session_find_or_create(st, skey);
        if (bs && !bs->is_blocked) {
            if (bs->current_event_id[0] == '\0') {
                make_event_id(bs->current_event_id, sizeof(bs->current_event_id),
                              daily_seq, day_anchor, db);
                struct rguard_event_record ev = {0};
                snprintf(ev.event_id,    sizeof(ev.event_id),    "%s", bs->current_event_id);
                snprintf(ev.session_key, sizeof(ev.session_key), "%s", skey);
                snprintf(ev.username,    sizeof(ev.username),    "%s", msg->username);
                snprintf(ev.client_ip,   sizeof(ev.client_ip),   "%s", msg->client_ip);
                iso8601_now(ev.started_at, sizeof(ev.started_at));
                snprintf(ev.action_taken, sizeof(ev.action_taken), "%s", "blocked");
                snprintf(ev.status,       sizeof(ev.status),       "%s", blk_status);
                db_upsert_event(db, &ev);
            }
            bs->is_blocked = true;
            /* Only SMB/FTP produce a real client IP for the blocked
             * file (consumed by the VFS module).  Cloud is reserved
             * (user API still mocked); local is enforced by kill. */
            const char *blk_ip =
                (msg->source_type == RGUARD_SOURCE_SMB ||
                 msg->source_type == RGUARD_SOURCE_FTP) ? msg->client_ip : NULL;
            /* Mark blocked only when the block actually landed — on
             * failure the next event retries instead of silently
             * treating the session as blocked while the DB says active. */
            if (blocker_execute(db, BLOCKED_PATH, blk_ip, bs->current_event_id,
                                msg->share_name, blk_status) != 0) {
                bs->is_blocked = false;
                rguard_log_write(LOG_ERROR, "BLOCK_FAILED", skey, "{}");
            }
        }
        return;
    }

    struct session_state *s = session_find_or_create(st, skey);
    if (!s) return;

    if (s->current_event_id[0] == '\0') {
        make_event_id(s->current_event_id, sizeof(s->current_event_id),
                      daily_seq, day_anchor, db);
        struct rguard_event_record ev = {0};
        snprintf(ev.event_id,    sizeof(ev.event_id),    "%s", s->current_event_id);
        snprintf(ev.session_key, sizeof(ev.session_key), "%s", skey);
        snprintf(ev.username,    sizeof(ev.username),    "%s", msg->username);
        snprintf(ev.client_ip,   sizeof(ev.client_ip),   "%s", msg->client_ip);
        iso8601_now(ev.started_at, sizeof(ev.started_at));
        snprintf(ev.action_taken, sizeof(ev.action_taken), "%s", "none");
        snprintf(ev.status,       sizeof(ev.status),       "%s", "active");
        /* pname only meaningful for local (host) channel — the process name */
        if (msg->source_type == RGUARD_SOURCE_HOST)
            snprintf(ev.pname, sizeof(ev.pname), "%s", msg->username);
        db_insert_event(db, &ev);
    }

    /* If VFS reports backup success, persist record. */
    if ((msg->flags & RGUARD_FLAG_BACKED_UP) &&
        (msg->op_type == RGUARD_OP_OPEN ||
         msg->op_type == RGUARD_OP_WRITE ||
         msg->op_type == RGUARD_OP_TRUNCATE ||
         msg->op_type == RGUARD_OP_DELETE)) {
        struct rguard_protected_file pf = {0};
        snprintf(pf.event_id,      sizeof(pf.event_id),      "%s", s->current_event_id);
        snprintf(pf.original_path, sizeof(pf.original_path), "%s", msg->file_path);
        /* Extract relative filename after share_name for backup_path.
         * file_path is now absolute, e.g. /mnt/storage/filer/home/administrator/1.txt
         * Find /<share_name>/ to locate the file portion. */
        {
            const char *fp = msg->file_path;
            char needle[128];
            snprintf(needle, sizeof(needle), "/%s/", msg->share_name);
            const char *pos = strstr(fp, needle);
            if (pos) {
                fp = pos + strlen(needle);
            } else {
                /* Fallback: old prefix-strip for relative paths. */
                size_t slen = strlen(msg->share_name);
                if (strncmp(fp, msg->share_name, slen) == 0 && fp[slen] == '/')
                    fp = fp + slen + 1;
            }
            int w = snprintf(pf.backup_path, sizeof(pf.backup_path),
                             "%s/backups/%s/%s", policy->store_path,
                             msg->share_name, fp);
            if (w < 0 || (size_t)w >= sizeof(pf.backup_path)) {
                /* DB row and on-disk copy would disagree — skip the
                 * record rather than restore from the wrong place. */
                char det[300];
                snprintf(det, sizeof(det), "{\"path\":\"%.250s\"}", msg->file_path);
                rguard_log_write(LOG_WARN, "BACKUP_PATH_TRUNCATED", skey, det);
                goto skip_pf_insert;
            }
        }
        snprintf(pf.share_name,    sizeof(pf.share_name),    "%s", msg->share_name);
        snprintf(pf.username,      sizeof(pf.username),      "%s", msg->username);
        snprintf(pf.client_ip,     sizeof(pf.client_ip),     "%s", msg->client_ip);
        pf.inode     = (long long)msg->inode;
        pf.mtime     = (long long)msg->mtime;
        pf.file_size = (long long)msg->file_size;
        pf.file_uid  = (int)msg->file_uid;
        pf.file_gid  = (int)msg->file_gid;
        pf.file_mode = (int)msg->file_mode;
        pf.op_type   = (int)msg->op_type;
        iso8601_now(pf.protected_at, sizeof(pf.protected_at));
        snprintf(pf.restore_status, sizeof(pf.restore_status), "%s", "pending");
        if (db_insert_protected_file(db, &pf) == RGUARD_OK) {
            char det[600];
            snprintf(det, sizeof(det),
                     "{\"event_id\":\"%s\",\"path\":\"%.200s\",\"share\":\"%.60s\"}",
                     s->current_event_id, msg->file_path, msg->share_name);
            rguard_log_write(LOG_INFO, "BACKUP_SUCCESS", skey, det);
        }
    } else if (msg->flags & RGUARD_FLAG_BACKUP_FAILED) {
        char det[600];
        snprintf(det, sizeof(det),
                 "{\"event_id\":\"%s\",\"path\":\"%.200s\"}",
                 s->current_event_id, msg->file_path);
        rguard_log_write(LOG_ERROR, "BACKUP_FAILED", skey, det);
    }
skip_pf_insert:

    if ((msg->flags & RGUARD_FLAG_RISKY) && msg->file_path[0] != '\0') {
        char det[600];
        snprintf(det, sizeof(det), "{\"path\":\"%.200s\",\"op\":%u}",
                 msg->file_path, msg->op_type);
        rguard_log_write(LOG_INFO, "RISK_HIT", skey, det);
    }

    /* --- Advanced content analysis on backed-up files --- */
    uint16_t analysis_flags = msg->flags;

    /* Extension-change / ransomware-extension detection.
     * These were previously computed in the VFS module; now the daemon
     * handles them centrally using its own policy copy — no VFS/daemon
     * consistency race. */

    /* RENAME: compare source and destination extensions. */
    if (msg->op_type == RGUARD_OP_RENAME &&
        msg->file_path[0] != '\0' && msg->new_name[0] != '\0') {
        const char *src_ext = strrchr(msg->file_path, '.');
        const char *dst_ext = strrchr(msg->new_name, '.');
        if ((src_ext == NULL) != (dst_ext == NULL) ||
            (src_ext && dst_ext && strcmp(src_ext, dst_ext) != 0)) {
            analysis_flags |= RGUARD_FLAG_EXT_CHANGE;

            if (dst_ext && policy->ransom_ext_count > 0) {
                for (int i = 0; i < policy->ransom_ext_count; i++) {
                    if (strcmp(dst_ext, policy->ransom_exts[i]) == 0) {
                        analysis_flags |= RGUARD_FLAG_RANSOM_EXT;
                        break;
                    }
                }
            }
        }
    }

    /* NEW_FILE: check if the created file has a ransomware extension.
     * Covers the delete-original + create-encrypted-copy pattern. */
    if ((msg->flags & RGUARD_FLAG_NEW_FILE) &&
        msg->file_path[0] != '\0' && policy->ransom_ext_count > 0) {
        const char *ext = strrchr(msg->file_path, '.');
        if (ext) {
            for (int i = 0; i < policy->ransom_ext_count; i++) {
                if (strcmp(ext, policy->ransom_exts[i]) == 0) {
                    analysis_flags |= RGUARD_FLAG_RANSOM_EXT;
                    break;
                }
            }
        }
    }

    /* Entropy analysis: check current file for high entropy. */
    if (policy->scoring.entropy_enabled && msg->file_path[0] != '\0') {
        bool run_entropy = false;
        if ((msg->flags & RGUARD_FLAG_BACKED_UP) &&
            (msg->op_type == RGUARD_OP_OPEN ||
             msg->op_type == RGUARD_OP_WRITE ||
             msg->op_type == RGUARD_OP_TRUNCATE)) {
            run_entropy = true;
        }
        if (run_entropy) {
            double ent = entropy_compute_file(msg->file_path, ENTROPY_SAMPLE_SIZE);
            if (entropy_is_suspicious(ent, policy->scoring.entropy_threshold)) {
                analysis_flags |= RGUARD_FLAG_HIGH_ENTROPY;
                char det[600];
                snprintf(det, sizeof(det),
                         "{\"path\":\"%.200s\",\"entropy\":%.2f,\"threshold\":%.1f}",
                         msg->file_path, ent, policy->scoring.entropy_threshold);
                rguard_log_write(LOG_WARN, "HIGH_ENTROPY", skey, det);
            }
        }
    }

    /* YARA scanning: scan file content against loaded rules.*/
    if (policy->scoring.yara_enabled &&
        msg->file_path[0] != '\0' && yara_engine_active() &&
        msg->op_type == RGUARD_OP_CLOSE) {
        char matched_rule[256] = {0};
        int yr = yara_scan_file(msg->file_path, matched_rule, sizeof(matched_rule));
        if (yr == 1) {
            analysis_flags |= RGUARD_FLAG_YARA_MATCH;
            char det[600];
            snprintf(det, sizeof(det),
                     "{\"path\":\"%.200s\",\"rule\":\"%.100s\"}",
                     msg->file_path, matched_rule);
            rguard_log_write(LOG_WARN, "YARA_MATCH", skey, det);
        }
    }

    /* Compute dir hash from parent of file_path. */
    uint64_t dir_hash = 0;
    {
        const char *slash = strrchr(msg->file_path, '/');
        size_t dl = slash ? (size_t)(slash - msg->file_path) : 0;
        if (dl > 0) dir_hash = rguard_fnv1a64(msg->file_path, dl);
    }

    time_t now = time(NULL);
    /* Cloud events arrive at cloud-API pace — a slow sync can never
     * accumulate a blocking score inside the default 10s window, so the
     * cloud channel gets its own (longer) windows. */
    int win_s = policy->scoring.window_short;
    int win_l = policy->scoring.window_long;
    if (msg->source_type == RGUARD_SOURCE_CLOUD_SYNC) {
        if (policy->scoring.cloud_window_short > 0)
            win_s = policy->scoring.cloud_window_short;
        if (policy->scoring.cloud_window_long > 0)
            win_l = policy->scoring.cloud_window_long;
    }
    session_check_window(s, now, win_s, win_l);
    session_update(s, msg->op_type, analysis_flags, dir_hash);

    /* Defer scoring for plain OPEN/WRITE/TRUNCATE events without ransomware
     * indicators.  This avoids premature threshold triggers during bulk file
     * copies where CLOSE (content-same) events arrive later.  Scoring still
     * happens on CLOSE, RENAME, DELETE, or when high-risk flags are set. */
    bool defer_score = false;
    if ((msg->op_type == RGUARD_OP_OPEN ||
         msg->op_type == RGUARD_OP_WRITE ||
         msg->op_type == RGUARD_OP_TRUNCATE) &&
        !(analysis_flags & (RGUARD_FLAG_RANSOM_EXT | RGUARD_FLAG_HIGH_ENTROPY |
                            RGUARD_FLAG_YARA_MATCH))) {
        defer_score = true;
    }

    int prev_level = s->risk_level;
    if (!defer_score) {
        scorer_calculate(s, policy);
    }

    db_update_event(db, s->current_event_id, 0, s->total_events,
                    (int)s->risk_score, NULL, NULL, NULL);

    if (s->risk_level >= RISK_SUSPICIOUS && s->risk_level > prev_level) {
        char det[256];
        snprintf(det, sizeof(det),
                 "{\"event_id\":\"%s\",\"score\":%u,\"level\":\"%s\"}",
                 s->current_event_id, s->risk_score, level_str(s->risk_level));
        rguard_log_write(LOG_WARN, "SCORE_ESCALATION", skey, det);
    }

    /* Track newly created files for cleanup on restore.
     * Event scoping via time-window ensures only files from the
     * attack window are deleted — earlier windows have different event_ids. */
    if ((msg->flags & RGUARD_FLAG_NEW_FILE) && msg->file_path[0] != '\0') {
        char ts[40];
        iso8601_now(ts, sizeof(ts));
        db_insert_created_file(db, s->current_event_id, msg->file_path,
                               msg->share_name, msg->username, msg->client_ip, ts);
    }

    if (s->risk_level == RISK_CRITICAL && !s->is_blocked) {
        /* Only SMB/FTP produce a real client IP for the blocked
         * file (consumed by the VFS module).  Cloud is reserved
         * (user API still mocked); local is enforced by kill. */
        const char *blk_ip =
            (msg->source_type == RGUARD_SOURCE_SMB ||
             msg->source_type == RGUARD_SOURCE_FTP) ? msg->client_ip : NULL;
        if (blocker_execute(db, BLOCKED_PATH, blk_ip, s->current_event_id,
                            msg->share_name, "blocked_ransom") == 0) {
            s->is_blocked = true;
            char det[256];
            snprintf(det, sizeof(det),
                     "{\"event_id\":\"%s\",\"score\":%u}",
                     s->current_event_id, s->risk_score);
            rguard_log_write(LOG_WARN, "BLOCK_EXECUTED", skey, det);

			scorer_blacklist_auto_add(policy, msg->client_ip);
            /* Persist the verdict into the policy file so a web-driven
            * config save (which restarts gfrguardd) or a SIGHUP can't
            * pardon it — only explicit admin removal can. */
            if (g_config_path &&
                config_persist_blacklist_ip(g_config_path, msg->client_ip) != RGUARD_OK) {
                rguard_log_write(LOG_WARN, "AUTO_BL_PERSIST_FAILED", skey,
                                "{\"msg\":\"in-memory entry still active\"}");
            }
            /* An auto-add is a mini policy reload: keep the three copies
             * in lockstep — memory (above), policy.json (above), and the
             * blocked file.  The full rebuild also drops FIFO-evicted
             * entries, which a pure append never would. */
            blocker_sync_blacklist(BLOCKED_PATH, &policy->blacklist);

            restore_trigger_auto(policy, s->current_event_id);
        } else {
            rguard_log_write(LOG_ERROR, "BLOCK_FAILED", skey, "{}");
        }
    }
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [--config <path>]\n", prog);
}

int main(int argc, char **argv)
{
    const char *config_path = DEFAULT_CONFIG;
    static struct option long_opts[] = {
        {"config", required_argument, 0, 'c'},
        {"help",   no_argument,       0, 'h'},
        {0,0,0,0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "c:h", long_opts, NULL)) != -1) {
        if (opt == 'c') config_path = optarg;
        else if (opt == 'h') { usage(argv[0]); return 0; }
        else { usage(argv[0]); return 1; }
    }
    g_config_path = config_path;

    install_signals();

    struct rguard_policy policy;
    if (config_load(config_path, &policy) != RGUARD_OK) {
        fprintf(stderr, "gfrguardd: failed to load config %s\n", config_path);
        return 1;
    }

    if (init_log(&policy) != 0) {
        fprintf(stderr, "gfrguardd: failed to init log %s\n", policy.log_path);
        return 1;
    }
    rguard_log_write(LOG_INFO, "CONFIG_LOADED", NULL, "{}");

    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/index.db", policy.store_path);
    sqlite3 *db = NULL;
    if (db_open(db_path, &db) != RGUARD_OK) {
        rguard_log_write(LOG_ERROR, "DB_OPEN_FAILED", NULL, "{}");
        return 1;
    }

    if (ensure_dir(RUN_DIR, 0755) != 0) {
        rguard_log_write(LOG_ERROR, "RUNDIR_FAILED", NULL, "{}");
        return 1;
    }
    ensure_blocked_file();
    blocker_sync_blacklist(BLOCKED_PATH, &policy.blacklist);

    /* Initialize YARA rule engine (non-fatal if no rules found). */
    if (yara_engine_init(YARA_RULES_DIR) < 0) {
        rguard_log_write(LOG_WARN, "YARA_INIT_WARN", NULL,
                         "{\"msg\":\"YARA init failed, continuing without\"}");
    }

    int sock_fd = bind_dgram_socket(DAEMON_SOCKET);
    if (sock_fd < 0) {
        rguard_log_write(LOG_ERROR, "SOCKET_FAILED", NULL, "{}");
        return 1;
    }

    int ep = epoll_create1(EPOLL_CLOEXEC);
    if (ep < 0) return 1;

    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    if (tfd < 0) {
        rguard_log_write(LOG_ERROR, "TIMERFD_FAILED", NULL,
                         "{\"action\":\"space_check disabled, daemon exiting\"}");
        close(ep);
        return 1;
    }
    struct itimerspec ts = { .it_interval = {60, 0}, .it_value = {60, 0} };
    timerfd_settime(tfd, 0, &ts, NULL);

    struct epoll_event ev = { .events = EPOLLIN, .data.fd = sock_fd };
    epoll_ctl(ep, EPOLL_CTL_ADD, sock_fd, &ev);
    ev.data.fd = tfd;
    epoll_ctl(ep, EPOLL_CTL_ADD, tfd, &ev);

    struct session_table table;
    session_table_init(&table);

    int daily_seq = 0;
    time_t day_anchor = 0;

    /* ── fanotify: FTP / Cloud / Local channels ── */
    int fan_pipe_fd = -1;
    if (fanotify_module_init(ep) == 0) {
        fanotify_set_daemon_ctx(db, &table, &policy, &daily_seq, &day_anchor);
        ftp_module_init(&policy);
        cloud_module_init(&policy);
        local_module_init(&policy);
        if (fanotify_start_perm_thread() != 0) {
            rguard_log_write(LOG_ERROR, "PERM_THREAD_DEAD",
                             NULL, "{\"action\":\"perm events unanswered at startup\"}");
        }
        fan_pipe_fd = fanotify_get_pipe_fd();
        rguard_log_write(LOG_INFO, "FANOTIFY_READY", NULL, "{}");
    } else {
        rguard_log_write(LOG_WARN, "FANOTIFY_SKIP", NULL,
                         "{\"reason\":\"fanotify init failed, continuing without\"}");
    }

    int loop_nr = 0;
    while (!g_quit_flag) {
        loop_nr++;
        struct epoll_event evs[8];
        int n = epoll_wait(ep, evs, 8, 1000);
        if (n < 0) {
            if (errno == EINTR) {
                if (g_reload_flag) {
                    g_reload_flag = 0;
                    daemon_reload(config_path, &policy);
                }
                continue;
            }
            break;
        }
        for (int i = 0; i < n; i++) {
            if (evs[i].data.fd == sock_fd) {
                struct rguard_event_msg msg;
                while (1) {
                    ssize_t r = recv(sock_fd, &msg, sizeof(msg), MSG_DONTWAIT);
                    if (r < 0) break;
                    if (r != (ssize_t)sizeof(msg)) continue;
                    /* Newer peer than this daemon: field semantics may
                     * have changed — drop rather than misread.  0 means
                     * a pre-versioning peer, which stays accepted. */
                    if (msg.proto_version > RGUARD_PROTO_VERSION) {
                        static int logged;
                        if (!logged) {
                            logged = 1;
                            char det[80];
                            snprintf(det, sizeof(det),
                                     "{\"peer_version\":%u,\"daemon_version\":%u}",
                                     msg.proto_version, RGUARD_PROTO_VERSION);
                            rguard_log_write(LOG_WARN, "PROTO_VERSION_DROP", NULL, det);
                        }
                        continue;
                    }
                    /* The socket is world-writable (0666) — never trust
                     * wire data to be NUL-terminated. */
                    msg.username[sizeof(msg.username) - 1]     = '\0';
                    msg.client_ip[sizeof(msg.client_ip) - 1]   = '\0';
                    msg.share_name[sizeof(msg.share_name) - 1] = '\0';
                    msg.file_path[sizeof(msg.file_path) - 1]   = '\0';
                    msg.new_name[sizeof(msg.new_name) - 1]     = '\0';
                    process_msg(&msg, db, &table, &policy, &daily_seq, &day_anchor);
                }
            } else if (evs[i].data.fd == tfd) {
                uint64_t exp;
                ssize_t nr = read(tfd, &exp, sizeof(exp));
                (void)nr;
                space_check(db, &policy);
                /* Monitor paths created after daemon start. */
                fanotify_retry_pending_channels();
            } else if (fan_pipe_fd >= 0 && evs[i].data.fd == fan_pipe_fd) {
                while (fanotify_process_queued() > 0) {}
            }
        }
        /* Drain fanotify notification events
         * (CLOSE_WRITE / MODIFY / CREATE / DELETE / MOVE) */
        fanotify_poll();
        restore_reap_children();
        if (g_reload_flag) {
            g_reload_flag = 0;
            daemon_reload(config_path, &policy);
        }
    }

    rguard_log_write(LOG_INFO, "SHUTDOWN", NULL, "{}");
    ftp_module_destroy();
    cloud_module_destroy();
    local_module_destroy();
    fanotify_module_destroy();
    session_cleanup(&table);
    yara_engine_destroy();
    close(tfd);
    close(ep);
    close(sock_fd);
    unlink(DAEMON_SOCKET);
    db_close(db);
    rguard_log_close();
    return 0;
}
