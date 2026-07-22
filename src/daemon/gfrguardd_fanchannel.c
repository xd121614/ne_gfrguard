/*
 * gfrguardd_fanchannel.c — Unified fanotify channel skeleton.
 *
 * One copy of the event pipeline for all fanotify channels:
 *
 *   perm:   blacklist → backup → build msg (+fstat) → gate → queue
 *   notify: build msg → fill_notify → submit → channel block
 *
 * Channels differ only in identity resolution and block action; both
 * are ops callbacks (see gfrguardd_fanchannel.h).
 */
#define _POSIX_C_SOURCE 200809L
#include "gfrguardd_fanchannel.h"
#include "gfrguardd_scorer.h"
#include "../common/rguard_log.h"
#include "../common/rguard_errors.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

enum fan_action fan_channel_handle(const struct fanotify_event *ev,
                                   struct rguard_policy *policy,
                                   const struct fan_channel_ops *ops)
{
    bool is_perm   = (ev->mask & FAN_OPEN_PERM) != 0;
    bool is_notify = (ev->mask & (FAN_MODIFY | FAN_CREATE | FAN_CLOSE_WRITE |
                                  FAN_DELETE | FAN_RENAME)) != 0;
    if (!(is_perm || is_notify))
        return FAN_RES_ALLOW;

    struct fan_channel_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (!ops->resolve(ev, &ctx))
        return FAN_RES_ALLOW;

    /* The session key is ALWAYS derived from the identity fields here —
     * the same derivation process_msg applies to the message.  Channels
     * never build it themselves; that is how the copies drifted apart
     * and is_blocked lookups silently missed. */
    rguard_make_session_key(ctx.skey, sizeof(ctx.skey),
                            ctx.username, ctx.client_ip);

    /* ── FAN_OPEN_PERM (perm thread): blacklist + backup + queue ─── */
    if (is_perm) {
        if (scorer_is_blacklisted(policy, ctx.username, ctx.client_ip)) {
            char det[384];
            snprintf(det, sizeof(det),
                     "{\"path\":\"%.200s\",\"ip\":\"%.47s\",\"user\":\"%.63s\"}",
                     ev->path, ctx.client_ip, ctx.username);
            rguard_log_write(LOG_WARN, "FANOTIFY_BLACKLIST_DENY",
                             ctx.skey, det);
            if (ops->on_blacklist_deny)
                ops->on_blacklist_deny(ev, &ctx);
            /* Report async so process_msg's blacklist branch records the
             * deny in the events table — SMB's VFS_BLOCKED path persists
             * it, fanotify channels must too.  Session is_blocked dedups
             * blocker_execute; the gate throttles repeat offenders. */
            struct rguard_event_msg msg;
            fanotify_build_event_msg(ev, ops->source_type, &msg);
            snprintf(msg.username,   sizeof(msg.username),   "%s", ctx.username);
            snprintf(msg.client_ip,  sizeof(msg.client_ip),  "%s", ctx.client_ip);
            snprintf(msg.share_name, sizeof(msg.share_name), "%s", ctx.share_name);
            if (fanotify_gate_allow(ctx.skey, ev->path, ops->source_type))
                fanotify_queue_event(&msg);
            return FAN_RES_DENY;
        }

        int bk_rc = fanotify_do_backup(ev->event_fd, ev->path,
                                       policy->store_path, ops->backup_dir);

        struct rguard_event_msg msg;
        fanotify_build_event_msg(ev, ops->source_type, &msg);
        snprintf(msg.username,   sizeof(msg.username),   "%s", ctx.username);
        snprintf(msg.client_ip,  sizeof(msg.client_ip),  "%s", ctx.client_ip);
        snprintf(msg.share_name, sizeof(msg.share_name), "%s", ctx.share_name);
        if (bk_rc == RGUARD_OK) {
            msg.flags |= RGUARD_FLAG_BACKED_UP;
            struct stat st;
            if (fstat(ev->event_fd, &st) == 0) {
                msg.inode     = (uint64_t)st.st_ino;
                msg.file_size = (uint64_t)st.st_size;
                msg.mtime     = (int64_t)st.st_mtime;
                msg.file_uid  = (uint32_t)st.st_uid;
                msg.file_gid  = (uint32_t)st.st_gid;
                msg.file_mode = (uint32_t)st.st_mode;
            }
        } else {
            msg.flags |= RGUARD_FLAG_BACKUP_FAILED;
        }

        /* Queue to main thread for process_msg (async, no deadlock).
         * Gate: one RISKY open per (session, file) per scoring window. */
        if (fanotify_gate_allow(ctx.skey, ev->path, ops->source_type))
            fanotify_queue_event(&msg);
        return FAN_RES_ALLOW;
    }

    /* ── Notification events (main thread): map + submit ─────────── */
    struct rguard_event_msg msg;
    fanotify_build_event_msg(ev, ops->source_type, &msg);
    snprintf(msg.username,   sizeof(msg.username),   "%s", ctx.username);
    snprintf(msg.client_ip,  sizeof(msg.client_ip),  "%s", ctx.client_ip);
    snprintf(msg.share_name, sizeof(msg.share_name), "%s", ctx.share_name);

    if (!fanotify_fill_notify_msg(ev, ctx.skey, &msg))
        return FAN_RES_ALLOW;   /* flood-gated or unmapped */

    /* Safe: perm thread handles any FAN_OPEN_PERM this triggers */
    if (fanotify_submit_event(&msg, ctx.skey) && ops->block)
        ops->block(ev, &ctx);
    return FAN_RES_ALLOW;
}

enum fan_action fan_channel_dispatch(const struct fanotify_event *ev,
                                     const char *matched_path,
                                     void *user_data)
{
    (void)matched_path;
    struct fan_channel *ch = user_data;
    if (!ch || !ch->policy || !ch->ops)
        return FAN_RES_ALLOW;
    return fan_channel_handle(ev, ch->policy, ch->ops);
}

int fan_proc_stat(pid_t pid, char *comm_out, size_t clen,
                  unsigned long long *start_out)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    /* /proc/PID/stat: pid (comm) state ... starttime is field 22.
     * We read the whole line and parse the comm (enclosed in parens). */
    char line[1024];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    fclose(f);

    char *rp = strrchr(line, ')');
    if (!rp) return -1;

    if (comm_out && clen > 0) {
        char *lp = strchr(line, '(');
        if (!lp || lp > rp) return -1;
        lp++;
        size_t comm_len = (size_t)(rp - lp);
        if (comm_len >= clen) comm_len = clen - 1;
        memcpy(comm_out, lp, comm_len);
        comm_out[comm_len] = '\0';
    }

    /* Extract starttime — field 22 after ')'.  Skip fields:
     * state ppid pgrp session tty_nr tpgid flags minflt cminflt
     * majflt cmajflt utime stime cutime cstime priority nice
     * num_threads itrealvalue → starttime is at index 19 from ')'+1 */
    unsigned long long starttime = 0;
    char *fields = rp + 2;  /* skip ") " */
    for (int i = 0; i < 19 && fields; i++) {
        char *next = strchr(fields, ' ');
        if (!next) break;
        fields = next + 1;
    }
    if (fields) starttime = strtoull(fields, NULL, 10);
    if (starttime == 0) return -1;

    *start_out = starttime;
    return 0;
}
