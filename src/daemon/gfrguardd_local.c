/*
 * gfrguardd_local.c — Local (host) anti-ransomware handler (fanotify).
 *
 * Monitors any non-whitelisted process on protected paths.
 * session identity = "<comm>@local:<pid>:<starttime>" — the starttime
 * makes the session key and the kill re-check resistant to PID reuse.
 * Whitelist: smbd, systemd, sshd, rclone, vsftpd, gfrguardd, etc.
 * Blocking: FAN_DENY + SIGKILL.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "gfrguardd_local.h"
#include "gfrguardd_fanchannel.h"
#include "../common/rguard_protocol.h"
#include "../common/rguard_config.h"
#include "../common/rguard_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

/* ── PID session resolution ───────────────────────────────────────────── */

/* Whitelist — these processes never trigger protection.
 *
 * Two tiers, checked against /proc/<pid>/exe (kernel-maintained,
 * trustworthy), NOT comm (prctl(PR_SET_NAME) is a free rename):
 *
 *   exe_whitelist  — absolute exe paths of the daemons we must not
 *                    kill.  Yocto/GF2000 image paths are fixed, so
 *                    absolute paths are reliable here.
 *   kthread_prefix — kernel threads have no exe (readlink fails);
 *                    fall back to comm prefix match for those.
 */
static const char *exe_whitelist[] = {
    "/usr/sbin/smbd", "/usr/local/samba/sbin/smbd",
    "/usr/sbin/sshd",
    "/usr/sbin/vsftpd",
    "/usr/bin/rclone", "/usr/local/bin/rclone",
    "/usr/local/sbin/gfrguardd",
    "/usr/local/sbin/gfrguard-recover",
    "/usr/lib/systemd/systemd", "/lib/systemd/systemd",
    "/usr/sbin/init", "/sbin/init",
    NULL
};
static const char *kthread_prefix[] = {
    "kworker", "kthreadd", "jbd2", "rcu", "ksoftirqd",
    "ksmd", "khugepaged", NULL
};

/* Whitelist decision.  exe_path NULL/empty (kernel thread, or a racing
 * exit) falls back to comm prefix matching. */
bool local_whitelist_match(const char *comm, const char *exe_path)
{
    if (exe_path && *exe_path) {
        for (int i = 0; exe_whitelist[i]; i++)
            if (strcmp(exe_path, exe_whitelist[i]) == 0) return true;
        return false;
    }
    if (comm) {
        for (int i = 0; kthread_prefix[i]; i++)
            if (strncmp(comm, kthread_prefix[i],
                        strlen(kthread_prefix[i])) == 0) return true;
    }
    return false;
}

/* ── fanotify channel ops ─────────────────────────────────────────────── */

static bool local_resolve(const struct fanotify_event *ev,
                          struct fan_channel_ctx *ctx)
{
    char comm[64];
    unsigned long long start = 0;
    if (ev->pid <= 0 ||
        fan_proc_stat(ev->pid, comm, sizeof(comm), &start) != 0) {
        /* Fallback: ONE fixed unknown-session so scoring accumulates
         * instead of scattering one session per file path. */
        snprintf(ctx->username,  sizeof(ctx->username),  "local");
        snprintf(ctx->client_ip, sizeof(ctx->client_ip), "unknown");
    } else {
        char exe[256] = "";
        {
            char ep[64];
            snprintf(ep, sizeof(ep), "/proc/%d/exe", ev->pid);
            ssize_t n = readlink(ep, exe, sizeof(exe) - 1);
            if (n > 0) exe[n] = '\0'; else exe[0] = '\0';
        }
        if (local_whitelist_match(comm, exe))
            return false;
        /* client_ip carries pid+starttime, so the derived session key
         * identifies one process INSTANCE — a recycled pid keys a new
         * session instead of inheriting the old one's score. */
        snprintf(ctx->username,  sizeof(ctx->username),  "%s", comm);
        snprintf(ctx->client_ip, sizeof(ctx->client_ip), "local:%d:%llu",
                 ev->pid, start);
        ctx->proc_start = start;
    }
    snprintf(ctx->share_name, sizeof(ctx->share_name), "local");
    return true;
}

static void local_kill(const struct fanotify_event *ev,
                       const struct fan_channel_ctx *ctx)
{
    /* PID-reuse guard: only kill the exact process instance that
     * triggered the event — the pid may have been recycled since. */
    if (ctx->proc_start) {
        unsigned long long now_start = 0;
        if (fan_proc_stat(ev->pid, NULL, 0, &now_start) != 0 ||
            now_start != ctx->proc_start)
            return;
    }
    kill(ev->pid, SIGKILL);
}

static const struct fan_channel_ops local_ops = {
    .source_type       = RGUARD_SOURCE_HOST,
    .backup_dir        = "local",
    .resolve           = local_resolve,
    .on_blacklist_deny = local_kill,
    .block             = local_kill,
};

static struct fan_channel local_channel = { .ops = &local_ops };

/* ── lifecycle ───────────────────────────────────────────────────────── */

int local_module_init(const struct rguard_policy *policy)
{
    if (!policy) return -1;
    if (!policy->protection.host) return 0;

    local_channel.policy = (struct rguard_policy *)policy;

    for (int i = 0; i < policy->local_paths.monitor_count; i++) {
        struct fanotify_channel ch = {
            .mark_path = policy->local_paths.monitor_path[i],
            .handler   = fan_channel_dispatch,
            .user_data = &local_channel,
        };
        if (fanotify_channel_setup(&ch) != 0) {
            char det[320];
            snprintf(det, sizeof(det), "{\"path\":\"%.256s\"}", ch.mark_path);
            rguard_log_write(LOG_ERROR, "CHANNEL_SETUP_FAILED", NULL, det);
        }
    }
    rguard_log_write(LOG_INFO, "LOCAL_CHANNEL_READY", NULL, "{}");
    return 0;
}

void local_module_destroy(void) {}
