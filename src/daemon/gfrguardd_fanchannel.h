/*
 * gfrguardd_fanchannel.h — Unified fanotify channel skeleton.
 *
 * cloud / ftp / local used to carry three copies of the same handler
 * (mask check → blacklist → backup → fstat → gate → queue → submit →
 * block) and the copies had already drifted: cloud missed the
 * blacklist check and file_uid/gid/mode, the perm branches diverged.
 *
 * The skeleton owns everything that is identical across channels; a
 * channel supplies only what is genuinely its own:
 *
 *   resolve — who is this event (session key + msg identity fields),
 *             or "drop it" (not our process / whitelisted / temp file)
 *   block   — what "block" means here (kill vsftpd child / SIGKILL a
 *             local process / neo-croner delete + kill tree)
 *
 * Registration: each module keeps a static struct fan_channel, sets
 * .policy at init, and registers fan_channel_dispatch as the handler.
 */
#ifndef GFRGUARDD_FANCHANNEL_H
#define GFRGUARDD_FANCHANNEL_H

#include "gfrguardd_fanotify.h"
#include "gfrguardd_session.h"   /* SESSION_KEY_LEN */

struct rguard_policy;

/* Per-event channel identity, filled by ops->resolve.  The session key
 * is NOT the channel's business: the skeleton derives it from
 * username/client_ip after resolve (same derivation as process_msg). */
struct fan_channel_ctx {
    char skey[SESSION_KEY_LEN];   /* derived by the skeleton */
    char username[64];            /* → msg.username */
    char client_ip[48];           /* → msg.client_ip */
    char share_name[64];          /* → msg.share_name */
    unsigned long long proc_start;/* /proc/<pid>/stat starttime, 0 = unknown;
                                     * lets block re-check PID reuse */
};

struct fan_channel_ops {
    uint8_t     source_type;      /* RGUARD_SOURCE_* */
    const char *backup_dir;       /* backup store subdir: "ftp"/"cloud"/"local" */

    /* Resolve ev into ctx.  Return false to drop the event (ALLOW):
     * not the channel's process, whitelisted, excluded temp file, ... */
    bool (*resolve)(const struct fanotify_event *ev,
                    struct fan_channel_ctx *ctx);

    /* Extra action when a blacklist match denies an open (perm path).
     * NULL = plain FAN_RES_DENY. */
    void (*on_blacklist_deny)(const struct fanotify_event *ev,
                              const struct fan_channel_ctx *ctx);

    /* Channel-specific block action after process_msg flags the
     * session blocked (notify path).  NULL = generic block only. */
    void (*block)(const struct fanotify_event *ev,
                  const struct fan_channel_ctx *ctx);
};

/* What a module passes as user_data when registering its handler. */
struct fan_channel {
    const struct fan_channel_ops *ops;
    struct rguard_policy         *policy;
};

/* The shared skeleton — one copy of mask check, blacklist, backup,
 * fstat, gate/queue and submit for all channels. */
enum fan_action fan_channel_handle(const struct fanotify_event *ev,
                                   struct rguard_policy *policy,
                                   const struct fan_channel_ops *ops);

/* fanotify_handler_fn adapter: user_data is a struct fan_channel. */
enum fan_action fan_channel_dispatch(const struct fanotify_event *ev,
                                     const char *matched_path,
                                     void *user_data);

/* Extract comm and starttime from /proc/<pid>/stat.  starttime makes
 * session keys (and kill re-checks) resistant to PID reuse — local and
 * ftp share this ONE parser.  comm_out may be NULL when only the
 * starttime is wanted.  Returns 0 on success, -1 on failure. */
int fan_proc_stat(pid_t pid, char *comm_out, size_t clen,
                  unsigned long long *start_out);

#endif /* GFRGUARDD_FANCHANNEL_H */
