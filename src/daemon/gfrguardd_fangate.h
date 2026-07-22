/*
 * gfrguardd_fangate.h — per-(session, inode) event flood gate.
 *
 * The daemon has no per-file dedup: every RISKY OPEN/WRITE event bumps
 * modified_count (weight 3, critical 80 → ~27 events per 10 s window
 * block the session).  The SMB VFS dedups at the source per open handle;
 * the fanotify channels have no handle state, and FAN_MODIFY fires per
 * write batch — a single large legitimate write would look like an
 * attack.  This gate collapses OPEN_PERM + MODIFY to at most one risky
 * event per (session, inode) per scoring window, matching VFS granularity.
 *
 * Direct-mapped table, fail-open on collision: a bucket clash can only
 * emit an extra event, never wrongly suppress one.
 */
#ifndef GFRGUARDD_FANGATE_H
#define GFRGUARDD_FANGATE_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#define FANGATE_BUCKETS 1024   /* power of two */

struct fangate_entry {
    uint64_t key;
    int64_t  last_sent;
};

struct fangate {
    pthread_mutex_t      mu;
    struct fangate_entry slots[FANGATE_BUCKETS];
};

void fangate_init(struct fangate *g);
void fangate_reset(struct fangate *g);

/* Returns true if the caller should emit the event; records `now` when
 * true.  window_secs <= 0 disables gating (always true). */
bool fangate_allow(struct fangate *g, const char *session_key,
                   uint64_t inode, int64_t now, int window_secs);

#endif /* GFRGUARDD_FANGATE_H */
