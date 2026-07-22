#define _POSIX_C_SOURCE 200809L
#include "gfrguardd_session.h"
#include "../common/rguard_protocol.h"
#include "../common/rguard_log.h"
#include "../common/rguard_hash.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void session_table_init(struct session_table *t)
{
    memset(t, 0, sizeof(*t));
}

struct session_state *session_find_or_create(struct session_table *t,
                                             const char *session_key)
{
    if (!t || !session_key) return NULL;
    uint64_t h = rguard_fnv1a64(session_key, strlen(session_key));
    for (int probe = 0; probe < SESSION_BUCKETS; probe++) {
        int idx = (int)((h + (uint64_t)probe) % SESSION_BUCKETS);
        struct session_state *s = &t->buckets[idx];
        if (!s->in_use) {
            memset(s, 0, sizeof(*s));
            snprintf(s->session_key, sizeof(s->session_key), "%s", session_key);
            s->in_use = true;
            s->last_seen = time(NULL);
            t->count++;
            return s;
        }
        if (strcmp(s->session_key, session_key) == 0) {
            s->last_seen = time(NULL);
            return s;
        }
    }

    /* Table full — evict the least recently active non-blocked session
     * instead of silently dropping protection for the newcomer.
     * Blocked sessions are never evicted: their is_blocked flag is the
     * fanotify channels' deny signal. */
    struct session_state *oldest = NULL;
    for (int i = 0; i < SESSION_BUCKETS; i++) {
        struct session_state *s = &t->buckets[i];
        if (!s->in_use || s->is_blocked) continue;
        if (!oldest || s->last_seen < oldest->last_seen)
            oldest = s;
    }
    if (!oldest) {
        rguard_log_write(LOG_WARN, "SESSION_TABLE_FULL", session_key,
                         "{\"reason\":\"all slots blocked, new session dropped\"}");
        return NULL;
    }
    rguard_log_write(LOG_WARN, "SESSION_EVICT", oldest->session_key,
                     "{\"reason\":\"table full, evicting least recently active\"}");
    memset(oldest, 0, sizeof(*oldest));
    snprintf(oldest->session_key, sizeof(oldest->session_key), "%s", session_key);
    oldest->in_use = true;
    oldest->last_seen = time(NULL);
    return oldest;
}

void session_check_window(struct session_state *s, time_t now,
                          int window_short, int window_long)
{
    if (s->window_start_10s == 0) s->window_start_10s = now;
    if (s->window_start_30s == 0) s->window_start_30s = now;

    if (now - s->window_start_10s >= window_short) {
        s->modified_count   = 0;
        s->rename_count     = 0;
        s->delete_count     = 0;
        s->ext_change_count = 0;
        s->ransom_ext_count = 0;
        s->high_entropy_count = 0;
        s->yara_match_count = 0;
        s->content_same_count = 0;
        s->window_start_10s = now;
    }
    if (now - s->window_start_30s >= window_long) {
        s->touched_dirs     = 0;
        s->dir_set_count    = 0;
        memset(s->dir_set_hashes, 0, sizeof(s->dir_set_hashes));
        s->window_start_30s = now;
        /* Start fresh event for the new window.  This ensures files
         * created in different time windows get different event_ids,
         * so restore only cleans up files from the attack window.
         *
         * is_blocked is deliberately NOT reset: it is the fanotify
         * channels' deny signal.  Clearing it on window expiry would
         * let a blocked session walk back in after ~30s and re-trigger
         * the whole block path (the auto-blacklist/backstop aside).
         * A block lasts until daemon restart — same lifetime as the
         * blocked file and the auto-blacklist. */
        s->current_event_id[0] = '\0';
        s->risk_level = RISK_NORMAL;
        s->risk_score = 0;
    }
}

static bool dir_seen(struct session_state *s, uint64_t hash)
{
    for (int i = 0; i < s->dir_set_count; i++) {
        if (s->dir_set_hashes[i] == hash) return true;
    }
    return false;
}

static void dir_add(struct session_state *s, uint64_t hash)
{
    if (s->dir_set_count >= DIR_SET_MAX) return;
    s->dir_set_hashes[s->dir_set_count++] = hash;
    if (s->touched_dirs < UINT32_MAX) s->touched_dirs++;
}

void session_update(struct session_state *s, int op_type, unsigned flags,
                    uint64_t dir_hash)
{
    if (!s) return;
    bool risky = (flags & RGUARD_FLAG_RISKY) != 0;
    switch (op_type) {
    case RGUARD_OP_OPEN:
    case RGUARD_OP_WRITE:
    case RGUARD_OP_TRUNCATE:
        if (risky && s->modified_count < UINT32_MAX) s->modified_count++;
        /* Created file with a known ransomware extension (NEW_FILE path:
         * the "delete original + write encrypted copy" pattern arrives
         * as CREATE, not RENAME — it must score the same). */
        if ((flags & RGUARD_FLAG_RANSOM_EXT) && s->ransom_ext_count < UINT32_MAX) {
            s->ransom_ext_count++;
        }
        break;
    case RGUARD_OP_RENAME:
        if (s->rename_count < UINT32_MAX) s->rename_count++;
        if ((flags & RGUARD_FLAG_EXT_CHANGE) && s->ext_change_count < UINT32_MAX) {
            s->ext_change_count++;
        }
        if ((flags & RGUARD_FLAG_RANSOM_EXT) && s->ransom_ext_count < UINT32_MAX) {
            s->ransom_ext_count++;
        }
        break;
    case RGUARD_OP_DELETE:
        if (s->delete_count < UINT32_MAX) s->delete_count++;
        break;
    case RGUARD_OP_CLOSE:
        /* Content-same retraction: file was overwritten with identical data.
         * Reduce modified_count to counteract the earlier RISKY open event. */
        if ((flags & RGUARD_FLAG_CONTENT_SAME) && s->modified_count > 0) {
            s->modified_count--;
            if (s->content_same_count < UINT32_MAX) s->content_same_count++;
        }
        break;
    default:
        break;
    }
    /* Entropy and YARA flags can come with any event (daemon sets them). */
    if ((flags & RGUARD_FLAG_HIGH_ENTROPY) && s->high_entropy_count < UINT32_MAX) {
        s->high_entropy_count++;
    }
    if ((flags & RGUARD_FLAG_YARA_MATCH) && s->yara_match_count < UINT32_MAX) {
        s->yara_match_count++;
    }
    if (dir_hash != 0 && !dir_seen(s, dir_hash)) {
        dir_add(s, dir_hash);
    }
    s->total_events++;
}

void session_cleanup(struct session_table *t)
{
    if (t) memset(t, 0, sizeof(*t));
}
