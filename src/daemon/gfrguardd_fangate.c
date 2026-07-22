/*
 * gfrguardd_fangate.c — per-(session, inode) event flood gate.
 */
#include "gfrguardd_fangate.h"
#include "../common/rguard_hash.h"

#include <string.h>

void fangate_init(struct fangate *g)
{
    memset(g->slots, 0, sizeof(g->slots));
    pthread_mutex_init(&g->mu, NULL);
}

void fangate_reset(struct fangate *g)
{
    pthread_mutex_lock(&g->mu);
    memset(g->slots, 0, sizeof(g->slots));
    pthread_mutex_unlock(&g->mu);
}

bool fangate_allow(struct fangate *g, const char *session_key,
                   uint64_t inode, int64_t now, int window_secs)
{
    if (window_secs <= 0 || !session_key)
        return true;

    uint64_t key = rguard_fnv1a64(session_key, strlen(session_key))
                   ^ (inode * 0x9E3779B97F4A7C15ULL);
    if (key == 0) key = 1;  /* 0 marks an empty slot */

    struct fangate_entry *e = &g->slots[key & (FANGATE_BUCKETS - 1)];

    pthread_mutex_lock(&g->mu);
    bool suppress = (e->key == key && now - e->last_sent < window_secs);
    if (!suppress) {
        /* Empty slot, different key (collision → evict, fail-open) or
         * expired window: record this send. */
        e->key = key;
        e->last_sent = now;
    }
    pthread_mutex_unlock(&g->mu);
    return !suppress;
}
