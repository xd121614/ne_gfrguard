#ifndef GFRGUARDD_SESSION_H
#define GFRGUARDD_SESSION_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define SESSION_KEY_LEN 128
#define EVENT_ID_LEN    32
#define DIR_SET_MAX     256
#define SESSION_BUCKETS 1024

enum risk_level {
    RISK_NORMAL     = 0,
    RISK_SUSPICIOUS = 1,
    RISK_HIGH       = 2,
    RISK_CRITICAL   = 3,
};

struct session_state {
    char     session_key[SESSION_KEY_LEN];
    uint32_t modified_count;
    uint32_t rename_count;
    uint32_t delete_count;
    uint32_t touched_dirs;
    uint32_t ext_change_count;
    uint32_t ransom_ext_count;    /* known ransomware extension renames */
    uint32_t high_entropy_count;  /* files with entropy > threshold */
    uint32_t yara_match_count;    /* YARA rule matches */
    uint32_t content_same_count;  /* retracted: content unchanged */
    uint32_t risk_score;
    int      risk_level;
    time_t   window_start_10s;
    time_t   window_start_30s;
    bool     is_blocked;
    time_t   last_seen;          /* last event time — eviction candidate */
    char     current_event_id[EVENT_ID_LEN];
    uint64_t total_events;
    uint64_t dir_set_hashes[DIR_SET_MAX];
    int      dir_set_count;
    bool     in_use;
};

struct session_table {
    struct session_state buckets[SESSION_BUCKETS];
    int count;
};

void session_table_init(struct session_table *t);

/* Find existing session_state by session_key, or insert new (zero-initialized).
 * Returns NULL only if table is full. */
struct session_state *session_find_or_create(struct session_table *t,
                                             const char *session_key);

/* Slide the 10s and 30s windows forward if expired, zeroing counters. */
void session_check_window(struct session_state *s, time_t now,
                          int window_short, int window_long);

/* Update counters based on op_type/flags/dir_hash. */
void session_update(struct session_state *s, int op_type, unsigned flags,
                    uint64_t dir_hash);

/* Reset all sessions (used on shutdown). */
void session_cleanup(struct session_table *t);

#endif /* GFRGUARDD_SESSION_H */
