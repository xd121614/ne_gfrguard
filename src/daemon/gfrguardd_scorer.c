#define _POSIX_C_SOURCE 200809L
#include "gfrguardd_scorer.h"
#include "../common/rguard_hash.h"

#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>

// 判断字符串是否为CIDR格式
static int is_cidr(const char *s) {
    return strchr(s, '/') != NULL;
}

// 判断字符串是否为IP段格式（如 192.168.1.10-192.168.1.50）
static int is_ip_range(const char *s) {
    return strchr(s, '-') != NULL;
}

// 判断ip是否在cidr网段
static int ip_in_cidr(const char *ip, const char *cidr) {
    char buf[64];
    strncpy(buf, cidr, sizeof(buf));
    buf[sizeof(buf)-1] = '\0';
    char *slash = strchr(buf, '/');
    if (!slash) return 0;
    *slash = '\0';
    int prefix = atoi(slash+1);
    if (prefix < 0 || prefix > 32) return 0;
    struct in_addr net, addr;
    if (!inet_aton(buf, &net)) return 0;
    if (!inet_aton(ip, &addr)) return 0;
    uint32_t mask = prefix == 0 ? 0 : htonl(~((1u << (32-prefix)) - 1));
    return (addr.s_addr & mask) == (net.s_addr & mask);
}

// 判断ip是否在ip段
static int ip_in_range(const char *ip, const char *range) {
    char buf[64];
    strncpy(buf, range, sizeof(buf));
    buf[sizeof(buf)-1] = '\0';
    char *dash = strchr(buf, '-');
    if (!dash) return 0;
    *dash = '\0';
    const char *start = buf;
    const char *end = dash+1;
    struct in_addr a_start, a_end, a_ip;
    if (!inet_aton(start, &a_start)) return 0;
    if (!inet_aton(end, &a_end)) return 0;
    if (!inet_aton(ip, &a_ip)) return 0;
    uint32_t ip_val = ntohl(a_ip.s_addr);
    uint32_t start_val = ntohl(a_start.s_addr);
    uint32_t end_val = ntohl(a_end.s_addr);
    if (start_val > end_val) {
        uint32_t tmp = start_val; start_val = end_val; end_val = tmp;
    }
    return ip_val >= start_val && ip_val <= end_val;
}

static int clamp100(long v)
{
    if (v < 0) return 0;
    if (v > 100) return 100;
    return (int)v;
}

void scorer_calculate(struct session_state *s, const struct rguard_policy *p)
{
    const struct rguard_weights *w = &p->scoring.weights;
    /* Content signals are session-level booleans, NOT per-file counts
     * (patent avoidance: no blocking by damaged-file count).  High
     * entropy and YARA each add their weight at most once per session —
     * a YARA hit is scored evidence like entropy, not an override. */
    long score = (long)s->modified_count   * w->modified
               + (long)s->rename_count     * w->rename_w
               + (long)s->delete_count     * w->delete_w
               + (long)s->touched_dirs     * w->dirs
               + (long)s->ext_change_count * w->ext_change
               + (long)s->ransom_ext_count * w->ransom_ext
               + (long)(s->high_entropy_count ? 1 : 0) * w->high_entropy
               + (long)(s->yara_match_count   ? 1 : 0) * w->yara_match;

    /* Content-same suppression: if a large proportion of file operations
     * resulted in identical content (normal overwrite pattern), cap the
     * score to prevent false positives during bulk file deployments.
     * The total "write activity" is modified_count + content_same_count
     * (same files already decremented modified_count, but same_count tracks
     * how many were identical). */
    uint32_t total_writes = s->modified_count + s->content_same_count;
    if (total_writes > 0 && s->content_same_count > 0) {
        /* If >=50% of writes are content-same, cap score at warn threshold.
         * If >=80% of writes are content-same, cap score at 0. */
        unsigned pct_same = (s->content_same_count * 100) / total_writes;
        if (pct_same >= 80) {
            score = 0;
        } else if (pct_same >= 50) {
            long cap = (long)p->scoring.thresholds.warn - 1;
            if (score > cap) score = cap;
        }
    }

    s->risk_score = (uint32_t)clamp100(score);

    /* Delete-only sessions should not trigger blocking.  If the session
     * has no writes, renames, or extension changes, cap the risk score
     * at 60 (below the critical threshold) to avoid false positives. */
    if (s->modified_count == 0 && s->rename_count == 0 &&
        s->ext_change_count == 0 && s->ransom_ext_count == 0 &&
        s->high_entropy_count == 0 && s->yara_match_count == 0 &&
        s->delete_count > 0) {
        if (s->risk_score > 60) s->risk_score = 60;
    }

    /* Patent avoidance: a single behavioral dimension alone must not
     * reach CRITICAL — otherwise the design reads as "block on write
     * count/frequency alone".  CRITICAL requires two independent
     * dimensions, or dimension score plus qualitative evidence
     * (ransomware extension).  Mass encryption still
     * blocks: it inherently spreads across directories (dirs > 0). */
    int dims = (s->modified_count   > 0) + (s->rename_count > 0)
             + (s->delete_count     > 0) + (s->touched_dirs > 0)
             + (s->ext_change_count > 0);
    bool evidence = s->ransom_ext_count > 0;
    if (dims == 1 && !evidence) {
        long cap = (long)p->scoring.thresholds.critical - 1;
        if ((long)s->risk_score > cap)
            s->risk_score = (uint32_t)cap;
    }

    const struct rguard_thresholds *t = &p->scoring.thresholds;
    if      ((int)s->risk_score >= t->critical) s->risk_level = RISK_CRITICAL;
    else if ((int)s->risk_score >= t->high)     s->risk_level = RISK_HIGH;
    else if ((int)s->risk_score >= t->warn)     s->risk_level = RISK_SUSPICIOUS;
    else                                        s->risk_level = RISK_NORMAL;
}

bool scorer_is_whitelisted(const struct rguard_policy *p,
                           const char *username, const char *client_ip)
{
    if (!p) return false;

    /* User: exact match via hash lookup (O(log n)). */
    if (username &&
        rguard_hash_lookup(username,
                           p->whitelist.user_hashes,
                           p->whitelist.users,
                           p->whitelist.user_count,
                           RGUARD_USER_LEN))
        return true;

    /* IP: hash lookup for exact match first, then linear scan for
     * CIDR / IP-range entries (few in practice, not hashable). */
    if (client_ip) {
        /* Exact IP via hash → binary search. */
        if (rguard_hash_lookup(client_ip,
                               p->whitelist.ip_hashes,
                               p->whitelist.ips,
                               p->whitelist.ip_count,
                               RGUARD_IP_LEN))
            return true;

        /* Fall through: CIDR and IP-range entries. */
        for (int i = 0; i < p->whitelist.ip_count; i++) {
            const char *entry = p->whitelist.ips[i];
            if (is_cidr(entry)) {
                if (ip_in_cidr(client_ip, entry)) return true;
            } else if (is_ip_range(entry)) {
                if (ip_in_range(client_ip, entry)) return true;
            }
        }
    }
    return false;
}

bool scorer_is_excepted(const struct rguard_policy *p,
                        const char *file_path)
{
    if (!p || !file_path || !*file_path) return false;

    size_t fplen = strlen(file_path);

    /* --- Exception files --- */

    /* 1) Exact match via hash lookup (O(log n)). */
    if (rguard_hash_lookup(file_path,
                           p->exceptions.file_hashes,
                           p->exceptions.files,
                           p->exceptions.file_count,
                           RGUARD_EXCEPTION_PATH_LEN))
        return true;

    /* 2) Suffix match — still linear, but suffixes are typically short
     *     and count is small.  The match must begin at a path boundary:
     *     "b.txt" must not match "/a/ab.txt", and "/data/x.txt" must
     *     not match "/mnt2/data/x.txt". */
    for (int i = 0; i < p->exceptions.file_count; i++) {
        const char *ef = p->exceptions.files[i];
        size_t eflen = strlen(ef);
        if (eflen == 0 || fplen <= eflen) continue;
        const char *tail = file_path + fplen - eflen;
        if (tail[-1] != '/') continue;
        if (strcmp(tail, ef) == 0) return true;
    }

    /* --- Exception folders: hash parent-directory prefixes --- */

    if (p->exceptions.folder_count > 0) {
        /* Walk up path components: for /a/b/c.txt, try /a/b/c.txt (exact),
         * /a/b, /a.  Each candidate is hashed and binary-searched. */
        const char *cursor = file_path + fplen;
        while (cursor > file_path) {
            /* Include the full path as a candidate (file may BE the folder). */
            size_t dlen = (size_t)(cursor - file_path);
            if (dlen == 0) break;

            /* For any candidate but the full path, skip if we're not at a
             * directory boundary (the char after the candidate must be '/'). */
            if (cursor != file_path + fplen && *cursor != '/') {
                /* Back up to previous '/' */
                while (cursor > file_path && *cursor != '/') cursor--;
                continue;
            }

            /* Binary search the hash of this parent/self path. */
            if (rguard_hash_lookup_len(file_path, dlen,
                                       p->exceptions.folder_hashes,
                                       p->exceptions.folders,
                                       p->exceptions.folder_count,
                                       RGUARD_EXCEPTION_PATH_LEN))
                return true;

            /* Back up to previous '/' for the next parent. */
            if (cursor == file_path) break;
            cursor--;
            while (cursor > file_path && *cursor != '/') cursor--;
        }
    }

    return false;
}

bool scorer_is_blacklisted(const struct rguard_policy *p,
                           const char *username, const char *client_ip)
{
    if (!p) return false;

    /* User: exact match via hash lookup (O(log n)).
     * Only manual blacklist has users — auto list is IP-only. */
    if (username &&
        rguard_hash_lookup(username,
                           p->blacklist.user_hashes,
                           p->blacklist.users,
                           p->blacklist.user_count,
                           RGUARD_USER_LEN))
        return true;

    if (client_ip) {
        /* --- Manual IP blacklist --- */
        if (rguard_hash_lookup(client_ip,
                               p->blacklist.ip_hashes,
                               p->blacklist.ips,
                               p->blacklist.ip_count,
                               sizeof(struct rguard_bl_ip)))
            return true;

        for (int i = 0; i < p->blacklist.ip_count; i++) {
            const char *entry = p->blacklist.ips[i].ip;
            if (is_cidr(entry)) {
                if (ip_in_cidr(client_ip, entry)) return true;
            } else if (is_ip_range(entry)) {
                if (ip_in_range(client_ip, entry)) return true;
            }
        }

        /* --- Auto IP blacklist (runtime, FIFO-managed, insertion order) --- */
        for (int i = 0; i < p->blacklist.auto_ip_count; i++) {
            const char *entry = p->blacklist.auto_ips[i].ip;
            if (!entry[0]) continue;
            if (strcmp(client_ip, entry) == 0) return true;
            if (is_cidr(entry) && ip_in_cidr(client_ip, entry)) return true;
            if (is_ip_range(entry) && ip_in_range(client_ip, entry)) return true;
        }
    }
    return false;
}

/* Add client IP to the in-memory auto-blacklist if not already present
 * (either in manual or auto list). Called when a session is blocked due
 * to critical risk score.
 *
 * Capacity: RGUARD_BLACKLIST_AUTO_MAX (64).  FIFO eviction — when full the
 * oldest entry (index 0) is dropped, the rest shift left, and the new
 * entry is appended at the tail.  Hashes are rebuilt after every mutation. */
void scorer_blacklist_auto_add(struct rguard_policy *policy, const char *client_ip)
{
    if (!policy || !client_ip || !*client_ip) return;

    /* Only real IPs belong on the blacklist — channels without a
     * client (cloud/local) pass placeholders like "local:<pid>". */
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, client_ip, &a4) != 1 &&
        inet_pton(AF_INET6, client_ip, &a6) != 1)
        return;

    /* 1. Already in manual list? */
    for (int i = 0; i < policy->blacklist.ip_count; i++) {
        if (strcmp(policy->blacklist.ips[i].ip, client_ip) == 0) return;
    }
    /* 2. Already in auto list? */
    for (int i = 0; i < policy->blacklist.auto_ip_count; i++) {
        if (strcmp(policy->blacklist.auto_ips[i].ip, client_ip) == 0) return;
    }

    /* 3. Insert, evicting oldest if full (FIFO shift-left). */
    if (policy->blacklist.auto_ip_count >= RGUARD_BLACKLIST_AUTO_MAX) {
        /* Evict oldest at index 0 */
        memmove(policy->blacklist.auto_ips,
                policy->blacklist.auto_ips + 1,
                (RGUARD_BLACKLIST_AUTO_MAX - 1) * sizeof(policy->blacklist.auto_ips[0]));
        policy->blacklist.auto_ip_count = RGUARD_BLACKLIST_AUTO_MAX - 1;
    }

    int idx = policy->blacklist.auto_ip_count;
    snprintf(policy->blacklist.auto_ips[idx].ip,
             RGUARD_IP_LEN, "%s", client_ip);
    policy->blacklist.auto_ips[idx].auto_add = true;
    policy->blacklist.auto_ip_count++;
}
