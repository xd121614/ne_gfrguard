/*
 * rguard_hash.h - FNV-1a 64-bit hash and sorted-hash lookup utilities.
 *
 * Used by config (to sort entries at load time) and scorer (to bsearch at
 * lookup time).  Kept as static inline so every compilation unit gets its
 * own copy — no link-time dependency.
 */
#ifndef RGUARD_HASH_H
#define RGUARD_HASH_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

/* FNV-1a 64-bit — the single hash implementation for the whole project
 * (session keys, dir hashes, config lists, fangate).  Do not add local
 * copies; a past copy in session.c had a typo'd offset basis (M24). */
static inline uint64_t rguard_fnv1a64(const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *)buf;
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/*
 * Binary-search a hash-sorted array for an exact string match.
 *
 * hashes  — sorted uint64_t array (length = count)
 * strings — 2D char array with stride 'stride' per row, sorted in the
 *           same order as hashes
 * key     — NUL-terminated lookup key
 *
 * Returns true if key's FNV-1a hash is found in hashes[] *and* the
 * corresponding string matches via strcmp() (hash-collision guard).
 */
static inline bool rguard_hash_lookup(const char *key,
                                       const uint64_t *hashes,
                                       const void *strings,
                                       int count, size_t stride)
{
    if (count <= 0 || !key || !*key || !hashes || !strings)
        return false;

    uint64_t h = rguard_fnv1a64(key, strlen(key));
    int lo = 0, hi = count - 1;

    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (hashes[mid] < h) {
            lo = mid + 1;
        } else if (hashes[mid] > h) {
            hi = mid - 1;
        } else {
            /* Hash hit — confirm with strcmp to rule out collision. */
            const char *s = (const char *)strings + (size_t)mid * stride;
            if (strcmp(key, s) == 0)
                return true;

            /* Collision: same hash, different string.  Walk neighbours
             * with identical hash — they're adjacent because the array
             * is sorted by hash. */
            for (int l = mid - 1; l >= 0 && hashes[l] == h; l--) {
                s = (const char *)strings + (size_t)l * stride;
                if (strcmp(key, s) == 0) return true;
            }
            for (int r = mid + 1; r < count && hashes[r] == h; r++) {
                s = (const char *)strings + (size_t)r * stride;
                if (strcmp(key, s) == 0) return true;
            }
            return false;
        }
    }
    return false;
}

/*
 * Same as rguard_hash_lookup, but takes an explicit length for the key
 * (key need not be NUL-terminated).  The match is EXACT: an entry wins
 * only when its own length equals keylen and the bytes match — this is
 * NOT a prefix matcher despite being used for folder lookups (callers
 * walk up the path and probe each ancestor as an exact-length key).
 */
static inline bool rguard_hash_lookup_len(const char *key, size_t keylen,
                                           const uint64_t *hashes,
                                           const void *strings,
                                           int count, size_t stride)
{
    if (count <= 0 || !key || keylen == 0 || !hashes || !strings)
        return false;

    uint64_t h = rguard_fnv1a64(key, keylen);
    int lo = 0, hi = count - 1;

    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (hashes[mid] < h) {
            lo = mid + 1;
        } else if (hashes[mid] > h) {
            hi = mid - 1;
        } else {
            /* Hash hit — confirm exact length + bytes (collision guard). */
            const char *s = (const char *)strings + (size_t)mid * stride;
            size_t slen = strlen(s);
            if (slen == keylen && memcmp(key, s, keylen) == 0)
                return true;

            for (int l = mid - 1; l >= 0 && hashes[l] == h; l--) {
                s = (const char *)strings + (size_t)l * stride;
                slen = strlen(s);
                if (slen == keylen && memcmp(key, s, keylen) == 0)
                    return true;
            }
            for (int r = mid + 1; r < count && hashes[r] == h; r++) {
                s = (const char *)strings + (size_t)r * stride;
                slen = strlen(s);
                if (slen == keylen && memcmp(key, s, keylen) == 0)
                    return true;
            }
            return false;
        }
    }
    return false;
}

/*
 * Sort strings[] + hashes[] in-place by hash value (ascending).
 * N is small (≤64), insertion sort is fine.
 *
 * The 'strings' parameter can be either char[][] or an array of structs
 * whose first member is a char array (e.g. struct rguard_bl_ip).
 * Usage:
 *   SORT_BY_HASH(hashes, strings, count, sizeof(strings[0]));
 */
#define SORT_BY_HASH(hashes, strings, count, row_sz)             \
    do {                                                         \
        int _n = (count);                                        \
        for (int _i = 1; _i < _n; _i++) {                        \
            uint64_t _h = (hashes)[_i];                          \
            char _tmp[row_sz];                                   \
            memcpy(_tmp, (const void *)((strings) + _i), row_sz); \
            int _j = _i - 1;                                     \
            while (_j >= 0 && (hashes)[_j] > _h) {               \
                (hashes)[_j + 1] = (hashes)[_j];                 \
                memcpy((void *)((strings) + _j + 1),              \
                       (const void *)((strings) + _j), row_sz);  \
                _j--;                                            \
            }                                                    \
            (hashes)[_j + 1] = _h;                               \
            memcpy((void *)((strings) + _j + 1), _tmp, row_sz);  \
        }                                                        \
    } while (0)

#endif /* RGUARD_HASH_H */
