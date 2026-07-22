#ifndef GFRGUARDD_SCORER_H
#define GFRGUARDD_SCORER_H

#include "gfrguardd_session.h"
#include "../common/rguard_config.h"

/* Recompute s->risk_score and s->risk_level from current counters and policy. */
void scorer_calculate(struct session_state *s, const struct rguard_policy *p);

/* Returns true if username or client_ip is whitelisted. */
bool scorer_is_whitelisted(const struct rguard_policy *p,
                           const char *username, const char *client_ip);

/* Returns true if username or client_ip is blacklisted. */
bool scorer_is_blacklisted(const struct rguard_policy *p,
                           const char *username, const char *client_ip);

/* Returns true if file_path matches an exception file or is under an exception
 * folder.  Checks exceptions first per the priority chain:
 *   exceptions > whitelist > blacklist */
bool scorer_is_excepted(const struct rguard_policy *p,
                        const char *file_path);

/* Add client_ip to the runtime auto-blacklist if not already present
 * (in either manual or auto list).  Capacity: RGUARD_BLACKLIST_AUTO_MAX (64).
 * FIFO eviction — when full the oldest entry is dropped and the rest shift
 * left.  Hashes are rebuilt after every mutation. */
void scorer_blacklist_auto_add(struct rguard_policy *policy, const char *client_ip);

#endif /* GFRGUARDD_SCORER_H */
