#ifndef GFRGUARDD_BLOCKER_H
#define GFRGUARDD_BLOCKER_H

#include "../common/rguard_db.h"
#include "../common/rguard_config.h"

struct sqlite3;

/* Block a session: append client_ip to the blocked file atomically,
 * run smbcontrol smbd close-share, and update the events row.
 *
 * The blocked file holds one bare IP per line; its only online
 * consumer is the VFS module refusing SMB sessions.  client_ip must
 * be a real IP — pass NULL for channels whose enforcement is not SMB
 * refusal (cloud: task delete + kill; local: kill) and nothing is
 * written.
 *
 * status distinguishes the block reason:
 *   "blocked_ransom" — CRITICAL risk-score trigger (ransomware detected)
 *   "blocked_ip"     — client IP is on the manual or auto blacklist
 *   "blocked_user"   — username is on the manual blacklist
 *
 * Returns 0 on success, non-zero on failure. */
int blocker_execute(struct sqlite3 *db, const char *blocked_path,
                    const char *client_ip, const char *event_id,
                    const char *share_name, const char *status);

/* Seed the blocked file with manual + auto blacklist IPs at startup /
 * reload.  One bare IP per line; CIDR / range entries are excluded
 * (they are evaluated by the daemon at event time).  Rebuilds the
 * file from scratch. */
void blocker_sync_blacklist(const char *blocked_path,
                            const struct rguard_blacklist *bl);

/* Remove the exact IP line from blocked_path atomically.
 * Returns 0 when removed, 1 when no matching line exists, -1 on error. */
int blocker_unblock(const char *blocked_path, const char *ip);

#endif /* GFRGUARDD_BLOCKER_H */
