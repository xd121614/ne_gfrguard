#ifndef GFRGUARDD_SPACE_H
#define GFRGUARDD_SPACE_H

#include "../common/rguard_config.h"

struct sqlite3;

/* Check store_path disk usage; if > max_usage_percent, attempt cleanup of
 * old restored backups via db_cleanup_restored. Returns 0 ok, -1 still over. */
int space_check(struct sqlite3 *db, const struct rguard_policy *p);

#endif
