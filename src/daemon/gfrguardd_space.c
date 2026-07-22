#define _POSIX_C_SOURCE 200809L
#include "gfrguardd_space.h"
#include "../common/rguard_db.h"
#include "../common/rguard_log.h"

#include <sys/statvfs.h>
#include <stdio.h>

static int used_percent(const char *path, int *out_pct)
{
    struct statvfs vs;
    if (statvfs(path, &vs) != 0) return -1;
    unsigned long total = vs.f_blocks;
    unsigned long avail = vs.f_bavail;
    if (total == 0) { *out_pct = 0; return 0; }
    *out_pct = (int)(((total - avail) * 100UL) / total);
    return 0;
}

int space_check(struct sqlite3 *db, const struct rguard_policy *p)
{
    if (!p || !p->store_path[0]) return 0;
    int used_pct = 0;
    if (used_percent(p->store_path, &used_pct) != 0) return -1;
    if (used_pct <= p->space.max_usage_percent) return 0;

    long long deleted = 0;
    if (db) db_cleanup_restored(db, p->space.cleanup_days, &deleted);

    /* Re-measure after cleanup: the header contract says -1 = still over,
     * and the caller can't tell "cleaned, fine now" from "still full". */
    int after_pct = used_pct;
    if (used_percent(p->store_path, &after_pct) != 0) return -1;

    char detail[160];
    snprintf(detail, sizeof(detail),
             "{\"used_pct\":%d,\"after_cleanup_pct\":%d,\"limit\":%d,\"deleted\":%lld}",
             used_pct, after_pct, p->space.max_usage_percent, deleted);
    rguard_log_write(after_pct > p->space.max_usage_percent ? LOG_WARN : LOG_INFO,
                     "SPACE_WARNING", NULL, detail);
    return after_pct > p->space.max_usage_percent ? -1 : 0;
}
