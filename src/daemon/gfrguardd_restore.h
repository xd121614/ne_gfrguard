#ifndef GFRGUARDD_RESTORE_H
#define GFRGUARDD_RESTORE_H

#include "../common/rguard_config.h"

/* If auto_restore.enabled, sleep delay_seconds then fork a child running
 *   /usr/bin/gfrguard-recover restore --event <event_id> --auto
 * Parent registers the child with the SIGCHLD reaper. Returns 0 on launch. */
int restore_trigger_auto(const struct rguard_policy *p, const char *event_id);

/* Reap any finished gfrguard-recover children (call from main loop). */
void restore_reap_children(void);

#endif /* GFRGUARDD_RESTORE_H */
