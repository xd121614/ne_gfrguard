/*
 * gfrguardd_cloud.h — Cloud-sync anti-ransomware module (fanotify-based).
 *
 * Intercepts rclone bisync file operations via fanotify, identifies the
 * cloud task by parsing /proc/PID/cmdline for "remote:path" arguments.
 * session_key = "cloud:<task_name>".
 */
#ifndef GFRGUARDD_CLOUD_H
#define GFRGUARDD_CLOUD_H

#include <stddef.h>

struct rguard_policy;

int  cloud_module_init(const struct rguard_policy *policy);
void cloud_module_destroy(void);

/* neo-croner helpers — fork+execvp with a hard timeout (M9: a hung
 * helper gets SIGKILL, never blocks the event thread).
 * Exposed for unit tests. */
int neo_croner_query(const char *task_name,
                     char *expression, size_t elen,
                     char *command, size_t clen);
int neo_croner_delete(const char *task_name);

#endif
