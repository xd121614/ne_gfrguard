/*
 * gfrguardd_local.h — Local (host) anti-ransomware module (fanotify-based).
 *
 * Monitors local processes operating on protected directories.
 * session_key = "local:<pid>" with /proc/PID/stat starttime for PID-reuse protection.
 */
#ifndef GFRGUARDD_LOCAL_H
#define GFRGUARDD_LOCAL_H

#include <stdbool.h>
#include <stddef.h>

struct rguard_policy;

int  local_module_init(const struct rguard_policy *policy);
void local_module_destroy(void);

/* Whitelist decision: exe_path (from /proc/<pid>/exe, trusted) wins when
 * present; kernel threads without exe fall back to comm prefix match.
 * Exposed for unit tests. */
bool local_whitelist_match(const char *comm, const char *exe_path);

#endif
