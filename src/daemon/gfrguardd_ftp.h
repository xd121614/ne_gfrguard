/*
 * gfrguardd_ftp.h — FTP anti-ransomware module (fanotify-based).
 *
 * Thin wrapper around the fan_channel skeleton.  Resolves vsftpd child PID
 * to user@ip via /proc, then delegates to the shared scoring engine.
 * SIGHUP reload re-registers marks through the shared fanotify machinery.
 */
#ifndef GFRGUARDD_FTP_H
#define GFRGUARDD_FTP_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

struct rguard_policy;
struct session_table;
struct sqlite3;

/* Initialize the FTP channel: register fanotify marks for ftp.monitor_paths.
 * Returns 0 on success. */
int  ftp_module_init(const struct rguard_policy *policy);

/* Cleanup. */
void ftp_module_destroy(void);

/* Kill the vsftpd child at pid, but only if it is STILL the same process
 * instance (comm=="vsftpd" and, when expected_start != 0, matching
 * /proc/<pid>/stat starttime).  SIGTERM, then SIGKILL after a grace
 * period from a detached reaper child. */
void ftp_block_execute(pid_t pid, unsigned long long expected_start);

/* Scan /proc/net/tcp(6) text for a line whose inode matches one of
 * inodes[] and format its remote address into ip_out.
 * Returns 0 on match, -1 otherwise.  Exposed for unit tests. */
int ftp_tcp_find_remote(const char *text, const unsigned long *inodes,
                        int ninode, char *ip_out, size_t iplen);

#endif /* GFRGUARDD_FTP_H */
