#define _POSIX_C_SOURCE 200809L
#include "gfrguardd_restore.h"
#include "../common/rguard_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>

#ifndef RECOVER_BIN
#define RECOVER_BIN "/usr/bin/gfrguard-recover"
#endif

/* PIDs of our own auto-restore children.  The daemon forks other
 * helpers (kill reapers, smbcontrol) that restore_reap_children also
 * harvests — only ours earn AUTO_RESTORE_* log lines. */
static pid_t g_restore_pids[16];
static int    g_restore_npid;

int restore_trigger_auto(const struct rguard_policy *p, const char *event_id)
{
    if (!p || !p->auto_restore.enabled) return 0;
    if (!event_id || !*event_id) return -1;

    char detail[256];
    snprintf(detail, sizeof(detail),
             "{\"event_id\":\"%s\",\"delay_seconds\":%d}",
             event_id, p->auto_restore.delay_seconds);
    rguard_log_write(LOG_INFO, "AUTO_RESTORE_STARTED", NULL, detail);

    pid_t pid = fork();
    if (pid < 0) {
        rguard_log_write(LOG_ERROR, "AUTO_RESTORE_FAILED", NULL,
                         "{\"reason\":\"fork failed\"}");
        return -1;
    }
    if (pid == 0) {
        /* Child: sleep then exec recover. */
        if (p->auto_restore.delay_seconds > 0) {
            sleep((unsigned)p->auto_restore.delay_seconds);
        }
        execl(RECOVER_BIN, "gfrguard-recover", "restore",
              "--event", event_id, "--auto", (char *)NULL);
        _exit(127);
    }
    if (g_restore_npid < 16)
        g_restore_pids[g_restore_npid++] = pid;
    return 0;
}

void restore_reap_children(void)
{
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        bool ours = false;
        for (int i = 0; i < g_restore_npid; i++) {
            if (g_restore_pids[i] == pid) {
                g_restore_pids[i] = g_restore_pids[--g_restore_npid];
                ours = true;
                break;
            }
        }
        if (!ours)
            continue;   /* kill reaper / smbcontrol — reap silently */

        char detail[128];
        int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        snprintf(detail, sizeof(detail),
                 "{\"pid\":%d,\"exit_code\":%d}", (int)pid, code);
        if (code == 0) {
            rguard_log_write(LOG_INFO, "AUTO_RESTORE_COMPLETED", NULL, detail);
        } else {
            rguard_log_write(LOG_ERROR, "AUTO_RESTORE_FAILED", NULL, detail);
        }
    }
}
