/*
 * rguard_proc.h — small process helpers shared by daemon and recover.
 * Header-only (static inline): no link-time dependency, usable from
 * compilation units that must not pull the daemon object set.
 */
#ifndef RGUARD_PROC_H
#define RGUARD_PROC_H

#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

/* waitpid with a timeout: on expiry SIGKILLs and reaps the child.
 * Returns 0 when the child was reaped in time (*status valid), -1 on
 * timeout/error.  Hung helpers (neo-croner, smbcontrol) must never
 * freeze the caller. */
static inline int rguard_wait_timeout(pid_t pid, int timeout_ms, int *status)
{
    int waited = 0;
    for (;;) {
        pid_t r = waitpid(pid, status, WNOHANG);
        if (r == pid) return 0;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (waited >= timeout_ms) {
            kill(pid, SIGKILL);
            while (waitpid(pid, status, 0) < 0 && errno == EINTR)
                ;
            return -1;
        }
        usleep(10000);
        waited += 10;
    }
}

#endif /* RGUARD_PROC_H */
