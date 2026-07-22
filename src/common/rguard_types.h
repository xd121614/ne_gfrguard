#ifndef RGUARD_TYPES_H
#define RGUARD_TYPES_H

#include <stdbool.h>
#include "rguard_protocol.h"   /* RGUARD_PATH_MAX */

#define RGUARD_SESSION_KEY_LEN  128
#define RGUARD_SHARE_MAX        64

/* VFS per-file state attached to fsp via VFS_ADD_FSP_EXTENSION. */
struct rguard_file_state {
    bool is_risky;
    bool backup_done;
    bool backup_failed;
    bool event_sent;    /* one WRITE event per handle, not per pwrite */
    char session_key[RGUARD_SESSION_KEY_LEN];
    char share_name[RGUARD_SHARE_MAX];
    char relative_path[RGUARD_PATH_MAX];
    char backup_path[RGUARD_PATH_MAX];  /* for close-time hash comparison */
};

#endif /* RGUARD_TYPES_H */
