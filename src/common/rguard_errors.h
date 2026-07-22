#ifndef RGUARD_ERRORS_H
#define RGUARD_ERRORS_H

enum rguard_error {
    RGUARD_OK            = 0,
    RGUARD_ERR_CONFIG    = 1,
    RGUARD_ERR_STORE     = 2,
    RGUARD_ERR_BACKUP    = 3,
    RGUARD_ERR_DB        = 4,
    RGUARD_ERR_IPC       = 5,
    RGUARD_ERR_SPACE     = 6,
    RGUARD_ERR_RESTORE   = 7,
    RGUARD_ERR_NOT_FOUND = 8,
};

const char *rguard_strerror(int err);

#endif /* RGUARD_ERRORS_H */
