#include "rguard_errors.h"

const char *rguard_strerror(int err)
{
    switch (err) {
    case RGUARD_OK:          return "ok";
    case RGUARD_ERR_CONFIG:  return "config error";
    case RGUARD_ERR_STORE:   return "store unavailable";
    case RGUARD_ERR_BACKUP:  return "backup failed";
    case RGUARD_ERR_DB:      return "sqlite error";
    case RGUARD_ERR_IPC:     return "ipc error";
    case RGUARD_ERR_SPACE:   return "out of space";
    case RGUARD_ERR_RESTORE: return "restore failed";
    case RGUARD_ERR_NOT_FOUND: return "not found";
    default:                 return "unknown error";
    }
}
