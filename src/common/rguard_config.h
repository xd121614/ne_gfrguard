#ifndef RGUARD_CONFIG_H
#define RGUARD_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RGUARD_WHITELIST_MAX         64
#define RGUARD_BLACKLIST_AUTO_MAX    64
#define RGUARD_USER_LEN              64
#define RGUARD_IP_LEN                48
#define RGUARD_LEVEL_LEN          16
#define RGUARD_MODE_LEN           16
#define RGUARD_LOGPATH_LEN        256
#define RGUARD_STORE_LEN          256
#define RGUARD_PATH_LEN           256
#define RGUARD_EXCEPTION_MAX      64
#define RGUARD_EXCEPTION_PATH_LEN 2048
#define RGUARD_RANSOM_EXT_MAX      128
#define RGUARD_RANSOM_EXT_LEN      32
#define RGUARD_PROTECT_EXT_MAX     128
#define RGUARD_PROTECT_EXT_LEN     32
#define RGUARD_PROTECT_EXT_HSIZE   257   /* prime, > 2x MAX for open addressing */

struct rguard_weights {
    int modified;
    int rename_w;
    int delete_w;
    int dirs;
    int ext_change;
    int ransom_ext;      /* weight for known ransomware extensions */
    int high_entropy;    /* weight for high-entropy file writes */
    int yara_match;      /* weight for YARA rule matches */
};

struct rguard_thresholds {
    int warn;
    int high;
    int critical;
};

struct rguard_scoring {
    int window_short;
    int window_long;
    /* Cloud-sync channel window overrides.  Cloud events arrive at
     * rclone/cloud-API pace (files per MINUTE, not per second) — the
     * global 10s window resets counters before a slow sync can ever
     * accumulate a blocking score.  0 = inherit the global windows. */
    int cloud_window_short;   /* default 60  */
    int cloud_window_long;    /* default 180 */
    struct rguard_weights weights;
    struct rguard_thresholds thresholds;
    double entropy_threshold;  /* Shannon entropy threshold (default 7.0) */
    bool entropy_enabled;      /* global switch for entropy analysis */
    bool yara_enabled;         /* global switch for YARA scanning */
};

struct rguard_whitelist {
    char users[RGUARD_WHITELIST_MAX][RGUARD_USER_LEN];
    int  user_count;
    uint64_t user_hashes[RGUARD_WHITELIST_MAX];  /* sorted, mirrors users[] */
    char ips[RGUARD_WHITELIST_MAX][RGUARD_IP_LEN];
    int  ip_count;
    uint64_t ip_hashes[RGUARD_WHITELIST_MAX];    /* sorted, mirrors ips[] */
};

struct rguard_bl_ip {
    char ip[RGUARD_IP_LEN];
    bool auto_add;
};

struct rguard_blacklist {
    /* Manual entries — loaded from policy JSON, managed by admin. */
    char users[RGUARD_WHITELIST_MAX][RGUARD_USER_LEN];
    int  user_count;
    uint64_t user_hashes[RGUARD_WHITELIST_MAX];  /* sorted, mirrors users[] */
    struct rguard_bl_ip ips[RGUARD_WHITELIST_MAX];
    int  ip_count;
    uint64_t ip_hashes[RGUARD_WHITELIST_MAX];    /* sorted, mirrors ips[] */

    /* Auto-added entries — populated at runtime by add_to_blacklist().
     * FIFO eviction: when auto_ip_count reaches RGUARD_BLACKLIST_AUTO_MAX,
     * the oldest entry (index 0) is evicted and the rest shift left. */
    struct rguard_bl_ip auto_ips[RGUARD_BLACKLIST_AUTO_MAX];
    int  auto_ip_count;
};

struct rguard_exceptions {
    char files[RGUARD_EXCEPTION_MAX][RGUARD_EXCEPTION_PATH_LEN];
    int  file_count;
    uint64_t file_hashes[RGUARD_EXCEPTION_MAX];   /* sorted, mirrors files[] */
    char folders[RGUARD_EXCEPTION_MAX][RGUARD_EXCEPTION_PATH_LEN];
    int  folder_count;
    uint64_t folder_hashes[RGUARD_EXCEPTION_MAX]; /* sorted, mirrors folders[] */
};

struct rguard_space {
    int max_usage_percent;
    int cleanup_days;
};

struct rguard_auto_restore {
    bool enabled;
    int  delay_seconds;
};

struct rguard_protection {
    bool enabled;       /* master kill-switch for all ransomware protection */
    bool smb;           /* SMB VFS 反勒索 */
    bool cloud_sync;    /* 云连携反勒索 (待开发) */
    bool ftp;           /* FTP 反勒索 (待开发) */
    bool host;          /* GF2000 本体勒索防护 (待开发) */
};

struct rguard_file_extensions {
    bool all;                                          /* protect all file types */
    char manual[RGUARD_PROTECT_EXT_MAX][RGUARD_PROTECT_EXT_LEN];
    int  manual_count;
    uint64_t manual_hashes[RGUARD_PROTECT_EXT_HSIZE];  /* O(1) lookup set, 0=empty */
};

#define RGUARD_MONITOR_MAX    8
#define RGUARD_MONITOR_PATH_LEN    4096

/* FTP channel: fanotify monitor paths only.  Session resolution
 * (IP/user) is done via /proc/<pid>/cmdline at event time. */
struct rguard_path_config {
    char monitor_path[RGUARD_MONITOR_MAX][RGUARD_MONITOR_PATH_LEN];
    int  monitor_count;
};

struct rguard_policy {
    char store_path[RGUARD_STORE_LEN];
    char log_path[RGUARD_LOGPATH_LEN];
    char log_level[RGUARD_LEVEL_LEN];
    char mode[RGUARD_MODE_LEN];
    char scoring_config[RGUARD_PATH_LEN];  /* path to external scoring JSON */
    char ransom_extensions_config[RGUARD_PATH_LEN];
    char ransom_exts[RGUARD_RANSOM_EXT_MAX][RGUARD_RANSOM_EXT_LEN];
    int  ransom_ext_count;

    struct rguard_scoring scoring;
    struct rguard_exceptions exceptions;
    struct rguard_whitelist whitelist;
    struct rguard_blacklist blacklist;
    struct rguard_space space;
    struct rguard_auto_restore auto_restore;
    struct rguard_protection protection;
    struct rguard_file_extensions file_ext;
    
    struct rguard_path_config ftp_paths;
    struct rguard_path_config cloud_paths;
    struct rguard_path_config local_paths;
};

/* Load and validate the JSON policy file. Returns RGUARD_OK on success,
 * RGUARD_ERR_CONFIG on parse/validation failure (reason is written to stderr).
 */
int  config_load(const char *path, struct rguard_policy *out);
int  config_persist_blacklist_ip(const char *config_path, const char *ip);

/* Free any dynamically owned resources inside policy (currently a no-op since
 * whitelist is statically sized, but kept symmetric for future growth).
 */
void config_free(struct rguard_policy *p);

#endif /* RGUARD_CONFIG_H */
