#ifndef RGUARD_DB_H
#define RGUARD_DB_H

#include <stdint.h>
#include <stddef.h>
#include "rguard_protocol.h"   /* RGUARD_PATH_MAX */

struct sqlite3;

struct rguard_protected_file {
    long long id;
    char  event_id[64];
    char  original_path[RGUARD_PATH_MAX];
    char  backup_path[RGUARD_PATH_MAX];
    char  share_name[64];
    char  username[64];
    char  client_ip[48];
    long long inode;
    long long mtime;
    long long file_size;
    int   file_uid;
    int   file_gid;
    int   file_mode;
    int   op_type;
    char  protected_at[40];
    char  restore_status[16];
    char  restored_at[40];
};

struct rguard_event_record {
    long long id;
    char  event_id[64];
    char  session_key[128];
    char  username[64];
    char  client_ip[48];
    char  pname[64];           /* process name (smbd/vsftpd/rclone/<comm>) */
    char  started_at[40];
    char  ended_at[40];
    long long files_protected;
    long long files_affected;
    int   peak_risk_score;
    char  action_taken[32];
    char  status[32];
};

/* Open SQLite at db_path in WAL mode and create schema if missing. */
int db_open(const char *db_path, struct sqlite3 **out_db);
int db_close(struct sqlite3 *db);

int db_insert_protected_file(struct sqlite3 *db, const struct rguard_protected_file *pf);
int db_insert_event(struct sqlite3 *db, const struct rguard_event_record *ev);
/* Upsert: INSERT or UPDATE on event_id conflict. Safer than insert-then-update
 * because it's a single atomic operation — no gap where update runs without a row. */
int db_upsert_event(struct sqlite3 *db, const struct rguard_event_record *ev);
int db_update_event(struct sqlite3 *db, const char *event_id,
                    long long files_protected, long long files_affected,
                    int peak_risk_score, const char *action_taken,
                    const char *status, const char *ended_at);
int db_update_restore_status(struct sqlite3 *db, long long id,
                             const char *status, const char *restored_at);

/* Iterator-style queries: caller-supplied callback invoked per row.
 * Returning non-zero from callback aborts iteration. */
typedef int (*rguard_pf_cb)(const struct rguard_protected_file *pf, void *ctx);

int db_query_by_event(struct sqlite3 *db, const char *event_id,
                      rguard_pf_cb cb, void *ctx);
int db_query_by_path(struct sqlite3 *db, const char *original_path,
                     rguard_pf_cb cb, void *ctx);
int db_count_pending(struct sqlite3 *db, long long *out_count);
int db_cleanup_restored(struct sqlite3 *db, int older_than_days,
                        long long *out_deleted_rows);

/* Created files (ransomware-generated files to delete on restore). */
typedef int (*rguard_cf_cb)(long long id, const char *file_path, void *ctx);

int db_insert_created_file(struct sqlite3 *db, const char *event_id,
                           const char *file_path, const char *share_name,
                           const char *username, const char *client_ip,
                           const char *created_at);
int db_query_created_by_event(struct sqlite3 *db, const char *event_id,
                              rguard_cf_cb cb, void *ctx);
int db_delete_created_file(struct sqlite3 *db, long long id);

/* Get the max daily sequence number for event IDs matching "evt-<date_prefix>-NNN". */
int db_get_max_daily_seq(struct sqlite3 *db, const char *date_prefix, int *out_seq);

/* ── cloud_task_configs (云连携任务配置保存/恢复) ────────────────────── */

/* Save a cloud task configuration before disabling it. */
int db_save_cloud_task_config(struct sqlite3 *db, const char *event_id,
                              const char *task_name, const char *expression,
                              const char *command, const char *disabled_at);

/* Retrieve the most recently disabled cloud task configuration. */
int db_get_cloud_task_config(struct sqlite3 *db, const char *task_name,
                             char *expression_out, size_t elen,
                             char *command_out, size_t clen);

/* Mark a disabled cloud task as restored. */
int db_mark_cloud_task_restored(struct sqlite3 *db, const char *task_name,
                                const char *restored_at);

#endif /* RGUARD_DB_H */
