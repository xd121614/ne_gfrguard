#define _POSIX_C_SOURCE 200809L
#include "rguard_db.h"
#include "rguard_errors.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *SCHEMA_SQL =
    "PRAGMA journal_mode=WAL;"
    "PRAGMA synchronous=NORMAL;"
    "CREATE TABLE IF NOT EXISTS protected_files ("
    " id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " event_id TEXT NOT NULL,"
    " original_path TEXT NOT NULL,"
    " backup_path TEXT NOT NULL,"
    " share_name TEXT NOT NULL,"
    " username TEXT NOT NULL,"
    " client_ip TEXT NOT NULL,"
    " inode INTEGER NOT NULL,"
    " mtime INTEGER NOT NULL,"
    " file_size INTEGER NOT NULL,"
    " file_uid INTEGER NOT NULL,"
    " file_gid INTEGER NOT NULL,"
    " file_mode INTEGER NOT NULL,"
    " op_type INTEGER NOT NULL DEFAULT 0,"
    " protected_at TEXT NOT NULL,"
    " restore_status TEXT NOT NULL DEFAULT 'pending',"
    " restored_at TEXT,"
    " UNIQUE(event_id, original_path)"
    ");"
    "CREATE TABLE IF NOT EXISTS events ("
    " id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " event_id TEXT UNIQUE NOT NULL,"
    " session_key TEXT NOT NULL,"
    " username TEXT NOT NULL,"
    " client_ip TEXT NOT NULL,"
    " pname TEXT NOT NULL DEFAULT '',"
    " started_at TEXT NOT NULL,"
    " ended_at TEXT,"
    " files_protected INTEGER DEFAULT 0,"
    " files_affected INTEGER DEFAULT 0,"
    " peak_risk_score INTEGER DEFAULT 0,"
    " action_taken TEXT,"
    " status TEXT NOT NULL DEFAULT 'active'"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_pf_event   ON protected_files(event_id);"
    "CREATE INDEX IF NOT EXISTS idx_pf_path    ON protected_files(original_path);"
    "CREATE INDEX IF NOT EXISTS idx_pf_status  ON protected_files(restore_status);"
    "CREATE INDEX IF NOT EXISTS idx_pf_session ON protected_files(username, client_ip);"
    "CREATE INDEX IF NOT EXISTS idx_evt_session ON events(session_key);"
    "CREATE INDEX IF NOT EXISTS idx_evt_status  ON events(status);"
    "CREATE TABLE IF NOT EXISTS created_files ("
    " id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " event_id TEXT NOT NULL,"
    " file_path TEXT NOT NULL,"
    " share_name TEXT NOT NULL,"
    " username TEXT NOT NULL,"
    " client_ip TEXT NOT NULL,"
    " created_at TEXT NOT NULL"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_cf_event ON created_files(event_id);"
    "CREATE TABLE IF NOT EXISTS cloud_task_configs ("
    " id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " event_id TEXT NOT NULL,"
    " task_name TEXT NOT NULL,"
    " expression TEXT NOT NULL,"
    " command TEXT NOT NULL,"
    " status TEXT DEFAULT 'disabled',"
    " disabled_at TEXT,"
    " restored_at TEXT"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_ctc_task ON cloud_task_configs(task_name);"
    "CREATE INDEX IF NOT EXISTS idx_ctc_event ON cloud_task_configs(event_id);"
    "CREATE INDEX IF NOT EXISTS idx_ctc_status ON cloud_task_configs(status);";

int db_open(const char *db_path, sqlite3 **out_db)
{
    if (!db_path || !out_db) return RGUARD_ERR_DB;
    sqlite3 *db = NULL;
    int rc = sqlite3_open(db_path, &db);
    if (rc != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return RGUARD_ERR_DB;
    }
    char *errmsg = NULL;
    rc = sqlite3_exec(db, SCHEMA_SQL, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "db_open: schema: %s\n", errmsg ? errmsg : "?");
        sqlite3_free(errmsg);
        sqlite3_close(db);
        return RGUARD_ERR_DB;
    }
    /* Migration: add op_type column for existing databases (ignore error if exists) */
    sqlite3_exec(db, "ALTER TABLE protected_files ADD COLUMN op_type INTEGER NOT NULL DEFAULT 0;",
                 NULL, NULL, NULL);
    /* Migration: add unique constraint on (event_id, original_path).
     * SQLite cannot ALTER TABLE to add constraints, so create unique index instead.
     * On a pre-existing database with duplicate rows this FAILS — dedup
     * silently broken.  That must be loud, not swallowed. */
    {
        char *merr = NULL;
        if (sqlite3_exec(db,
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_pf_event_path"
                " ON protected_files(event_id, original_path);",
                NULL, NULL, &merr) != SQLITE_OK) {
            fprintf(stderr, "db_open: unique index migration failed: %s\n",
                    merr ? merr : "?");
            sqlite3_free(merr);
            sqlite3_close(db);
            return RGUARD_ERR_DB;
        }
    }
    /* Migration: add pname column for process-name traceability (FTP/Local/Cloud). */
    sqlite3_exec(db, "ALTER TABLE events ADD COLUMN pname TEXT NOT NULL DEFAULT '';",
                 NULL, NULL, NULL);
    *out_db = db;
    return RGUARD_OK;
}

int db_close(sqlite3 *db)
{
    if (!db) return RGUARD_OK;
    /* SQLITE_BUSY means unfinalized statements — the handle leaks if we
     * ignore it.  close_v2 zombifies instead and frees when possible. */
    if (sqlite3_close(db) != SQLITE_OK) {
        sqlite3_close_v2(db);
        return RGUARD_ERR_DB;
    }
    return RGUARD_OK;
}

int db_insert_protected_file(sqlite3 *db, const struct rguard_protected_file *pf)
{
    if (!db || !pf) return RGUARD_ERR_DB;
    static const char *SQL =
        "INSERT OR IGNORE INTO protected_files(event_id, original_path, backup_path,"
        " share_name, username, client_ip, inode, mtime, file_size,"
        " file_uid, file_gid, file_mode, op_type, protected_at, restore_status, restored_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &st, NULL) != SQLITE_OK) return RGUARD_ERR_DB;
    sqlite3_bind_text (st, 1,  pf->event_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (st, 2,  pf->original_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (st, 3,  pf->backup_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (st, 4,  pf->share_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (st, 5,  pf->username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (st, 6,  pf->client_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 7,  pf->inode);
    sqlite3_bind_int64(st, 8,  pf->mtime);
    sqlite3_bind_int64(st, 9,  pf->file_size);
    sqlite3_bind_int  (st, 10, pf->file_uid);
    sqlite3_bind_int  (st, 11, pf->file_gid);
    sqlite3_bind_int  (st, 12, pf->file_mode);
    sqlite3_bind_int  (st, 13, pf->op_type);
    sqlite3_bind_text (st, 14, pf->protected_at, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (st, 15, pf->restore_status[0] ? pf->restore_status : "pending", -1, SQLITE_TRANSIENT);
    if (pf->restored_at[0])
        sqlite3_bind_text(st, 16, pf->restored_at, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(st, 16);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? RGUARD_OK : RGUARD_ERR_DB;
}

int db_insert_event(sqlite3 *db, const struct rguard_event_record *ev)
{
    if (!db || !ev) return RGUARD_ERR_DB;
    static const char *SQL =
        "INSERT OR IGNORE INTO events(event_id, session_key, username, client_ip,"
        " pname, started_at, ended_at, files_protected, files_affected,"
        " peak_risk_score, action_taken, status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?);";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &st, NULL) != SQLITE_OK) return RGUARD_ERR_DB;
    sqlite3_bind_text (st, 1, ev->event_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (st, 2, ev->session_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (st, 3, ev->username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (st, 4, ev->client_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (st, 5, ev->pname[0] ? ev->pname : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (st, 6, ev->started_at, -1, SQLITE_TRANSIENT);
    if (ev->ended_at[0])
        sqlite3_bind_text(st, 7, ev->ended_at, -1, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(st, 7);
    sqlite3_bind_int64(st, 8, ev->files_protected);
    sqlite3_bind_int64(st, 9, ev->files_affected);
    sqlite3_bind_int  (st, 10, ev->peak_risk_score);
    sqlite3_bind_text (st, 11, ev->action_taken[0] ? ev->action_taken : "none", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (st, 12, ev->status[0] ? ev->status : "active", -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? RGUARD_OK : RGUARD_ERR_DB;
}

int db_upsert_event(sqlite3 *db, const struct rguard_event_record *ev)
{
    if (!db || !ev || !ev->event_id[0]) return RGUARD_ERR_DB;
    static const char *SQL =
        "INSERT INTO events(event_id, session_key, username, client_ip,"
        " pname, started_at, ended_at, files_protected, files_affected,"
        " peak_risk_score, action_taken, status)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"
        " ON CONFLICT(event_id) DO UPDATE SET"
        " session_key=COALESCE(excluded.session_key, events.session_key),"
        " username=COALESCE(excluded.username, events.username),"
        " client_ip=COALESCE(excluded.client_ip, events.client_ip),"
        " pname=COALESCE(excluded.pname, events.pname),"
        " started_at=COALESCE(excluded.started_at, events.started_at),"
        " ended_at=COALESCE(excluded.ended_at, events.ended_at),"
        " files_protected=MAX(events.files_protected, excluded.files_protected),"
        " files_affected=MAX(events.files_affected, excluded.files_affected),"
        " peak_risk_score=MAX(events.peak_risk_score, excluded.peak_risk_score),"
        " action_taken=COALESCE(excluded.action_taken, events.action_taken),"
        " status=COALESCE(excluded.status, events.status);";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &st, NULL) != SQLITE_OK) return RGUARD_ERR_DB;
    sqlite3_bind_text (st, 1, ev->event_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (st, 2, ev->session_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (st, 3, ev->username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (st, 4, ev->client_ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (st, 5, ev->pname[0] ? ev->pname : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (st, 6, ev->started_at[0] ? ev->started_at : "", -1, SQLITE_TRANSIENT);
    if (ev->ended_at[0]) sqlite3_bind_text(st, 7, ev->ended_at, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_null(st, 7);
    sqlite3_bind_int64(st, 8, ev->files_protected);
    sqlite3_bind_int64(st, 9, ev->files_affected);
    sqlite3_bind_int  (st, 10, ev->peak_risk_score);
    if (ev->action_taken[0]) sqlite3_bind_text(st, 11, ev->action_taken, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_text(st, 11, "none", -1, SQLITE_STATIC);
    /* status is NOT NULL — binding NULL here made every upsert with an
     * empty status fail outright.  Default like db_insert_event. */
    if (ev->status[0]) sqlite3_bind_text(st, 12, ev->status, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_text(st, 12, "active", -1, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? RGUARD_OK : RGUARD_ERR_DB;
}

int db_update_event(sqlite3 *db, const char *event_id,
                    long long files_protected, long long files_affected,
                    int peak_risk_score, const char *action_taken,
                    const char *status, const char *ended_at)
{
    if (!db || !event_id) return RGUARD_ERR_DB;
    static const char *SQL =
        "UPDATE events SET files_protected=MAX(files_protected,?),"
        " files_affected=MAX(files_affected,?),"
        " peak_risk_score=MAX(peak_risk_score,?),"
        " action_taken=COALESCE(?, action_taken),"
        " status=COALESCE(?, status), ended_at=COALESCE(?, ended_at)"
        " WHERE event_id=?;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &st, NULL) != SQLITE_OK) return RGUARD_ERR_DB;
    sqlite3_bind_int64(st, 1, files_protected);
    sqlite3_bind_int64(st, 2, files_affected);
    sqlite3_bind_int  (st, 3, peak_risk_score);
    if (action_taken && *action_taken) sqlite3_bind_text(st, 4, action_taken, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_null(st, 4);
    if (status && *status) sqlite3_bind_text(st, 5, status, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_null(st, 5);
    if (ended_at && *ended_at) sqlite3_bind_text(st, 6, ended_at, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_null(st, 6);
    sqlite3_bind_text(st, 7, event_id, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? RGUARD_OK : RGUARD_ERR_DB;
}

int db_update_restore_status(sqlite3 *db, long long id,
                             const char *status, const char *restored_at)
{
    if (!db || !status) return RGUARD_ERR_DB;
    static const char *SQL =
        "UPDATE protected_files SET restore_status=?, restored_at=? WHERE id=?;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &st, NULL) != SQLITE_OK) return RGUARD_ERR_DB;
    sqlite3_bind_text (st, 1, status, -1, SQLITE_TRANSIENT);
    if (restored_at && *restored_at) sqlite3_bind_text(st, 2, restored_at, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_null(st, 2);
    sqlite3_bind_int64(st, 3, id);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? RGUARD_OK : RGUARD_ERR_DB;
}

static int row_to_pf(sqlite3_stmt *st, struct rguard_protected_file *pf)
{
    memset(pf, 0, sizeof(*pf));
    pf->id            = sqlite3_column_int64(st, 0);
    const unsigned char *t;
#define SCOPY(idx, field) do {                              \
        t = sqlite3_column_text(st, idx);                   \
        if (t) snprintf(pf->field, sizeof(pf->field), "%s", (const char *)t); \
    } while (0)
    SCOPY(1,  event_id);
    SCOPY(2,  original_path);
    SCOPY(3,  backup_path);
    SCOPY(4,  share_name);
    SCOPY(5,  username);
    SCOPY(6,  client_ip);
    pf->inode      = sqlite3_column_int64(st, 7);
    pf->mtime      = sqlite3_column_int64(st, 8);
    pf->file_size  = sqlite3_column_int64(st, 9);
    pf->file_uid   = sqlite3_column_int  (st, 10);
    pf->file_gid   = sqlite3_column_int  (st, 11);
    pf->file_mode  = sqlite3_column_int  (st, 12);
    SCOPY(13, protected_at);
    SCOPY(14, restore_status);
    SCOPY(15, restored_at);
#undef SCOPY
    return 0;
}

static const char *PF_SELECT_COLS =
    "id, event_id, original_path, backup_path, share_name, username,"
    " client_ip, inode, mtime, file_size, file_uid, file_gid, file_mode,"
    " protected_at, restore_status, COALESCE(restored_at,'')";

int db_query_by_event(sqlite3 *db, const char *event_id, rguard_pf_cb cb, void *ctx)
{
    if (!db || !event_id || !cb) return RGUARD_ERR_DB;
    char sql[512];
    snprintf(sql, sizeof(sql),
             "SELECT %s FROM protected_files WHERE event_id=?;", PF_SELECT_COLS);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return RGUARD_ERR_DB;
    sqlite3_bind_text(st, 1, event_id, -1, SQLITE_TRANSIENT);

    /* Collect all rows first, then finalize the SELECT before invoking
     * callbacks.  This avoids SQLITE_LOCKED when the callback does
     * UPDATE/INSERT on the same table via the same connection. */
    int cap = 64, count = 0;
    struct rguard_protected_file *arr = malloc(cap * sizeof(*arr));
    if (!arr) { sqlite3_finalize(st); return RGUARD_ERR_DB; }
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (count >= cap) {
            cap *= 2;
            struct rguard_protected_file *tmp = realloc(arr, cap * sizeof(*arr));
            if (!tmp) { free(arr); sqlite3_finalize(st); return RGUARD_ERR_DB; }
            arr = tmp;
        }
        row_to_pf(st, &arr[count]);
        count++;
    }
    sqlite3_finalize(st);

    for (int i = 0; i < count; i++) {
        if (cb(&arr[i], ctx) != 0) break;
    }
    free(arr);
    return RGUARD_OK;
}

int db_query_by_path(sqlite3 *db, const char *path, rguard_pf_cb cb, void *ctx)
{
    if (!db || !path || !cb) return RGUARD_ERR_DB;
    char sql[512];
    snprintf(sql, sizeof(sql),
             "SELECT %s FROM protected_files WHERE original_path=?;", PF_SELECT_COLS);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return RGUARD_ERR_DB;
    sqlite3_bind_text(st, 1, path, -1, SQLITE_TRANSIENT);

    int cap = 64, count = 0;
    struct rguard_protected_file *arr = malloc(cap * sizeof(*arr));
    if (!arr) { sqlite3_finalize(st); return RGUARD_ERR_DB; }
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (count >= cap) {
            cap *= 2;
            struct rguard_protected_file *tmp = realloc(arr, cap * sizeof(*arr));
            if (!tmp) { free(arr); sqlite3_finalize(st); return RGUARD_ERR_DB; }
            arr = tmp;
        }
        row_to_pf(st, &arr[count]);
        count++;
    }
    sqlite3_finalize(st);

    for (int i = 0; i < count; i++) {
        if (cb(&arr[i], ctx) != 0) break;
    }
    free(arr);
    return RGUARD_OK;
}

int db_count_pending(sqlite3 *db, long long *out_count)
{
    if (!db || !out_count) return RGUARD_ERR_DB;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT COUNT(*) FROM protected_files WHERE restore_status='pending';",
        -1, &st, NULL) != SQLITE_OK) return RGUARD_ERR_DB;
    *out_count = 0;
    if (sqlite3_step(st) == SQLITE_ROW) *out_count = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return RGUARD_OK;
}

int db_cleanup_restored(sqlite3 *db, int older_than_days, long long *out_deleted)
{
    /* Negative days would build an invalid SQLite modifier ("--5 days"),
     * silently deleting nothing while reporting success. */
    if (!db || older_than_days < 0) return RGUARD_ERR_DB;
    sqlite3_stmt *st = NULL;
    static const char *SQL =
        "DELETE FROM protected_files WHERE restore_status='restored'"
        " AND restored_at IS NOT NULL"
        " AND restored_at < datetime('now', 'localtime', ?);";
    if (sqlite3_prepare_v2(db, SQL, -1, &st, NULL) != SQLITE_OK) return RGUARD_ERR_DB;
    char modifier[64];
    snprintf(modifier, sizeof(modifier), "-%d days", older_than_days);
    sqlite3_bind_text(st, 1, modifier, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return RGUARD_ERR_DB;
    if (out_deleted) *out_deleted = sqlite3_changes(db);
    return RGUARD_OK;
}

int db_insert_created_file(sqlite3 *db, const char *event_id,
                           const char *file_path, const char *share_name,
                           const char *username, const char *client_ip,
                           const char *created_at)
{
    if (!db || !event_id || !file_path) return RGUARD_ERR_DB;
    static const char *SQL =
        "INSERT INTO created_files(event_id, file_path, share_name,"
        " username, client_ip, created_at) VALUES(?,?,?,?,?,?);";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &st, NULL) != SQLITE_OK) return RGUARD_ERR_DB;
    sqlite3_bind_text(st, 1, event_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, file_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, share_name ? share_name : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, username ? username : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, client_ip ? client_ip : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, created_at ? created_at : "", -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? RGUARD_OK : RGUARD_ERR_DB;
}

int db_query_created_by_event(sqlite3 *db, const char *event_id,
                              rguard_cf_cb cb, void *ctx)
{
    if (!db || !event_id || !cb) return RGUARD_ERR_DB;
    static const char *SQL =
        "SELECT id, file_path FROM created_files WHERE event_id=?;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &st, NULL) != SQLITE_OK) return RGUARD_ERR_DB;
    sqlite3_bind_text(st, 1, event_id, -1, SQLITE_TRANSIENT);

    /* Collect rows first, run callbacks after finalize: the callback
     * may write the same table on this connection (restore deletes
     * created files), which fails with SQLITE_LOCKED while a read is
     * in flight — and the column text pointer dangles past finalize. */
    struct cf_row { long long id; char *path; };
    struct cf_row *rows = NULL;
    size_t n = 0, cap = 0, i;
    int rc = RGUARD_OK;
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (n == cap) {
            size_t ncap = cap ? cap * 2 : 16;
            struct cf_row *nr = realloc(rows, ncap * sizeof(*nr));
            if (!nr) { rc = RGUARD_ERR_DB; break; }
            rows = nr; cap = ncap;
        }
        const char *p = (const char *)sqlite3_column_text(st, 1);
        rows[n].path = strdup(p ? p : "");
        if (!rows[n].path) { rc = RGUARD_ERR_DB; break; }
        rows[n].id = sqlite3_column_int64(st, 0);
        n++;
    }
    sqlite3_finalize(st);

    if (rc == RGUARD_OK) {
        for (i = 0; i < n; i++) {
            if (cb(rows[i].id, rows[i].path, ctx) != 0) break;
        }
    }
    for (i = 0; i < n; i++) free(rows[i].path);
    free(rows);
    return rc;
}

int db_delete_created_file(sqlite3 *db, long long id)
{
    if (!db) return RGUARD_ERR_DB;
    static const char *SQL = "DELETE FROM created_files WHERE id=?;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &st, NULL) != SQLITE_OK) return RGUARD_ERR_DB;
    sqlite3_bind_int64(st, 1, id);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? RGUARD_OK : RGUARD_ERR_DB;
}

int db_get_max_daily_seq(sqlite3 *db, const char *date_prefix, int *out_seq)
{
    /* date_prefix goes into a LIKE pattern — reject wildcard chars
     * instead of adding ESCAPE plumbing; prefixes are dates (digits). */
    if (!db || !date_prefix || !out_seq || strpbrk(date_prefix, "%_")) return RGUARD_ERR_DB;
    /* Match event_id like 'evt-YYYYMMDD-%' and extract the trailing integer. */
    static const char *SQL =
        "SELECT MAX(CAST(SUBSTR(event_id, LENGTH(?)+2) AS INTEGER))"
        " FROM events WHERE event_id LIKE ? || '-%';";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &st, NULL) != SQLITE_OK) return RGUARD_ERR_DB;
    char prefix[32];
    snprintf(prefix, sizeof(prefix), "evt-%s", date_prefix);
    sqlite3_bind_text(st, 1, prefix, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, prefix, -1, SQLITE_TRANSIENT);
    *out_seq = 0;
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL)
        *out_seq = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return RGUARD_OK;
}

/* ── cloud_task_configs table ─────────────────────────────────────── */

int db_save_cloud_task_config(sqlite3 *db, const char *event_id,
                              const char *task_name, const char *expression,
                              const char *command, const char *disabled_at)
{
    if (!db || !task_name || !expression || !command) return RGUARD_ERR_DB;
    static const char *SQL =
        "INSERT INTO cloud_task_configs"
        " (event_id, task_name, expression, command, status, disabled_at)"
        " VALUES(?,?,?,?,?,?);";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &st, NULL) != SQLITE_OK) return RGUARD_ERR_DB;
    sqlite3_bind_text(st, 1, event_id ? event_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, task_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, expression, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, command, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, "disabled", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, disabled_at ? disabled_at : "", -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? RGUARD_OK : RGUARD_ERR_DB;
}

int db_get_cloud_task_config(sqlite3 *db, const char *task_name,
                             char *expression_out, size_t elen,
                             char *command_out, size_t clen)
{
    if (!db || !task_name || !expression_out || !command_out) return RGUARD_ERR_DB;
    static const char *SQL =
        "SELECT expression, command FROM cloud_task_configs"
        " WHERE task_name=? AND status='disabled' ORDER BY id DESC LIMIT 1;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &st, NULL) != SQLITE_OK) return RGUARD_ERR_DB;
    sqlite3_bind_text(st, 1, task_name, -1, SQLITE_TRANSIENT);
    int found = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *expr = (const char *)sqlite3_column_text(st, 0);
        const char *cmd  = (const char *)sqlite3_column_text(st, 1);
        if (expr) snprintf(expression_out, elen, "%s", expr);
        else expression_out[0] = '\0';
        if (cmd) snprintf(command_out, clen, "%s", cmd);
        else command_out[0] = '\0';
        found = 1;
    }
    sqlite3_finalize(st);
    return found ? RGUARD_OK : RGUARD_ERR_NOT_FOUND;
}

int db_mark_cloud_task_restored(sqlite3 *db, const char *task_name,
                                const char *restored_at)
{
    if (!db || !task_name) return RGUARD_ERR_DB;
    static const char *SQL =
        "UPDATE cloud_task_configs SET status='restored', restored_at=?"
        " WHERE task_name=? AND status='disabled';";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &st, NULL) != SQLITE_OK) return RGUARD_ERR_DB;
    sqlite3_bind_text(st, 1, restored_at ? restored_at : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, task_name, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? RGUARD_OK : RGUARD_ERR_DB;
}
