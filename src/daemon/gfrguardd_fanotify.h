/*
 * gfrguardd_fanotify.h — Common fanotify infrastructure for FTP / Cloud / Local.
 *
 * Architecture:
 *   - g_fan_fd (FAN_CLASS_CONTENT) → dedicated pthread handles FAN_OPEN_PERM.
 *     Quick backup + blacklist check + ALLOW/DENY.  Events are queued to the
 *     main thread via a SOCK_DGRAM socketpair for process_msg (YARA / entropy / scoring).
 *     Do not add FID reporting flags here: FAN_CLASS_CONTENT + FID
 *     reporting, and permission masks on a FID group, are rejected.
 *   - g_fan_notify_fd (FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME) → main thread
 *     epoll handles FAN_CLOSE_WRITE / FAN_MODIFY / FAN_CREATE / FAN_DELETE /
 *     FAN_RENAME.  FID reporting is required for the dirent events; paths
 *     are reconstructed from parent-dir file handles + names.  These call
 *     process_msg directly —
 *     safe because the perm thread handles any FAN_OPEN_PERM that
 *     process_msg's file opens would trigger.
 *
 * Marks are per-directory inode marks applied recursively (nftw walk at
 * channel setup; new directories are marked from their CREATE/RENAME
 * events before handler dispatch).  fanotify has no perm events for
 * delete/rename/mkdir and no pre-delete content access — those stay
 * detect-then-block, unlike the SMB VFS module which denies up front.
 *
 * Dispatch contract for notify handlers: each fanotify_event carries
 * exactly ONE op bit (FAN_CREATE / FAN_MODIFY / FAN_CLOSE_WRITE /
 * FAN_DELETE / FAN_RENAME), plus FAN_ONDIR when the
 * object is a directory.  Kernel-merged masks are decomposed before
 * dispatch.
 */
#ifndef GFRGUARDD_FANOTIFY_H
#define GFRGUARDD_FANOTIFY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/fanotify.h>

#include "../common/rguard_protocol.h"   /* RGUARD_PATH_MAX */

struct rguard_event_msg;
struct rguard_policy;
struct session_table;
struct sqlite3;

/* ── daemon context (set by main before fanotify modules init) ────────── */

void fanotify_set_daemon_ctx(struct sqlite3 *db, struct session_table *st,
                              struct rguard_policy *policy,
                              int *daily_seq, time_t *day_anchor);

/* ── fanotify event passed to handlers ────────────────────────────────── */

struct fanotify_event {
    uint64_t  mask;          /* ONE op bit, plus FAN_ONDIR if directory */
    int       event_fd;      /* O_RDONLY fd (OPEN_PERM) or -1 (notify) */
    pid_t     pid;           /* process that triggered the event */
    char      path[RGUARD_PATH_MAX]; /* resolved absolute path (old path for renames) */
    char      new_path[RGUARD_PATH_MAX]; /* rename destination path; "" otherwise */
    char      new_name[256]; /* rename destination basename; "" otherwise */
};

enum fan_action { FAN_RES_ALLOW = 1, FAN_RES_DENY = 2 };

typedef enum fan_action (*fanotify_handler_fn)(
    const struct fanotify_event *ev,
    const char *matched_mark_path,
    void *user_data);

/* ── Channel registration ─────────────────────────────────────────────── */

struct fanotify_channel {
    const char         *mark_path;
    fanotify_handler_fn handler;
    void               *user_data;
};

#define FANOTIFY_MAX_CHANNELS 16

/* ── API ──────────────────────────────────────────────────────────────── */

/* Create both fds (content + notify), add notify fd to epoll.
 * Returns 0 on success.  Perm thread is started separately. */
int  fanotify_module_init(int epoll_fd);

/* Start the permission-handling pthread.  Must be called after
 * daemon context and channels are set up. */
int  fanotify_start_perm_thread(void);

/* Signal perm thread to stop and join it. */
void fanotify_stop_perm_thread(void);

/* Add marks to BOTH fds for one directory (or file). */
int  fanotify_mark_add(const char *path);
void fanotify_mark_remove(const char *path);

/* Recursively mark every directory under root_dir on BOTH fds.
 * MAIN THREAD ONLY (static walk context; called from channel setup and
 * from the notify drain on new-directory events).
 * Returns the number of directories marked, -1 on hard error. */
int  fanotify_mark_tree_add(const char *root_dir);

/* Retry channels whose monitor path was missing at setup time.
 * Called from the main loop's periodic timer. */
int  fanotify_retry_pending_channels(void);

/* Flood gate: returns true if a RISKY event for (session, path) should
 * be emitted in the current scoring window.  Keyed by path hash — the
 * file may already be renamed/deleted when notify events are processed,
 * so inode identity is not stable.  Window follows the channel's scoring
 * short window (cloud override aware).  Thread-safe (perm + main). */
bool fanotify_gate_allow(const char *session_key, const char *path,
                         uint8_t source_type);

int  fanotify_reload_marks(const struct fanotify_channel *channels, int n);

int  fanotify_channel_register(const struct fanotify_channel *ch);
int  fanotify_channel_setup(const struct fanotify_channel *ch);
void fanotify_channels_clear(void);

/* Drain notification events from notify fd.  Called from main thread. */
int  fanotify_poll(void);

/* Close fds, join thread, free resources. */
void fanotify_module_destroy(void);

/* ── Shared helpers ───────────────────────────────────────────────────── */

int  fanotify_resolve_path(int event_fd, char *out, size_t out_len);

int  fanotify_do_backup(int src_fd, const char *file_path,
                        const char *store_path, const char *channel_dir);

void fanotify_build_event_msg(const struct fanotify_event *ev,
                              uint8_t source_type,
                              struct rguard_event_msg *msg);

/* Map a notify event onto msg: op_type, flags, new_name and stat
 * metadata (VFS-parity semantics — MODIFY→WRITE|RISKY gated per
 * (session, inode) window, CREATE→OPEN|NEW_FILE, DELETE, RENAME with
 * new_name, CLOSE_WRITE→CLOSE).  Returns false if the event should be
 * dropped (flood-gated or unmapped mask). */
bool fanotify_fill_notify_msg(const struct fanotify_event *ev,
                              const char *session_key,
                              struct rguard_event_msg *msg);

/* Submit event to process_msg (main thread only — not from perm thread). */
bool fanotify_submit_event(const struct rguard_event_msg *msg,
                           const char *session_key);

/* Queue an event from the perm thread to the main thread via the dgram socketpair. */
void fanotify_queue_event(const struct rguard_event_msg *msg);

/* Get notify fd for main thread epoll integration. */
int  fanotify_get_notify_fd(void);

/* Get queue (socketpair) read fd for main thread epoll integration. */
int  fanotify_get_pipe_fd(void);

/* Read and process one queued event from the pipe.  Returns 1 if an
 * event was processed, 0 if pipe was empty, -1 on error. */
int  fanotify_process_queued(void);

/* Accessors. */
struct sqlite3       *fanotify_get_db(void);
struct session_table *fanotify_get_session_table(void);

#endif /* GFRGUARDD_FANOTIFY_H */
