/*
 * rguard_protocol.h - IPC message format between gfrguard.so and gfrguardd.
 *
 * Fixed 4608-byte datagram per design doc 3.8.1.
 * NOTE: layout is a wire contract — vfs_gfrguard.so and gfrguardd MUST be
 * rebuilt together on any change (receivers drop size-mismatched datagrams).
 */
#ifndef RGUARD_PROTOCOL_H
#define RGUARD_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>

/* Unified path buffer length — matches Linux PATH_MAX. */
#define RGUARD_PATH_MAX 4096

/* Session key — the ONE place the session identity format is defined.
 * A session is "<username>@<client_ip>".  process_msg derives the key
 * from the message fields, and every producer must derive it from the
 * same fields through this function — building it ad hoc per channel
 * is how lookups drift apart and blocking silently never fires. */
static inline void rguard_make_session_key(char *out, size_t outlen,
                                           const char *username,
                                           const char *client_ip)
{
    snprintf(out, outlen, "%s@%s",
             username ? username : "", client_ip ? client_ip : "");
}

/* msg_type values */
#define RGUARD_MSG_FILE_EVENT     1
#define RGUARD_MSG_VFS_CONNECT    2
#define RGUARD_MSG_VFS_DISCONNECT 3
#define RGUARD_MSG_VFS_BLOCKED    4   /* VFS denied a blacklisted session */

/* source_type values — which subsystem generated this event */
#define RGUARD_SOURCE_SMB        1   /* SMB VFS module */
#define RGUARD_SOURCE_CLOUD_SYNC 2   /* cloud sync protection */
#define RGUARD_SOURCE_FTP        3   /* FTP protection */
#define RGUARD_SOURCE_HOST       4   /* GF2000 host protection */

/* op_type values */
#define RGUARD_OP_OPEN      1
#define RGUARD_OP_WRITE     2
#define RGUARD_OP_TRUNCATE  3
#define RGUARD_OP_RENAME    4
#define RGUARD_OP_DELETE    5
#define RGUARD_OP_CLOSE     6

/* flags bit positions */
#define RGUARD_FLAG_RISKY         (1u << 0)
#define RGUARD_FLAG_BACKED_UP     (1u << 1)
#define RGUARD_FLAG_BACKUP_FAILED (1u << 2)
#define RGUARD_FLAG_EXT_CHANGE    (1u << 3)
#define RGUARD_FLAG_NEW_FILE      (1u << 4)
#define RGUARD_FLAG_CONTENT_SAME  (1u << 5)  /* close: backup == current file */
#define RGUARD_FLAG_RANSOM_EXT    (1u << 6)  /* rename to known ransomware ext */
#define RGUARD_FLAG_HIGH_ENTROPY  (1u << 7)  /* file entropy > threshold */
#define RGUARD_FLAG_YARA_MATCH    (1u << 8)  /* YARA rule matched */

#define RGUARD_MSG_SIZE 4608

/* Wire protocol version, carried in proto_version (former _reserved[0]).
 * Senders MUST set RGUARD_PROTO_VERSION; receivers MUST accept versions
 * 0..RGUARD_PROTO_VERSION (0 = pre-versioning peer) and drop anything
 * newer — a size match alone cannot detect changed field semantics. */
#define RGUARD_PROTO_VERSION 1

/* String fields are fixed-size wire buffers, NOT guaranteed NUL-terminated
 * by the peer: senders must NUL-terminate, receivers must force-terminate
 * before use (the socket is world-writable). */

#pragma pack(push, 1)
struct rguard_event_msg {
    uint8_t  msg_type;        /* offset 0   */
    uint8_t  op_type;         /* offset 1   */
    uint16_t flags;           /* offset 2   */
    int64_t  timestamp;       /* offset 4   */
    uint64_t inode;           /* offset 12  */
    uint64_t file_size;       /* offset 20  */
    int64_t  mtime;           /* offset 28  */
    uint32_t file_uid;        /* offset 36  */
    uint32_t file_gid;        /* offset 40  */
    uint32_t file_mode;       /* offset 44  */
    char     username[64];    /* offset 48  */
    char     client_ip[48];   /* offset 112 */
    char     share_name[64];  /* offset 160 */
    char     file_path[RGUARD_PATH_MAX]; /* offset 224 */
    char     new_name[256];   /* offset 4320 */
    uint8_t  source_type;     /* offset 4576 — RGUARD_SOURCE_* */
    uint8_t  proto_version;   /* offset 4577 — RGUARD_PROTO_VERSION */
    uint8_t  _reserved[30];   /* offset 4578 */
};
#pragma pack(pop)

_Static_assert(sizeof(struct rguard_event_msg) == RGUARD_MSG_SIZE,
               "rguard_event_msg must be exactly 4608 bytes");
_Static_assert(offsetof(struct rguard_event_msg, msg_type)   == 0,   "msg_type@0");
_Static_assert(offsetof(struct rguard_event_msg, op_type)    == 1,   "op_type@1");
_Static_assert(offsetof(struct rguard_event_msg, flags)      == 2,   "flags@2");
_Static_assert(offsetof(struct rguard_event_msg, timestamp)  == 4,   "timestamp@4");
_Static_assert(offsetof(struct rguard_event_msg, inode)      == 12,  "inode@12");
_Static_assert(offsetof(struct rguard_event_msg, file_size)  == 20,  "file_size@20");
_Static_assert(offsetof(struct rguard_event_msg, mtime)      == 28,  "mtime@28");
_Static_assert(offsetof(struct rguard_event_msg, file_uid)   == 36,  "file_uid@36");
_Static_assert(offsetof(struct rguard_event_msg, file_gid)   == 40,  "file_gid@40");
_Static_assert(offsetof(struct rguard_event_msg, file_mode)  == 44,  "file_mode@44");
_Static_assert(offsetof(struct rguard_event_msg, username)   == 48,  "username@48");
_Static_assert(offsetof(struct rguard_event_msg, client_ip)  == 112, "client_ip@112");
_Static_assert(offsetof(struct rguard_event_msg, share_name) == 160, "share_name@160");
_Static_assert(offsetof(struct rguard_event_msg, file_path)  == 224, "file_path@224");
_Static_assert(offsetof(struct rguard_event_msg, new_name)    == 4320, "new_name@4320");
_Static_assert(offsetof(struct rguard_event_msg, source_type) == 4576, "source_type@4576");
_Static_assert(offsetof(struct rguard_event_msg, proto_version) == 4577, "proto_version@4577");
_Static_assert(offsetof(struct rguard_event_msg, _reserved)   == 4578, "_reserved@4578");

#endif /* RGUARD_PROTOCOL_H */
