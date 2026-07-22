#include "test_main.h"
#include "../src/common/rguard_protocol.h"
#include <string.h>

TEST(struct_size)   { ASSERT_EQ(sizeof(struct rguard_event_msg), (size_t)4608); }
TEST(field_offsets) {
    ASSERT_EQ(offsetof(struct rguard_event_msg, msg_type),   (size_t)0);
    ASSERT_EQ(offsetof(struct rguard_event_msg, op_type),    (size_t)1);
    ASSERT_EQ(offsetof(struct rguard_event_msg, flags),      (size_t)2);
    ASSERT_EQ(offsetof(struct rguard_event_msg, timestamp),  (size_t)4);
    ASSERT_EQ(offsetof(struct rguard_event_msg, inode),      (size_t)12);
    ASSERT_EQ(offsetof(struct rguard_event_msg, file_size),  (size_t)20);
    ASSERT_EQ(offsetof(struct rguard_event_msg, mtime),      (size_t)28);
    ASSERT_EQ(offsetof(struct rguard_event_msg, file_uid),   (size_t)36);
    ASSERT_EQ(offsetof(struct rguard_event_msg, file_gid),   (size_t)40);
    ASSERT_EQ(offsetof(struct rguard_event_msg, file_mode),  (size_t)44);
    ASSERT_EQ(offsetof(struct rguard_event_msg, username),   (size_t)48);
    ASSERT_EQ(offsetof(struct rguard_event_msg, client_ip),  (size_t)112);
    ASSERT_EQ(offsetof(struct rguard_event_msg, share_name), (size_t)160);
    ASSERT_EQ(offsetof(struct rguard_event_msg, file_path),  (size_t)224);
    ASSERT_EQ(offsetof(struct rguard_event_msg, new_name),   (size_t)4320);
    ASSERT_EQ(offsetof(struct rguard_event_msg, source_type),(size_t)4576);
    ASSERT_EQ(offsetof(struct rguard_event_msg, proto_version),(size_t)4577);
    ASSERT_EQ(offsetof(struct rguard_event_msg, _reserved),  (size_t)4578);
}
TEST(proto_version) {
    /* M26：版本字段占原 _reserved[0]，报文尺寸不变（旧对端读到 0，向后兼容） */
    ASSERT_EQ(RGUARD_PROTO_VERSION, 1);
    struct rguard_event_msg m; memset(&m, 0, sizeof(m));
    ASSERT_EQ((int)m.proto_version, 0);   /* 预版本对端语义 */
    ASSERT_EQ(sizeof(m._reserved), (size_t)30);
}
TEST(flags_no_overlap) {
    unsigned f[] = { RGUARD_FLAG_RISKY, RGUARD_FLAG_BACKED_UP, RGUARD_FLAG_BACKUP_FAILED,
        RGUARD_FLAG_EXT_CHANGE, RGUARD_FLAG_NEW_FILE, RGUARD_FLAG_CONTENT_SAME,
        RGUARD_FLAG_RANSOM_EXT, RGUARD_FLAG_HIGH_ENTROPY, RGUARD_FLAG_YARA_MATCH };
    int n = sizeof(f)/sizeof(f[0]);
    for (int i = 0; i < n; i++) {
        ASSERT_TRUE(f[i] > 0 && f[i] <= 0xFFFF);
        for (int j = i+1; j < n; j++) ASSERT_TRUE((f[i] & f[j]) == 0);
    }
}
TEST(op_type_range) {
    ASSERT_EQ(RGUARD_OP_OPEN, 1); ASSERT_EQ(RGUARD_OP_WRITE, 2);
    ASSERT_EQ(RGUARD_OP_TRUNCATE, 3); ASSERT_EQ(RGUARD_OP_RENAME, 4);
    ASSERT_EQ(RGUARD_OP_DELETE, 5); ASSERT_EQ(RGUARD_OP_CLOSE, 6);
}
int main(void) { RUN_TEST(struct_size); RUN_TEST(field_offsets);
    RUN_TEST(proto_version); RUN_TEST(flags_no_overlap); RUN_TEST(op_type_range); return test_summary(); }
