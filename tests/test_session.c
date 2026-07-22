#include "test_main.h"
#include "../src/daemon/gfrguardd_session.h"
#include "../src/common/rguard_protocol.h"
#include "../src/common/rguard_hash.h"
#include <string.h>

TEST(fnv_deterministic){ ASSERT_EQ(rguard_fnv1a64("admin@10.0.0.1",14),rguard_fnv1a64("admin@10.0.0.1",14)); }
TEST(fnv_different){ ASSERT_TRUE(rguard_fnv1a64("a@b",3)!=rguard_fnv1a64("a@c",3)); }
/* FNV-1a 64 偏移基：14695981039346656037（0xcbf29ce484222325）。
 * 旧值 ...603 掉了一位数字，根本不是 FNV-1a —— 本用例锁定正确常量。 */
TEST(fnv_empty){ ASSERT_EQ(rguard_fnv1a64("",0),14695981039346656037ULL); }
TEST(create_new){ struct session_table t; session_table_init(&t);
    struct session_state *s=session_find_or_create(&t,"alice@1.1.1.1"); ASSERT_TRUE(s&&s->in_use); }
TEST(find_existing){ struct session_table t; session_table_init(&t);
    struct session_state *a=session_find_or_create(&t,"bob@1.1.1.1");
    struct session_state *b=session_find_or_create(&t,"bob@1.1.1.1"); ASSERT_EQ((long)(a-b),0L); }
TEST(short_window){ struct session_table t; session_table_init(&t);
    struct session_state *s=session_find_or_create(&t,"x"); session_update(s,RGUARD_OP_WRITE,RGUARD_FLAG_RISKY,0);
    ASSERT_EQ((int)s->modified_count,1); s->window_start_10s=time(NULL)-20;
    session_check_window(s,time(NULL),10,30); ASSERT_EQ((int)s->modified_count,0); }
/* 长窗口滑动清零窗口计数，但 is_blocked 必须保留——它是 fanotify 通道的
 * deny 信号，30 余秒后解禁等于防护失效（且与 auto-blacklist 生命周期一致） */
TEST(long_reset){ struct session_table t; session_table_init(&t);
    struct session_state *s=session_find_or_create(&t,"x"); s->is_blocked=true; s->current_event_id[0]='X';
    s->window_start_30s=time(NULL)-40; session_check_window(s,time(NULL),10,30);
    ASSERT_TRUE(s->is_blocked); ASSERT_EQ((int)s->current_event_id[0],0); }
TEST(cnt_modified){ struct session_state s; memset(&s,0,sizeof(s));
    session_update(&s,RGUARD_OP_WRITE,RGUARD_FLAG_RISKY,0); ASSERT_EQ((int)s.modified_count,1); }
TEST(cnt_rename){ struct session_state s; memset(&s,0,sizeof(s));
    session_update(&s,RGUARD_OP_RENAME,0,0); ASSERT_EQ((int)s.rename_count,1); }
TEST(cnt_ext_change){ struct session_state s; memset(&s,0,sizeof(s));
    session_update(&s,RGUARD_OP_RENAME,RGUARD_FLAG_EXT_CHANGE,0); ASSERT_EQ((int)s.ext_change_count,1); }
TEST(cnt_same){ struct session_state s; memset(&s,0,sizeof(s)); s.modified_count=5;
    session_update(&s,RGUARD_OP_CLOSE,RGUARD_FLAG_CONTENT_SAME,0);
    ASSERT_EQ((int)s.modified_count,4); ASSERT_EQ((int)s.content_same_count,1); }
TEST(dir_dedup){ struct session_state s; memset(&s,0,sizeof(s));
    uint64_t h=rguard_fnv1a64("/a",2); session_update(&s,RGUARD_OP_WRITE,RGUARD_FLAG_RISKY,h);
    session_update(&s,RGUARD_OP_WRITE,RGUARD_FLAG_RISKY,h); ASSERT_EQ((int)s.touched_dirs,1); }
/* 新建勒索后缀文件（删原文件+写加密副本模式）走 OPEN+NEW_FILE，不是 RENAME —
 * RANSOM_EXT 在 OPEN 上也必须计分 */
TEST(cnt_ransom_ext_on_create){ struct session_state s; memset(&s,0,sizeof(s));
    session_update(&s,RGUARD_OP_OPEN,RGUARD_FLAG_NEW_FILE|RGUARD_FLAG_RANSOM_EXT,0);
    ASSERT_EQ((int)s.ransom_ext_count,1); ASSERT_EQ((int)s.modified_count,0);
    session_update(&s,RGUARD_OP_RENAME,RGUARD_FLAG_RANSOM_EXT,0);
    ASSERT_EQ((int)s.ransom_ext_count,2); }
int main(void){ RUN_TEST(fnv_deterministic);RUN_TEST(fnv_different);RUN_TEST(fnv_empty);
    RUN_TEST(create_new);RUN_TEST(find_existing);RUN_TEST(short_window);RUN_TEST(long_reset);
    RUN_TEST(cnt_modified);RUN_TEST(cnt_rename);RUN_TEST(cnt_ext_change);RUN_TEST(cnt_same);
    RUN_TEST(dir_dedup);RUN_TEST(cnt_ransom_ext_on_create);return test_summary();}
