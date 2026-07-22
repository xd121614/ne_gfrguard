/* test_restore.c — restore_trigger_auto / restore_reap_children（此前零覆盖）。
 * RECOVER_BIN 编译期替换为 /bin/true：fork+exec 全链路跑真，
 * 但不触碰真实 DB/备份目录。 */
#include "test_main.h"
#include "../src/daemon/gfrguardd_restore.h"
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

static struct rguard_policy p;
static void init(int enabled,int delay){ memset(&p,0,sizeof(p));
    p.auto_restore.enabled=enabled; p.auto_restore.delay_seconds=delay; }

static int zombies(void){ int n=0,st; while(waitpid(-1,&st,WNOHANG)>0)n++; return n; }

TEST(disabled_no_fork){ init(0,0);
    ASSERT_EQ(restore_trigger_auto(&p,"evt-x"),0);
    ASSERT_EQ(zombies(),0); }
TEST(null_policy){ ASSERT_EQ(restore_trigger_auto(NULL,"evt-x"),0); }
TEST(empty_event_id){ init(1,0);
    ASSERT_EQ(restore_trigger_auto(&p,""),-1);
    ASSERT_EQ(restore_trigger_auto(&p,NULL),-1); }
TEST(enabled_fork_exec_reap){ init(1,0);
    ASSERT_EQ(restore_trigger_auto(&p,"evt-test-001"),0);
    /* 子进程 exec /bin/true 立即退出；reap 必须收走且记日志归属正确 */
    usleep(200000);
    restore_reap_children();
    ASSERT_EQ(zombies(),0); }
TEST(delay_negative_guarded){ init(1,-1);
    /* 负 delay 不得 cast unsigned 睡几百年——guard 按 0 处理立即 exec */
    ASSERT_EQ(restore_trigger_auto(&p,"evt-neg"),0);
    usleep(200000); restore_reap_children();
    ASSERT_EQ(zombies(),0); }

int main(void){ RUN_TEST(disabled_no_fork);RUN_TEST(null_policy);
    RUN_TEST(empty_event_id);RUN_TEST(enabled_fork_exec_reap);
    RUN_TEST(delay_negative_guarded);
    return test_summary();}
