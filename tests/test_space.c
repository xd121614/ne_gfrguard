#include "test_main.h"
#include <sqlite3.h>
#include "../src/daemon/gfrguardd_space.h"
#include "../src/common/rguard_db.h"
#include "../src/common/rguard_errors.h"
#include <string.h>
#include <unistd.h>

static struct rguard_policy p;
static void init(int max_pct){ memset(&p,0,sizeof(p));
    snprintf(p.store_path,sizeof(p.store_path),"/tmp");
    p.space.max_usage_percent=max_pct; p.space.cleanup_days=30; }

TEST(null_policy){ ASSERT_EQ(space_check(NULL,NULL),0); }
TEST(empty_store_path){ memset(&p,0,sizeof(p)); ASSERT_EQ(space_check(NULL,&p),0); }
TEST(bad_store_path){ init(100); snprintf(p.store_path,sizeof(p.store_path),"/nonexistent-xyz");
    ASSERT_EQ(space_check(NULL,&p),-1); }
TEST(under_limit_no_db_needed){ init(100);
    /* 100% 上限永远不会触发清理，db 为 NULL 也必须正常返回 0 */
    ASSERT_EQ(space_check(NULL,&p),0); }
TEST(over_limit_no_db){ init(0);
    /* 超限但无 db 可清理 → 必须报 -1（M17：旧代码 db 不判空且从不复查） */
    ASSERT_EQ(space_check(NULL,&p),-1); }
TEST(over_limit_still_over){ init(0); unlink("/tmp/tspace.db"); sqlite3 *db=NULL;
    ASSERT_EQ(db_open("/tmp/tspace.db",&db),RGUARD_OK);
    /* 清理后磁盘占用不会变 → 复查仍超限 → -1 */
    ASSERT_EQ(space_check(db,&p),-1); db_close(db); }
TEST(over_limit_cleanup_helps_not){ init(1); unlink("/tmp/tspace.db"); sqlite3 *db=NULL;
    db_open("/tmp/tspace.db",&db);
    ASSERT_EQ(space_check(db,&p),-1); db_close(db); }

int main(void){ RUN_TEST(null_policy);RUN_TEST(empty_store_path);RUN_TEST(bad_store_path);
    RUN_TEST(under_limit_no_db_needed);RUN_TEST(over_limit_no_db);
    RUN_TEST(over_limit_still_over);RUN_TEST(over_limit_cleanup_helps_not);
    return test_summary();}
