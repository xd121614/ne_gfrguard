#include "test_main.h"
#include "../src/common/rguard_config.h"
#include "../src/common/rguard_errors.h"
#include <stdio.h>

static void w(const char *p,const char *c){ FILE *f=fopen(p,"w");fprintf(f,"%s",c);fclose(f); }
TEST(nonexistent){ struct rguard_policy p; ASSERT_EQ(config_load("/tmp/nope.json",&p),RGUARD_ERR_CONFIG); }
TEST(valid_minimal){ w("/tmp/t1.json","{\"store_path\":\"/tmp\"}"); struct rguard_policy p;
    ASSERT_EQ(config_load("/tmp/t1.json",&p),RGUARD_OK); ASSERT_EQ(p.scoring.window_short,10); }
TEST(invalid_mode){ w("/tmp/t2.json","{\"store_path\":\"/tmp\",\"mode\":\"bogus\"}");
    struct rguard_policy p; ASSERT_EQ(config_load("/tmp/t2.json",&p),RGUARD_ERR_CONFIG); }
TEST(bad_thresholds){ w("/tmp/t3.json","{\"store_path\":\"/tmp\","
    "\"scoring\":{\"thresholds\":{\"warn\":50,\"high\":30,\"critical\":80}}}");
    struct rguard_policy p; ASSERT_EQ(config_load("/tmp/t3.json",&p),RGUARD_ERR_CONFIG); }
TEST(scoring_inline){ w("/tmp/t4.json","{\"store_path\":\"/tmp\","
    "\"scoring\":{\"weights\":{\"modified\":10},\"thresholds\":{\"warn\":10,\"high\":50,\"critical\":90}}}");
    struct rguard_policy p; ASSERT_EQ(config_load("/tmp/t4.json",&p),RGUARD_OK);
    ASSERT_EQ(p.scoring.weights.modified,10); ASSERT_EQ(p.scoring.thresholds.critical,90); }
TEST(whitelist){ w("/tmp/t5.json","{\"store_path\":\"/tmp\","
    "\"whitelist\":{\"users\":[\"alice\",\"bob\"],\"ips\":[\"10.0.0.0/24\"]}}");
    struct rguard_policy p; ASSERT_EQ(config_load("/tmp/t5.json",&p),RGUARD_OK);
    ASSERT_EQ(p.whitelist.user_count,2); ASSERT_EQ(p.whitelist.ip_count,1); }
TEST(blacklist){ w("/tmp/t6.json","{\"store_path\":\"/tmp\","
    "\"blacklist\":{\"users\":[\"eve\"],\"ips\":[\"192.168.1.0/24\"]}}");
    struct rguard_policy p; ASSERT_EQ(config_load("/tmp/t6.json",&p),RGUARD_OK);
    ASSERT_EQ(p.blacklist.user_count,1); ASSERT_EQ(p.blacklist.ip_count,1); }
TEST(cloud_windows_default){ w("/tmp/t7.json","{\"store_path\":\"/tmp\"}");
    struct rguard_policy p; ASSERT_EQ(config_load("/tmp/t7.json",&p),RGUARD_OK);
    ASSERT_EQ(p.scoring.cloud_window_short,60); ASSERT_EQ(p.scoring.cloud_window_long,180); }
TEST(cloud_windows_override){ w("/tmp/t8.json","{\"store_path\":\"/tmp\","
    "\"scoring\":{\"cloud_sync\":{\"window_short\":120,\"window_long\":300}}}");
    struct rguard_policy p; ASSERT_EQ(config_load("/tmp/t8.json",&p),RGUARD_OK);
    ASSERT_EQ(p.scoring.cloud_window_short,120); ASSERT_EQ(p.scoring.cloud_window_long,300);
    ASSERT_EQ(p.scoring.window_short,10); /* 全局窗口不受影响 */ }
int main(void){ RUN_TEST(nonexistent);RUN_TEST(valid_minimal);RUN_TEST(invalid_mode);
    RUN_TEST(bad_thresholds);RUN_TEST(scoring_inline);RUN_TEST(whitelist);RUN_TEST(blacklist);
    RUN_TEST(cloud_windows_default);RUN_TEST(cloud_windows_override);
    return test_summary();}
