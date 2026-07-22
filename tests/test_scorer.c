#include "test_main.h"
#include "../src/daemon/gfrguardd_scorer.h"
#include "../src/daemon/gfrguardd_session.h"
#include "../src/common/rguard_config.h"
#include <string.h>

static struct rguard_policy p;
static void init(void){ memset(&p,0,sizeof(p)); p.scoring.weights.modified=3;
    p.scoring.weights.rename_w=4; p.scoring.weights.delete_w=3; p.scoring.weights.dirs=5;
    p.scoring.weights.ext_change=5; p.scoring.weights.ransom_ext=20;
    p.scoring.weights.high_entropy=8; p.scoring.weights.yara_match=40;
    p.scoring.thresholds.warn=30; p.scoring.thresholds.high=60; p.scoring.thresholds.critical=80; }
TEST(zero){ struct session_state s; init();memset(&s,0,sizeof(s));
    scorer_calculate(&s,&p); ASSERT_EQ((int)s.risk_score,0); ASSERT_EQ(s.risk_level,RISK_NORMAL); }
TEST(below_warn){ struct session_state s; init();memset(&s,0,sizeof(s)); s.modified_count=9;
    scorer_calculate(&s,&p); ASSERT_EQ((int)s.risk_score,27); }
TEST(at_warn){ struct session_state s; init();memset(&s,0,sizeof(s)); s.modified_count=10;
    scorer_calculate(&s,&p); ASSERT_EQ((int)s.risk_score,30); ASSERT_EQ(s.risk_level,RISK_SUSPICIOUS); }
TEST(below_high){ struct session_state s; init();memset(&s,0,sizeof(s)); s.modified_count=19;
    scorer_calculate(&s,&p); ASSERT_EQ((int)s.risk_score,57); ASSERT_EQ(s.risk_level,RISK_SUSPICIOUS); }
TEST(at_high){ struct session_state s; init();memset(&s,0,sizeof(s)); s.modified_count=20;
    scorer_calculate(&s,&p); ASSERT_EQ((int)s.risk_score,60); ASSERT_EQ(s.risk_level,RISK_HIGH); }
TEST(below_critical){ struct session_state s; init();memset(&s,0,sizeof(s)); s.modified_count=26;
    scorer_calculate(&s,&p); ASSERT_EQ((int)s.risk_score,78); ASSERT_EQ(s.risk_level,RISK_HIGH); }
TEST(at_critical_80){ struct session_state s; init();memset(&s,0,sizeof(s)); s.rename_count=20;
    scorer_calculate(&s,&p); ASSERT_EQ((int)s.risk_score,80); ASSERT_EQ(s.risk_level,RISK_CRITICAL); }
TEST(at_critical){ struct session_state s; init();memset(&s,0,sizeof(s)); s.modified_count=27;
    scorer_calculate(&s,&p); ASSERT_EQ((int)s.risk_score,81); ASSERT_EQ(s.risk_level,RISK_CRITICAL); }
TEST(clamp){ struct session_state s; init();memset(&s,0,sizeof(s)); s.modified_count=50;
    scorer_calculate(&s,&p); ASSERT_EQ((int)s.risk_score,100); }
TEST(delete_cap){ struct session_state s; init();memset(&s,0,sizeof(s)); s.delete_count=50;
    scorer_calculate(&s,&p); ASSERT_EQ((int)s.risk_score,60); }
TEST(yara_force){ struct session_state s; init();memset(&s,0,sizeof(s)); s.yara_match_count=1;
    scorer_calculate(&s,&p); ASSERT_TRUE((int)s.risk_score>=80); ASSERT_EQ(s.risk_level,RISK_CRITICAL); }
TEST(same_80pct){ struct session_state s; init();memset(&s,0,sizeof(s));
    s.modified_count=2;s.content_same_count=8; scorer_calculate(&s,&p); ASSERT_EQ((int)s.risk_score,0); }
/* 50%≤pct<80% → cap 在 warn-1=29。raw 必须高于 29 才能区分"cap 生效"和"本来就低"：
 * modified=20 → raw=60，same=20 → pct=50% → 必须恰好 29，0 分通过是假阳性 */
TEST(same_50pct){ struct session_state s; init();memset(&s,0,sizeof(s));
    s.modified_count=20;s.content_same_count=20; scorer_calculate(&s,&p); ASSERT_EQ((int)s.risk_score,29); }
/* pct 恰在 80% 边界：4/5=80% → 归零；4/6≈66% → cap 29 */
TEST(same_80pct_edge){ struct session_state s; init();memset(&s,0,sizeof(s));
    s.modified_count=20;s.content_same_count=80; scorer_calculate(&s,&p); ASSERT_EQ((int)s.risk_score,0); }
TEST(same_66pct){ struct session_state s; init();memset(&s,0,sizeof(s));
    s.modified_count=20;s.content_same_count=40; scorer_calculate(&s,&p); ASSERT_EQ((int)s.risk_score,29); }
/* pct<50% 不封顶：modified=20 raw=60，same=10 → pct=33% → 保持 60 */
TEST(same_33pct_nocap){ struct session_state s; init();memset(&s,0,sizeof(s));
    s.modified_count=20;s.content_same_count=10; scorer_calculate(&s,&p); ASSERT_EQ((int)s.risk_score,60); }
TEST(weighted){ struct session_state s; init();memset(&s,0,sizeof(s));
    s.modified_count=5;s.rename_count=2;s.delete_count=1; scorer_calculate(&s,&p);
    ASSERT_EQ((int)s.risk_score,26); }
TEST(weighted_entropy_ransom){ struct session_state s; init();memset(&s,0,sizeof(s));
    s.high_entropy_count=5;s.ransom_ext_count=2; scorer_calculate(&s,&p);
    ASSERT_EQ((int)s.risk_score,80); ASSERT_EQ(s.risk_level,RISK_CRITICAL); }
int main(void){ RUN_TEST(zero);RUN_TEST(below_warn);RUN_TEST(at_warn);
    RUN_TEST(below_high);RUN_TEST(at_high);RUN_TEST(below_critical);RUN_TEST(at_critical_80);
    RUN_TEST(at_critical);RUN_TEST(clamp);RUN_TEST(delete_cap);RUN_TEST(yara_force);RUN_TEST(same_80pct);
    RUN_TEST(same_50pct);RUN_TEST(same_80pct_edge);RUN_TEST(same_66pct);RUN_TEST(same_33pct_nocap);
    RUN_TEST(weighted);RUN_TEST(weighted_entropy_ransom);return test_summary();}
