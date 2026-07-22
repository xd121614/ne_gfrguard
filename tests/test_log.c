#include "test_main.h"
#include "../src/common/rguard_log.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *LP = "/tmp/tlog.log";
static int line_count(void){ FILE *f=fopen(LP,"r"); if(!f)return -1; int n=0,c;
    while((c=fgetc(f))!=EOF) { if(c=='\n') n++; }
    fclose(f); return n; }
static void slurp(char *out,size_t n){ FILE *f=fopen(LP,"r"); size_t r=0;
    if(f){r=fread(out,1,n-1,f);fclose(f);} out[r]=0; }

TEST(init_write){ unlink(LP);
    ASSERT_EQ(rguard_log_init(LP,"test",LOG_DEBUG),0);
    rguard_log_write(LOG_INFO,"EV","u@1.1.1.1","{\"k\":1}");
    rguard_log_close();
    ASSERT_EQ(line_count(),1);
    char b[1024]; slurp(b,sizeof(b));
    ASSERT_TRUE(strstr(b,"|INFO|EV|test|u@1.1.1.1|{\"k\":1}\n")!=NULL); }
TEST(level_filter){ unlink(LP);
    ASSERT_EQ(rguard_log_init(LP,"test",LOG_WARN),0);
    rguard_log_write(LOG_DEBUG,"DBG",NULL,NULL);
    rguard_log_write(LOG_INFO,"INF",NULL,NULL);
    rguard_log_write(LOG_ERROR,"ERR",NULL,NULL);
    rguard_log_close();
    ASSERT_EQ(line_count(),1);
    char b[1024]; slurp(b,sizeof(b)); ASSERT_TRUE(strstr(b,"|ERR|")!=NULL); }
TEST(set_level_runtime){ unlink(LP);
    ASSERT_EQ(rguard_log_init(LP,"test",LOG_ERROR),0);
    rguard_log_set_level(LOG_DEBUG);
    rguard_log_write(LOG_DEBUG,"DBG2",NULL,NULL);
    rguard_log_close();
    ASSERT_EQ(line_count(),1); }
/* M27：session_key/detail_json 里的 \n \r 必须转义——
 * 用户可控字段（session_key 含客户端输入）否则可伪造整行日志 */
TEST(no_log_injection){ unlink(LP);
    ASSERT_EQ(rguard_log_init(LP,"test",LOG_DEBUG),0);
    rguard_log_write(LOG_WARN,"EV","attacker@1.2.3.4\n2026-01-01T00:00:00|ERROR|FAKE|x|y|{}",
                     "{\"note\":\"line1\nline2\r\nline3\"}");
    rguard_log_close();
    ASSERT_EQ(line_count(),1);  /* 一条写入只产生一行 */
    char b[2048]; slurp(b,sizeof(b));
    ASSERT_TRUE(strstr(b,"FAKE")!=NULL);            /* 内容保留 */
    ASSERT_TRUE(strstr(b,"\\n")!=NULL);             /* 但以转义形式 */
    ASSERT_TRUE(strstr(b,"\n2026-01-01")==NULL);    /* 没有真的换行注入 */ }
TEST(null_fields){ unlink(LP);
    ASSERT_EQ(rguard_log_init(LP,"test",LOG_DEBUG),0);
    rguard_log_write(LOG_INFO,NULL,NULL,NULL);
    rguard_log_close();
    char b[1024]; slurp(b,sizeof(b));
    ASSERT_TRUE(strstr(b,"|INFO|-|test|-|{}")!=NULL); }
TEST(json_escape){ char out[128];
    rguard_json_escape(out,sizeof(out),"say \"hi\"\\path\tab");
    ASSERT_TRUE(strstr(out,"\\\"hi\\\"")!=NULL);   /* 引号已转义 */
    ASSERT_TRUE(strstr(out,"\\\\path")!=NULL);    /* 反斜杠已转义 */
    ASSERT_TRUE(strchr(out,'\t')==NULL);          /* 控制字符无原文 */
    ASSERT_TRUE(strstr(out,"0009")!=NULL);        /* \t →  形式 */
    ASSERT_TRUE(strncmp(out,"say ",4)==0);
    /* 截断安全：小缓冲 NUL 收尾 */
    char tiny[8]; memset(tiny,0xAA,sizeof(tiny));
    rguard_json_escape(tiny,sizeof(tiny),"\"1234567890\"");
    ASSERT_TRUE(strlen(tiny)<sizeof(tiny)); }
TEST(reinit_reopens){ unlink(LP);
    ASSERT_EQ(rguard_log_init(LP,"a",LOG_DEBUG),0);
    ASSERT_EQ(rguard_log_init(LP,"b",LOG_DEBUG),0);  /* 二次 init 不得泄漏/崩溃 */
    rguard_log_write(LOG_INFO,"EV2",NULL,NULL);
    rguard_log_close();
    char b[1024]; slurp(b,sizeof(b)); ASSERT_TRUE(strstr(b,"|EV2|b|")!=NULL); }

int main(void){ RUN_TEST(init_write);RUN_TEST(level_filter);RUN_TEST(set_level_runtime);
    RUN_TEST(no_log_injection);RUN_TEST(null_fields);RUN_TEST(json_escape);RUN_TEST(reinit_reopens);
    return test_summary();}
