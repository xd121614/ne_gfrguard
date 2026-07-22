/* test_yara.c — yara 引擎单测（此前零覆盖）。
 * 规则目录全部临时自建：合法规则、坏规则、symlink 环互不依赖系统环境。 */
#include "test_main.h"
#include "../src/daemon/gfrguardd_yara.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static const char *RULE =
    "rule TestRansomNote {\n"
    "  strings: $a = \"DECRYPT YOUR FILES\"\n"
    "  condition: $a\n"
    "}\n";
static const char *RULE_BAD = "rule Broken { condition: and and and }\n";

static char RD[256];   /* rules dir */
static void mk_rules(void){ snprintf(RD,sizeof(RD),"/tmp/tyara_%d",(int)getpid());
    mkdir(RD,0777);
    char p[512]; snprintf(p,sizeof(p),"%s/good.yar",RD);
    int fd=open(p,O_WRONLY|O_CREAT|O_TRUNC,0644); if(write(fd,RULE,strlen(RULE))<0){} close(fd); }
static void mk_target(const char *path,const char *content){
    int fd=open(path,O_WRONLY|O_CREAT|O_TRUNC,0644); if(write(fd,content,strlen(content))<0){} close(fd); }

TEST(init_and_match){ mk_rules();
    ASSERT_EQ(yara_engine_init(RD),0);
    ASSERT_TRUE(yara_engine_active());
    mk_target("/tmp/tyara_hit.txt","HOW TO DECRYPT YOUR FILES - pay 1 btc");
    char rule[256]={0};
    ASSERT_EQ(yara_scan_file("/tmp/tyara_hit.txt",rule,sizeof(rule)),1);
    ASSERT_TRUE(strcmp(rule,"TestRansomNote")==0);
    yara_engine_destroy(); }
TEST(no_match_benign){ mk_rules();
    ASSERT_EQ(yara_engine_init(RD),0);
    mk_target("/tmp/tyara_ok.txt","just a normal document about puppies");
    ASSERT_EQ(yara_scan_file("/tmp/tyara_ok.txt",NULL,0),0);
    yara_engine_destroy(); }
TEST(scan_fifo_fast_fail){ mk_rules();
    ASSERT_EQ(yara_engine_init(RD),0);
    mkfifo("/tmp/tyara_fifo",0644);
    /* FIFO 必须立即 -1，绝不阻塞主线程（H8 闸门） */
    ASSERT_EQ(yara_scan_file("/tmp/tyara_fifo",NULL,0),-1);
    yara_engine_destroy(); }
TEST(scan_nonexistent){ mk_rules();
    ASSERT_EQ(yara_engine_init(RD),0);
    ASSERT_EQ(yara_scan_file("/tmp/tyara_gone.txt",NULL,0),-1);
    yara_engine_destroy(); }
TEST(scan_directory){ mk_rules();
    ASSERT_EQ(yara_engine_init(RD),0);
    ASSERT_EQ(yara_scan_file(RD,NULL,0),-1);   /* 目录不是常规文件 */
    yara_engine_destroy(); }
TEST(all_bad_rules_no_engine){ snprintf(RD,sizeof(RD),"/tmp/tyara_bad_%d",(int)getpid());
    mkdir(RD,0777);
    char p[512]; snprintf(p,sizeof(p),"%s/bad.yar",RD);
    int fd=open(p,O_WRONLY|O_CREAT|O_TRUNC,0644); if(write(fd,RULE_BAD,strlen(RULE_BAD))<0){} close(fd);
    ASSERT_EQ(yara_engine_init(RD),0);      /* 有规则但全坏 → 0 加载，不算 init 失败 */
    ASSERT_FALSE(yara_engine_active());
    yara_engine_destroy(); }
TEST(bad_rule_skipped_good_loaded){ mk_rules();
    char p[512]; snprintf(p,sizeof(p),"%s/bad.yar",RD);
    int fd=open(p,O_WRONLY|O_CREAT|O_TRUNC,0644); if(write(fd,RULE_BAD,strlen(RULE_BAD))<0){} close(fd);
    ASSERT_EQ(yara_engine_init(RD),0);
    ASSERT_TRUE(yara_engine_active());      /* 坏文件跳过，好文件照常 */
    mk_target("/tmp/tyara_hit2.txt","DECRYPT YOUR FILES now");
    ASSERT_EQ(yara_scan_file("/tmp/tyara_hit2.txt",NULL,0),1);
    yara_engine_destroy(); }
TEST(symlink_loop_no_crash){ snprintf(RD,sizeof(RD),"/tmp/tyara_loop_%d",(int)getpid());
    mkdir(RD,0777);
    char p[512]; snprintf(p,sizeof(p),"%s/loop",RD);
    if(symlink(RD,p)!=0){}                      /* 自指环：无限递归 → 栈溢出（深度上限前） */
    char g[512]; snprintf(g,sizeof(g),"%s/good.yar",RD);
    int fd=open(g,O_WRONLY|O_CREAT|O_TRUNC,0644); if(write(fd,RULE,strlen(RULE))<0){} close(fd);
    ASSERT_EQ(yara_engine_init(RD),0);      /* 不崩即赢 */
    yara_engine_destroy(); }
TEST(reload){ mk_rules();
    ASSERT_EQ(yara_engine_init(RD),0);
    ASSERT_EQ(yara_engine_reload(RD),0);
    ASSERT_TRUE(yara_engine_active());
    yara_engine_destroy(); }
TEST(scan_null_path){ mk_rules(); yara_engine_init(RD);
    ASSERT_EQ(yara_scan_file(NULL,NULL,0),-1);
    yara_engine_destroy(); }

int main(void){ RUN_TEST(init_and_match);RUN_TEST(no_match_benign);
    RUN_TEST(scan_fifo_fast_fail);RUN_TEST(scan_nonexistent);RUN_TEST(scan_directory);
    RUN_TEST(all_bad_rules_no_engine);RUN_TEST(bad_rule_skipped_good_loaded);
    RUN_TEST(symlink_loop_no_crash);RUN_TEST(reload);RUN_TEST(scan_null_path);
    return test_summary();}
