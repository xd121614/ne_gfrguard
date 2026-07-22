#include "test_main.h"
#include "../src/daemon/gfrguardd_blocker.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>

static char B[264];   /* blocked file path, per-test unique: D(255)+"/blocked" */
static char D[256];   /* scratch dir */

static void mkpaths(void){ snprintf(D,sizeof(D),"/tmp/tblk_%d",(int)getpid());
    mkdir(D,0777); snprintf(B,sizeof(B),"%s/blocked",D); }
static void wf(const char *c){ int fd=open(B,O_WRONLY|O_CREAT|O_TRUNC,0640);
    if(write(fd,c,strlen(c))<0){} close(fd); }
static void rf(char *out,size_t n){ int fd=open(B,O_RDONLY); if(fd<0){out[0]=0;return;}
    ssize_t r=read(fd,out,n-1); if(r<0)r=0; out[r]=0; close(fd); }

TEST(execute_append_preserves){ mkpaths(); wf("1.1.1.1\n2.2.2.2\n");
    ASSERT_EQ(blocker_execute(NULL,B,"3.3.3.3",NULL,NULL,NULL),0);
    char c[256]; rf(c,sizeof(c));
    ASSERT_TRUE(strstr(c,"1.1.1.1\n")!=NULL); ASSERT_TRUE(strstr(c,"2.2.2.2\n")!=NULL);
    ASSERT_TRUE(strstr(c,"3.3.3.3\n")!=NULL); }
TEST(execute_dedup){ mkpaths(); wf("1.1.1.1\n");
    ASSERT_EQ(blocker_execute(NULL,B,"1.1.1.1",NULL,NULL,NULL),0);
    char c[256]; rf(c,sizeof(c)); ASSERT_TRUE(strcmp(c,"1.1.1.1\n")==0); }
TEST(execute_no_trailing_newline){ mkpaths(); wf("1.1.1.1");
    ASSERT_EQ(blocker_execute(NULL,B,"2.2.2.2",NULL,NULL,NULL),0);
    char c[256]; rf(c,sizeof(c)); ASSERT_TRUE(strcmp(c,"1.1.1.1\n2.2.2.2\n")==0); }
TEST(execute_rejects_non_ip){ mkpaths(); wf("1.1.1.1\n");
    /* cloud task_name / local placeholder 全被 inet_pton 闸门挡掉，文件不动 */
    ASSERT_EQ(blocker_execute(NULL,B,"photos-sync",NULL,NULL,NULL),0);
    ASSERT_EQ(blocker_execute(NULL,B,"local:1234",NULL,NULL,NULL),0);
    ASSERT_EQ(blocker_execute(NULL,B,"",NULL,NULL,NULL),0);
    ASSERT_EQ(blocker_execute(NULL,B,NULL,NULL,NULL,NULL),0);
    char c[256]; rf(c,sizeof(c)); ASSERT_TRUE(strcmp(c,"1.1.1.1\n")==0); }
TEST(execute_ipv6){ mkpaths(); wf("");
    ASSERT_EQ(blocker_execute(NULL,B,"::1",NULL,NULL,NULL),0);
    char c[256]; rf(c,sizeof(c)); ASSERT_TRUE(strcmp(c,"::1\n")==0); }

/* M10：blocked 文件存在但读失败时，execute 必须返回 -1 且原文件一字节不动。
 * 旧代码吞掉 read 错误按"空文件"重建 → 已有封锁条目全丢。
 * 用 setuid(nobody) 制造 EACCES（root 本身挡不住），目录 0777 保证 rename 能成功——
 * 若 bug 存在，文件会被换成仅含新 IP 的内容。 */
TEST(execute_read_fail_preserves){ mkpaths();
    /* 独立目录：前面用例会留下 root 拥有的 B.lock，nobody 打不开锁会提前 -1，
     * 测试就永远"通过"——锁文件必须不存在，让子进程走到读文件那一步。 */
    char d2[264], b2[272];   /* D(255)+"/rf"; d2(263)+"/blocked" */
    snprintf(d2,sizeof(d2),"%s/rf",D); mkdir(d2,0777); chmod(d2,0777);
    snprintf(b2,sizeof(b2),"%s/blocked",d2);
    { int fd=open(b2,O_WRONLY|O_CREAT|O_TRUNC,0640); if(write(fd,"1.1.1.1\n2.2.2.2\n",16)<0){} close(fd); }
    chmod(b2,0000);
    pid_t pid=fork();
    if(pid==0){ if(setgid(65534)!=0||setuid(65534)!=0) _exit(2);
        _exit(blocker_execute(NULL,b2,"3.3.3.3",NULL,NULL,NULL)==-1?0:1); }
    int st=0; waitpid(pid,&st,0);
    ASSERT_TRUE(WIFEXITED(st)&&WEXITSTATUS(st)==0);
    chmod(b2,0640);
    char c[256]={0}; int fd=open(b2,O_RDONLY); ssize_t r=read(fd,c,255); if(r>0)c[r]=0; close(fd);
    ASSERT_TRUE(strcmp(c,"1.1.1.1\n2.2.2.2\n")==0); }

TEST(unblock_exact){ mkpaths(); wf("1.1.1.1\n2.2.2.2\n3.3.3.3\n");
    ASSERT_EQ(blocker_unblock(B,"2.2.2.2"),0);
    char c[256]; rf(c,sizeof(c)); ASSERT_TRUE(strcmp(c,"1.1.1.1\n3.3.3.3\n")==0); }
TEST(unblock_not_found){ mkpaths(); wf("1.1.1.1\n");
    ASSERT_EQ(blocker_unblock(B,"9.9.9.9"),1);
    char c[256]; rf(c,sizeof(c)); ASSERT_TRUE(strcmp(c,"1.1.1.1\n")==0); }
TEST(unblock_missing_file){ mkpaths(); unlink(B);
    ASSERT_EQ(blocker_unblock(B,"1.1.1.1"),1); }
TEST(unblock_no_prefix_match){ mkpaths(); wf("1.1.1.1\n");
    /* "1.1.1.1" 的前缀/超集都不得误删 */
    ASSERT_EQ(blocker_unblock(B,"1.1.1"),1);
    ASSERT_EQ(blocker_unblock(B,"1.1.1.10"),1);
    char c[256]; rf(c,sizeof(c)); ASSERT_TRUE(strcmp(c,"1.1.1.1\n")==0); }

TEST(sync_writes_bare_ips){ mkpaths(); unlink(B);
    struct rguard_blacklist bl; memset(&bl,0,sizeof(bl));
    snprintf(bl.ips[0].ip,RGUARD_IP_LEN,"10.0.0.1");
    snprintf(bl.ips[1].ip,RGUARD_IP_LEN,"10.0.0.0/24");  /* CIDR 不写 */
    snprintf(bl.ips[2].ip,RGUARD_IP_LEN,"10.0.1.1-10.0.1.9"); /* range 不写 */
    bl.ip_count=3;
    snprintf(bl.auto_ips[0].ip,RGUARD_IP_LEN,"192.168.1.5"); bl.auto_ips[0].auto_add=true;
    bl.auto_ip_count=1;
    blocker_sync_blacklist(B,&bl);
    char c[512]; rf(c,sizeof(c));
    ASSERT_TRUE(strstr(c,"10.0.0.1\n")!=NULL); ASSERT_TRUE(strstr(c,"192.168.1.5\n")!=NULL);
    ASSERT_TRUE(strstr(c,"/24")==NULL); ASSERT_TRUE(strstr(c,"-10.0.1.9")==NULL); }

int main(void){ RUN_TEST(execute_append_preserves);RUN_TEST(execute_dedup);
    RUN_TEST(execute_no_trailing_newline);RUN_TEST(execute_rejects_non_ip);
    RUN_TEST(execute_ipv6);RUN_TEST(execute_read_fail_preserves);
    RUN_TEST(unblock_exact);RUN_TEST(unblock_not_found);RUN_TEST(unblock_missing_file);
    RUN_TEST(unblock_no_prefix_match);RUN_TEST(sync_writes_bare_ips);
    return test_summary();}
