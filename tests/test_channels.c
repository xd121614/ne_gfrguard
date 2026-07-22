/* test_channels.c — ftp/local 通道纯逻辑单测。
 * fanotify 机制（marks/perm 线程/队列）不属被测对象，用 stub 隔离；
 * /proc 解析、白名单判定、kill 复核全部跑真代码。 */
#include "test_main.h"
#include "../src/daemon/gfrguardd_ftp.h"
#include "../src/daemon/gfrguardd_local.h"
#include "../src/daemon/gfrguardd_cloud.h"
#include "../src/daemon/gfrguardd_fanchannel.h"
#include "../src/common/rguard_proc.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>

/* ── fanotify 机制 stub（链接需要，测试不经过） ─────────────────────── */
int fanotify_channel_setup(const struct fanotify_channel *ch){ return -1; }
int fanotify_do_backup(int f,const char*p,const char*s,const char*c){ return -1; }
void fanotify_build_event_msg(const struct fanotify_event *e,uint8_t s,struct rguard_event_msg *m){}
bool fanotify_gate_allow(const char *s,const char *p,uint8_t t){ return false; }
void fanotify_queue_event(const struct rguard_event_msg *m){}
bool fanotify_fill_notify_msg(const struct fanotify_event *e,const char *s,struct rguard_event_msg *m){ return false; }
bool fanotify_submit_event(const struct rguard_event_msg *m,const char *s){ return false; }
struct sqlite3 *fanotify_get_db(void){ return NULL; }
struct session_table *fanotify_get_session_table(void){ return NULL; }

/* ── fan_proc_stat ─────────────────────────────────────────────────── */
TEST(proc_stat_self){ char comm[64]={0}; unsigned long long st=0;
    ASSERT_EQ(fan_proc_stat(getpid(),comm,sizeof(comm),&st),0);
    ASSERT_TRUE(comm[0]!=0); ASSERT_TRUE(st>0); }
TEST(proc_stat_gone){ unsigned long long st=0;
    ASSERT_EQ(fan_proc_stat(4194303,NULL,0,&st),-1); }  /* pid 上限外 */

/* ── M12：local 白名单按 exe 绝对路径，comm 改名不可绕过 ───────────── */
TEST(wl_exe_exact){ ASSERT_TRUE(local_whitelist_match("sshd","/usr/sbin/sshd")); }
TEST(wl_exe_rename_bypass){ /* comm 改成 sshd 但 exe 是 /tmp/evil → 必须拦 */
    ASSERT_FALSE(local_whitelist_match("sshd","/tmp/evil")); }
TEST(wl_exe_fs_rename_bypass){ /* 二进制直接命名为 sshd 放 /tmp → 同样拦 */
    ASSERT_FALSE(local_whitelist_match("whatever","/tmp/sshd")); }
TEST(wl_exe_wins_over_comm){ /* comm 随便改，exe 是白名单即放行 */
    ASSERT_TRUE(local_whitelist_match("evil","/usr/sbin/sshd")); }
TEST(wl_daemon_paths){ ASSERT_TRUE(local_whitelist_match(NULL,"/usr/local/sbin/gfrguardd"));
    ASSERT_TRUE(local_whitelist_match(NULL,"/usr/local/sbin/gfrguard-recover"));
    ASSERT_TRUE(local_whitelist_match(NULL,"/usr/lib/systemd/systemd"));
    ASSERT_TRUE(local_whitelist_match(NULL,"/usr/bin/rclone"));
    ASSERT_TRUE(local_whitelist_match(NULL,"/usr/local/samba/sbin/smbd")); }
TEST(wl_kthread_prefix){ ASSERT_TRUE(local_whitelist_match("kworker/0:1H",NULL));
    ASSERT_TRUE(local_whitelist_match("jbd2/sda1-8",NULL));
    ASSERT_TRUE(local_whitelist_match("kthreadd","")); }
TEST(wl_user_proc_not){ ASSERT_FALSE(local_whitelist_match("bash",NULL));
    ASSERT_FALSE(local_whitelist_match("python3",NULL));
    ASSERT_FALSE(local_whitelist_match(NULL,NULL)); }

/* ── M11：/proc/net/tcp 解析 ───────────────────────────────────────── */
static const char *TCP_HDR =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
TEST(tcp_v4_loopback){ char ip[48]={0}; unsigned long ino[]={12345};
    char text[1024]; snprintf(text,sizeof(text),"%s%s",TCP_HDR,
        "   1: 0100007F:1F90 0100007F:0015 01 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 100 0 0 10 0\n");
    ASSERT_EQ(ftp_tcp_find_remote(text,ino,1,ip,sizeof(ip)),0);
    ASSERT_TRUE(strcmp(ip,"127.0.0.1")==0); }
TEST(tcp_v4_real_ip){ char ip[48]={0}; unsigned long ino[]={999};
    char text[1024]; snprintf(text,sizeof(text),"%s%s",TCP_HDR,
        "   2: 000011AC:0015 0203A8C0:8F76 01 00000000:00000000 00:00000000 00000000 1000 0 999 1 0000000000000000 100 0 0 10 0\n");
    ASSERT_EQ(ftp_tcp_find_remote(text,ino,1,ip,sizeof(ip)),0);
    ASSERT_TRUE(strcmp(ip,"192.168.3.2")==0); }  /* 0203A8C0 低字节起 → 192.168.3.2 */
TEST(tcp_no_match){ char ip[48]={0}; unsigned long ino[]={555};
    char text[1024]; snprintf(text,sizeof(text),"%s%s",TCP_HDR,
        "   1: 0100007F:1F90 0100007F:0015 01 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 100 0 0 10 0\n");
    ASSERT_EQ(ftp_tcp_find_remote(text,ino,1,ip,sizeof(ip)),-1); }
/* 回归：旧实现单次 read 4KB 截断，目标行在 4KB 之后永远匹配不上 */
TEST(tcp_beyond_4k){ char ip[48]={0}; unsigned long ino[]={777777};
    static char text[128*1024]; size_t off=0;
    off+=snprintf(text+off,sizeof(text)-off,"%s",TCP_HDR);
    for(int i=0;i<300;i++)
        off+=snprintf(text+off,sizeof(text)-off,
            "%4d: 0100007F:%04X 0100007F:0015 01 00000000:00000000 00:00000000 00000000 1000 0 %d 1 0000000000000000 100 0 0 10 0\n",
            i,0x1F90+i,1000+i);
    off+=snprintf(text+off,sizeof(text)-off,
        " 301: 0100007F:1F90 0403A8C0:0015 01 00000000:00000000 00:00000000 00000000 1000 0 777777 1 0000000000000000 100 0 0 10 0\n");
    ASSERT_TRUE(off>4096);
    ASSERT_EQ(ftp_tcp_find_remote(text,ino,1,ip,sizeof(ip)),0);
    ASSERT_TRUE(strcmp(ip,"192.168.3.4")==0); }
TEST(tcp6_loopback){ char ip[48]={0}; unsigned long ino[]={4242};
    char text[1024]; snprintf(text,sizeof(text),"%s%s",TCP_HDR,
        "   1: 00000000000000000000000001000000:1F90 00000000000000000000000001000000:0015 01 00000000:00000000 00:00000000 00000000 1000 0 4242 1 0000000000000000 100 0 0 10 0\n");
    ASSERT_EQ(ftp_tcp_find_remote(text,ino,1,ip,sizeof(ip)),0);
    ASSERT_TRUE(strcmp(ip,"::1")==0); }
TEST(tcp6_global){ char ip[48]={0}; unsigned long ino[]={4243};
    /* fe80::1 → 词0 "000080FE" 其余 0，末词 "01000000" */
    char text[1024]; snprintf(text,sizeof(text),"%s%s",TCP_HDR,
        "   1: 000080FE000000000000000000000000:1F90 000080FE000000000000000001000000:0015 01 00000000:00000000 00:00000000 00000000 1000 0 4243 1 0000000000000000 100 0 0 10 0\n");
    ASSERT_EQ(ftp_tcp_find_remote(text,ino,1,ip,sizeof(ip)),0);
    ASSERT_TRUE(strcmp(ip,"fe80::1")==0); }

/* ── M16：ftp kill 复核 starttime，PID 复用不误杀 ──────────────────── */
static pid_t spawn_named(const char *name){ pid_t p=fork();
    if(p==0){ prctl(PR_SET_NAME,name,0,0,0); pause(); _exit(0); }
    usleep(50000); return p; }
static int alive(pid_t p){ return kill(p,0)==0; }
TEST(block_wrong_starttime_spares){ pid_t p=spawn_named("vsftpd");
    unsigned long long st=0; ASSERT_EQ(fan_proc_stat(p,NULL,0,&st),0);
    ftp_block_execute(p,st+1);           /* starttime 不符 → 复用的 PID，不杀 */
    ASSERT_TRUE(alive(p)); kill(p,SIGKILL); waitpid(p,NULL,0); }
TEST(block_non_vsftpd_spares){ pid_t p=spawn_named("sleep");
    ftp_block_execute(p,0);              /* comm 不是 vsftpd → 不杀 */
    ASSERT_TRUE(alive(p)); kill(p,SIGKILL); waitpid(p,NULL,0); }
TEST(block_matching_kills){ pid_t p=spawn_named("vsftpd");
    unsigned long long st=0; ASSERT_EQ(fan_proc_stat(p,NULL,0,&st),0);
    ftp_block_execute(p,st);             /* comm+starttime 都符 → SIGTERM */
    int stt=0; waitpid(p,&stt,0);
    ASSERT_TRUE(WIFSIGNALED(stt)||WIFEXITED(stt)); ASSERT_FALSE(alive(p)); }
TEST(block_gone_pid){ ftp_block_execute(4194303,0); ASSERT_TRUE(1); }  /* 不崩溃 */

/* ── M9：外部 helper 必须有超时，挂死即 SIGKILL ────────────────────── */
TEST(wait_timeout_fast_child){ pid_t p=fork();
    if(p==0)_exit(3);
    int st=0; ASSERT_EQ(rguard_wait_timeout(p,2000,&st),0);
    ASSERT_TRUE(WIFEXITED(st)&&WEXITSTATUS(st)==3); }
TEST(wait_timeout_kills_hanger){ pid_t p=fork();
    if(p==0){ sleep(60); _exit(0); }
    int st=0;
    ASSERT_EQ(rguard_wait_timeout(p,300,&st),-1);   /* 超时 → SIGKILL */
    ASSERT_FALSE(kill(p,0)==0); }                /* 尸体已收割 */

/* fake neo-croner：PATH 前置一个临时目录，按 argv 演不同剧本 */
static void fake_neo_croner(const char *script){
    char dir[]="/tmp/fakeneo_XXXXXX"; if(!mkdtemp(dir)) return;
    char path[256]; snprintf(path,sizeof(path),"%s/neo-croner",dir);
    int fd=open(path,O_WRONLY|O_CREAT|O_TRUNC,0755);
    if(write(fd,script,strlen(script))<0){} close(fd);
    char oldpath[4096]; snprintf(oldpath,sizeof(oldpath),"%s",getenv("PATH"));
    char newpath[4608]; snprintf(newpath,sizeof(newpath),"%s:%s",dir,oldpath);
    setenv("PATH",newpath,1);
    setenv("SAVED_PATH",oldpath,1);  /* stash for restore */
}
static void restore_path(void){ setenv("PATH",getenv("SAVED_PATH"),1); }
TEST(neo_query_parse){ fake_neo_croner(
    "#!/bin/sh\nprintf 'Expression:     0 2 * * *\\nCommand:        main.py sync\\n'\n");
    char expr[128]={0},cmd[256]={0};
    ASSERT_EQ(neo_croner_query("photos-sync",expr,sizeof(expr),cmd,sizeof(cmd)),0);
    ASSERT_TRUE(strcmp(expr,"0 2 * * *")==0); ASSERT_TRUE(strcmp(cmd,"main.py sync")==0);
    restore_path(); }
TEST(neo_query_bad_name_rejected){ /* 白名单字符集提前拒绝，不 fork */
    char expr[8]={0},cmd[8]={0};
    ASSERT_EQ(neo_croner_query("a;rm -rf /",expr,sizeof(expr),cmd,sizeof(cmd)),-1);
    ASSERT_EQ(neo_croner_query("$(whoami)",expr,sizeof(expr),cmd,sizeof(cmd)),-1); }
TEST(neo_query_hang_killed){ fake_neo_croner("#!/bin/sh\nsleep 60\n");
    char expr[128]={0},cmd[256]={0};
    /* 编译期 NEO_CRONER_TIMEOUT_MS=400 —— 必须在 3s 内返回而不是 60s */
    ASSERT_EQ(neo_croner_query("hanger",expr,sizeof(expr),cmd,sizeof(cmd)),-1);
    restore_path(); }
TEST(neo_delete_exit_codes){ fake_neo_croner(
    "#!/bin/sh\n[ \"$1\" = delete ] && exit 0 || exit 1\n");
    ASSERT_EQ(neo_croner_delete("task1"),0);
    restore_path(); }
TEST(neo_delete_missing_binary){ setenv("PATH","/nonexistent",1);
    ASSERT_EQ(neo_croner_delete("task1"),-1);   /* exec 失败 _exit(127) → -1 */
    restore_path(); }

int main(void){ RUN_TEST(proc_stat_self);RUN_TEST(proc_stat_gone);
    RUN_TEST(wl_exe_exact);RUN_TEST(wl_exe_rename_bypass);RUN_TEST(wl_exe_fs_rename_bypass);
    RUN_TEST(wl_exe_wins_over_comm);RUN_TEST(wl_daemon_paths);
    RUN_TEST(wl_kthread_prefix);RUN_TEST(wl_user_proc_not);
    RUN_TEST(tcp_v4_loopback);RUN_TEST(tcp_v4_real_ip);RUN_TEST(tcp_no_match);
    RUN_TEST(tcp_beyond_4k);RUN_TEST(tcp6_loopback);RUN_TEST(tcp6_global);
    RUN_TEST(block_wrong_starttime_spares);RUN_TEST(block_non_vsftpd_spares);
    RUN_TEST(block_matching_kills);RUN_TEST(block_gone_pid);
    RUN_TEST(wait_timeout_fast_child);RUN_TEST(wait_timeout_kills_hanger);
    RUN_TEST(neo_query_parse);RUN_TEST(neo_query_bad_name_rejected);
    RUN_TEST(neo_query_hang_killed);RUN_TEST(neo_delete_exit_codes);
    RUN_TEST(neo_delete_missing_binary);
    return test_summary();}
