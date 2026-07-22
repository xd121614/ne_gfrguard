/* test_main_daemon.c — process_msg 消息处理核心（此前零覆盖）。
 * fanotify/通道模块符号用 stub 隔离；session/scorer/blocker/db/yara 全真。
 * RUN_DIR 重定向到 /tmp，blocked 文件落在临时目录。 */
#include "test_main.h"
#include "../src/common/rguard_protocol.h"
#include "../src/common/rguard_config.h"
#include "../src/common/rguard_db.h"
#include "../src/common/rguard_hash.h"
#include "../src/daemon/gfrguardd_session.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* process_msg 本体（main.c 以 -Dmain=daemon_main 编译进来） */
void process_msg(const struct rguard_event_msg *msg, sqlite3 *db,
                 struct session_table *st, struct rguard_policy *policy,
                 int *daily_seq, time_t *day_anchor);

/* ── stub：fanotify 与三通道模块（main.c 的 main/reload 引用，测试不经过） ── */
int fanotify_module_init(int e){ return -1; }
void fanotify_set_daemon_ctx(sqlite3*d,struct session_table*s,struct rguard_policy*p,int*ds,time_t*da){}
int fanotify_start_perm_thread(void){ return -1; }
void fanotify_stop_perm_thread(void){}
int fanotify_get_notify_fd(void){ return -1; }
int fanotify_get_pipe_fd(void){ return -1; }
int fanotify_poll(void){ return 0; }
int fanotify_process_queued(void){ return 0; }
int fanotify_retry_pending_channels(void){ return 0; }
struct fanotify_channel;   /* opaque — stub only needs the pointer type */
int fanotify_reload_marks(const struct fanotify_channel *c,int n){ return 0; }
int ftp_module_init(const struct rguard_policy*p){ return 0; }
int cloud_module_init(const struct rguard_policy*p){ return 0; }
int local_module_init(const struct rguard_policy*p){ return 0; }
void ftp_module_destroy(void){}
void cloud_module_destroy(void){}
void local_module_destroy(void){}
void fanotify_module_destroy(void){}

/* ── fixtures ────────────────────────────────────────────────────────── */
static char RUN[64];           /* RUN_DIR 重定向目标 */
static char DBP[128], BLP[128];
static struct rguard_policy P;
static struct session_table T;
static sqlite3 *DB;
static int seq; static time_t anchor;

static void rf(const char *p,char *o,size_t n){ int fd=open(p,O_RDONLY);
    if(fd<0){o[0]=0;return;} ssize_t r=read(fd,o,n-1); if(r<0)r=0; o[r]=0; close(fd); }

static void setup(void){
    snprintf(RUN,sizeof(RUN),"/tmp/tmain_run");   /* 与 -DRUN_DIR 一致 */
    mkdir(RUN,0777);
    snprintf(DBP,sizeof(DBP),"%s/index.db",RUN);
    snprintf(BLP,sizeof(BLP),"%s/blocked",RUN);
    unlink(DBP); unlink(BLP);
    memset(&P,0,sizeof(P));
    P.protection.enabled=true; P.protection.smb=true;
    P.protection.cloud_sync=true; P.protection.ftp=true; P.protection.host=true;
    P.scoring.window_short=10; P.scoring.window_long=30;
    P.scoring.cloud_window_short=60; P.scoring.cloud_window_long=180;
    P.scoring.weights.modified=3; P.scoring.weights.rename_w=4; P.scoring.weights.delete_w=3;
    P.scoring.weights.dirs=5; P.scoring.weights.ext_change=5; P.scoring.weights.ransom_ext=20;
    P.scoring.weights.high_entropy=8; P.scoring.weights.yara_match=40;
    P.scoring.thresholds.warn=30; P.scoring.thresholds.high=60; P.scoring.thresholds.critical=80;
    P.scoring.entropy_enabled=false; P.scoring.yara_enabled=false;
    P.file_ext.all=true;
    P.auto_restore.enabled=false;
    session_table_init(&T);
    DB=NULL; db_open(DBP,&DB);
    seq=0; anchor=0;
}
static void teardown(void){ if(DB) db_close(DB); DB=NULL; }

static void mkmsg(struct rguard_event_msg *m,int op,unsigned flags,
                  const char *user,const char *ip,const char *path){
    memset(m,0,sizeof(*m));
    m->msg_type=RGUARD_MSG_FILE_EVENT; m->proto_version=RGUARD_PROTO_VERSION;
    m->op_type=op; m->flags=flags; m->source_type=RGUARD_SOURCE_SMB;
    snprintf(m->username,sizeof(m->username),"%s",user);
    snprintf(m->client_ip,sizeof(m->client_ip),"%s",ip);
    snprintf(m->file_path,sizeof(m->file_path),"%s",path);
}
static struct session_state *find(const char *key){ return session_find_or_create(&T,key); }

/* ── 用例 ────────────────────────────────────────────────────────────── */
TEST(vfs_blocked_records_event){ setup();
    struct rguard_event_msg m; mkmsg(&m,0,0,"alice","10.0.0.5","");
    m.msg_type=RGUARD_MSG_VFS_BLOCKED;
    process_msg(&m,DB,&T,&P,&seq,&anchor);
    struct session_state *s=find("alice@10.0.0.5");
    ASSERT_TRUE(s->current_event_id[0]!=0);
    sqlite3_stmt *st; int n=0;
    if(sqlite3_prepare_v2(DB,"SELECT COUNT(*) FROM events WHERE status='blocked_ip'",-1,&st,NULL)==SQLITE_OK
       && sqlite3_step(st)==SQLITE_ROW) n=sqlite3_column_int(st,0);
    sqlite3_finalize(st);
    ASSERT_EQ(n,1);
    teardown(); }
TEST(master_switch_off_drops){ setup();
    P.protection.enabled=false;
    struct rguard_event_msg m; mkmsg(&m,RGUARD_OP_WRITE,RGUARD_FLAG_RISKY,"bob","10.0.0.6","/srv/s/a.txt");
    process_msg(&m,DB,&T,&P,&seq,&anchor);
    ASSERT_EQ((int)T.count,0);            /* 会话都没建 */
    teardown(); }
TEST(sub_switch_per_channel){ setup();
    P.protection.ftp=false;               /* 只关 FTP */
    struct rguard_event_msg m;
    mkmsg(&m,RGUARD_OP_WRITE,RGUARD_FLAG_RISKY,"eve","10.0.0.7","/srv/ftp/x.bin");
    m.source_type=RGUARD_SOURCE_FTP;
    process_msg(&m,DB,&T,&P,&seq,&anchor);
    ASSERT_EQ((int)T.count,0);            /* FTP 事件被自己的开关挡掉 */
    mkmsg(&m,RGUARD_OP_WRITE,RGUARD_FLAG_RISKY,"eve","10.0.0.7","/srv/s/y.bin");
    m.source_type=RGUARD_SOURCE_SMB;
    process_msg(&m,DB,&T,&P,&seq,&anchor);
    ASSERT_EQ((int)T.count,1);            /* SMB 照常 */
    teardown(); }
TEST(escalate_to_critical_blocks){ setup();
    struct rguard_event_msg m;
    /* 27 个 RISKY WRITE（27*3=81）+ 1 个 RENAME 触发非延迟评分 */
    for(int i=0;i<27;i++){
        char p[64]; snprintf(p,sizeof(p),"/srv/s/f%02d.txt",i);
        mkmsg(&m,RGUARD_OP_WRITE,RGUARD_FLAG_RISKY,"mallory","10.0.0.9",p);
        process_msg(&m,DB,&T,&P,&seq,&anchor);
    }
    struct session_state *s=find("mallory@10.0.0.9");
    ASSERT_EQ((int)s->modified_count,27);
    ASSERT_EQ((int)s->risk_score,0);      /* 全部延迟评分，尚未计算 */
    mkmsg(&m,RGUARD_OP_RENAME,0,"mallory","10.0.0.9","/srv/s/f00.txt");
    snprintf(m.new_name,sizeof(m.new_name),"g00.txt");
    process_msg(&m,DB,&T,&P,&seq,&anchor);
    ASSERT_EQ(s->risk_level,RISK_CRITICAL);   /* 81+4=85 ≥ 80 */
    ASSERT_TRUE(s->is_blocked);
    char bl[256]; rf(BLP,bl,sizeof(bl));
    ASSERT_TRUE(strstr(bl,"10.0.0.9\n")!=NULL);  /* IP 进 blocked 文件 */
    ASSERT_EQ((int)P.blacklist.auto_ip_count,1); /* auto-blacklist 同步 */
    teardown(); }
TEST(ransom_ext_on_rename){ setup();
    snprintf(P.ransom_exts[0],16,".locked"); P.ransom_ext_count=1;
    struct rguard_event_msg m;
    mkmsg(&m,RGUARD_OP_RENAME,0,"mallory","10.0.0.9","/srv/s/doc.txt");
    snprintf(m.new_name,sizeof(m.new_name),"doc.txt.locked");
    process_msg(&m,DB,&T,&P,&seq,&anchor);
    struct session_state *s=find("mallory@10.0.0.9");
    ASSERT_EQ((int)s->ext_change_count,1);
    ASSERT_EQ((int)s->ransom_ext_count,1);
    ASSERT_EQ((int)s->risk_score,34);     /* rename 4 + ransom 20 + ext_change 5 + dirs 5 */
    teardown(); }
TEST(created_file_recorded){ setup();
    struct rguard_event_msg m;
    mkmsg(&m,RGUARD_OP_OPEN,RGUARD_FLAG_NEW_FILE|RGUARD_FLAG_RISKY,"eve","10.0.0.7","/srv/s/NOTE.html");
    process_msg(&m,DB,&T,&P,&seq,&anchor);
    sqlite3_stmt *st; int n=0;
    if(sqlite3_prepare_v2(DB,"SELECT COUNT(*) FROM created_files WHERE file_path='/srv/s/NOTE.html'",-1,&st,NULL)==SQLITE_OK
       && sqlite3_step(st)==SQLITE_ROW) n=sqlite3_column_int(st,0);
    sqlite3_finalize(st);
    ASSERT_EQ(n,1);
    teardown(); }
TEST(manual_blacklist_immediate){ setup();
    snprintf(P.blacklist.ips[0].ip,48,"10.6.6.6"); P.blacklist.ip_count=1;
    P.blacklist.ip_hashes[0]=rguard_fnv1a64("10.6.6.6",8);
    struct rguard_event_msg m;
    mkmsg(&m,RGUARD_OP_WRITE,RGUARD_FLAG_RISKY,"mallory","10.6.6.6","/srv/s/a.txt");
    process_msg(&m,DB,&T,&P,&seq,&anchor);
    struct session_state *s=find("mallory@10.6.6.6");
    ASSERT_TRUE(s->is_blocked);           /* 无需累计评分，立即阻断 */
    char bl[256]; rf(BLP,bl,sizeof(bl));
    ASSERT_TRUE(strstr(bl,"10.6.6.6\n")!=NULL);
    teardown(); }
TEST(whitelist_bypass){ setup();
    snprintf(P.whitelist.users[0],64,"admin"); P.whitelist.user_count=1;
    P.whitelist.user_hashes[0]=rguard_fnv1a64("admin",5);
    struct rguard_event_msg m;
    for(int i=0;i<27;i++){
        char p[64]; snprintf(p,sizeof(p),"/srv/s/f%02d.txt",i);
        mkmsg(&m,RGUARD_OP_WRITE,RGUARD_FLAG_RISKY,"admin","10.0.0.9",p);
        process_msg(&m,DB,&T,&P,&seq,&anchor);
    }
    ASSERT_EQ((int)T.count,0);            /* 白名单直接放行，不计分 */
    teardown(); }
TEST(exception_bypass){ setup();
    snprintf(P.exceptions.files[0],256,"/srv/s/puppet-deploy.txt");
    P.exceptions.file_count=1;
    P.exceptions.file_hashes[0]=rguard_fnv1a64("/srv/s/puppet-deploy.txt",24);
    struct rguard_event_msg m;
    mkmsg(&m,RGUARD_OP_WRITE,RGUARD_FLAG_RISKY,"deploy","10.0.0.8","/srv/s/puppet-deploy.txt");
    process_msg(&m,DB,&T,&P,&seq,&anchor);
    ASSERT_EQ((int)T.count,0);
    teardown(); }
TEST(blocked_session_stays_blocked_after_window){ setup();
    struct rguard_event_msg m;
    mkmsg(&m,RGUARD_OP_WRITE,RGUARD_FLAG_RISKY,"mallory","10.0.0.9","/srv/s/a.txt");
    struct session_state *s=find("mallory@10.0.0.9");
    s->is_blocked=true;
    s->window_start_30s=time(NULL)-60;    /* 窗口已过 → check_window 滑动 */
    mkmsg(&m,RGUARD_OP_WRITE,RGUARD_FLAG_RISKY,"mallory","10.0.0.9","/srv/s/b.txt");
    process_msg(&m,DB,&T,&P,&seq,&anchor);
    ASSERT_TRUE(s->is_blocked);           /* 窗口滑动不解除阻断 */
    teardown(); }
TEST(cloud_window_longer){ setup();
    /* 云通道用独立窗口：cloud_window_short=60 —— 同一秒 2 个事件不滑动窗口，
     * 而全局窗口 window_short=10 若被误用同样不滑动；此处验证 window 选择路径
     * 只读对应字段（构造 cloud_window_short=0 时回退全局窗口） */
    P.scoring.cloud_window_short=0;
    struct rguard_event_msg m;
    mkmsg(&m,RGUARD_OP_WRITE,RGUARD_FLAG_RISKY,"sync","task1","/cloud/a.txt");
    m.source_type=RGUARD_SOURCE_CLOUD_SYNC;
    process_msg(&m,DB,&T,&P,&seq,&anchor);
    struct session_state *s=find("sync@task1");
    ASSERT_TRUE(s!=NULL);
    ASSERT_EQ((int)s->modified_count,1);
    teardown(); }

int main(void){
    RUN_TEST(vfs_blocked_records_event);
    RUN_TEST(master_switch_off_drops);
    RUN_TEST(sub_switch_per_channel);
    RUN_TEST(escalate_to_critical_blocks);
    RUN_TEST(ransom_ext_on_rename);
    RUN_TEST(created_file_recorded);
    RUN_TEST(manual_blacklist_immediate);
    RUN_TEST(whitelist_bypass);
    RUN_TEST(exception_bypass);
    RUN_TEST(blocked_session_stays_blocked_after_window);
    RUN_TEST(cloud_window_longer);
    return test_summary();}
