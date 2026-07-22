/* test_recover.c — gfrguard_recover.c 静态函数直测（此前零覆盖）。
 * 以 main 改名 + 路径宏重定向 include 整个 .c：valid_restore_path /
 * copy_file / restore_one / delete_created_one / cmd_status 全跑真代码。 */
#include "test_main.h"

#define main recover_cli_main
#define STORE_PATH "/tmp/trec_store"
#define DB_PATH    "/tmp/trec_store/index.db"
#define BLOCKED_PATH "/tmp/trec_store/blocked"
#define QUARANTINE_PATH "/tmp/trec_store/quarantine"
#include "../src/recover/gfrguard_recover.c"
#undef main
/* DB_PATH / QUARANTINE_PATH / BLOCKED_PATH 保持重定向后的值供用例使用 */

#include <sys/stat.h>
#include <sys/wait.h>

static char RD[256];   /* scratch root per process */
static void setup(void){
    snprintf(RD,sizeof(RD),"/tmp/trec_%d",(int)getpid());
    char cmd[600]; snprintf(cmd,sizeof(cmd),"rm -rf %s /tmp/trec_store",RD);
    if(system(cmd)!=0){}
    mkdir(RD,0777); mkdir("/tmp/trec_store",0777);
}
static void wf(const char *path,const char *c){
    int fd=open(path,O_WRONLY|O_CREAT|O_TRUNC,0644);
    if(write(fd,c,strlen(c))<0){} close(fd); }
static void rf(const char *path,char *out,size_t n){
    int fd=open(path,O_RDONLY); if(fd<0){out[0]=0;return;}
    ssize_t r=read(fd,out,n-1); if(r<0)r=0; out[r]=0; close(fd); }
static int is_symlink(const char *p){ struct stat st; return lstat(p,&st)==0 && S_ISLNK(st.st_mode); }

/* ── valid_restore_path ────────────────────────────────────────────── */
TEST(path_valid){ ASSERT_TRUE(valid_restore_path("/srv/share/a.txt")); }
TEST(path_reject_relative){ ASSERT_FALSE(valid_restore_path("etc/passwd"));
    ASSERT_FALSE(valid_restore_path("")); ASSERT_FALSE(valid_restore_path(NULL)); }
TEST(path_reject_dotdot){ ASSERT_FALSE(valid_restore_path("/a/../b"));
    ASSERT_FALSE(valid_restore_path("/a/.."));
    ASSERT_TRUE(valid_restore_path("/a/..hidden")); }  /* 前缀不算 */

/* ── copy_file ─────────────────────────────────────────────────────── */
TEST(copy_roundtrip){ setup();
    char s[300],d[300]; snprintf(s,sizeof(s),"%s/s",RD); snprintf(d,sizeof(d),"%s/d",RD);
    wf(s,"payload-12345");
    ASSERT_EQ(copy_file(s,d,0100640,0,0),0);
    char c[64]; rf(d,c,sizeof(c)); ASSERT_TRUE(strcmp(c,"payload-12345")==0);
    struct stat st; stat(d,&st); ASSERT_EQ((int)(st.st_mode&0777),0640); }
TEST(copy_src_symlink_refused){ setup();
    char t[300],l[300],d[300];
    snprintf(t,sizeof(t),"%s/t",RD); snprintf(l,sizeof(l),"%s/l",RD); snprintf(d,sizeof(d),"%s/d",RD);
    wf(t,"secret"); if(symlink(t,l)!=0){}
    ASSERT_EQ(copy_file(l,d,0644,0,0),-1);   /* O_NOFOLLOW：源是链接即拒 */
    ASSERT_EQ(access(d,F_OK),-1); }
TEST(copy_dst_symlink_refused){ setup();
    char s[300],t[300],l[300];
    snprintf(s,sizeof(s),"%s/s",RD); snprintf(t,sizeof(t),"%s/t",RD); snprintf(l,sizeof(l),"%s/l",RD);
    wf(s,"newdata"); wf(t,"keepme"); if(symlink(t,l)!=0){}
    ASSERT_EQ(copy_file(s,l,0644,0,0),-1);   /* 不穿透链接改写目标 */
    char c[64]; rf(t,c,sizeof(c)); ASSERT_TRUE(strcmp(c,"keepme")==0); }

/* ── restore_one ───────────────────────────────────────────────────── */
static void mkpf(struct rguard_protected_file *pf,long long id,
                 const char *eid,const char *orig,const char *bak){
    memset(pf,0,sizeof(*pf)); pf->id=id;
    snprintf(pf->event_id,sizeof(pf->event_id),"%s",eid);
    snprintf(pf->original_path,sizeof(pf->original_path),"%s",orig);
    snprintf(pf->backup_path,sizeof(pf->backup_path),"%s",bak);
    snprintf(pf->restore_status,sizeof(pf->restore_status),"pending");
    pf->file_mode=0100644; }
TEST(restore_happy){ setup();
    sqlite3 *db=NULL; db_open(DB_PATH,&db);
    char orig[300],bak[300];
    snprintf(orig,sizeof(orig),"%s/victim.txt",RD); snprintf(bak,sizeof(bak),"%s/bak",RD);
    wf(orig,"ENCRYPTED"); wf(bak,"original-good");
    struct rguard_protected_file pf; mkpf(&pf,1,"evt-t1",orig,bak);
    struct restore_ctx ctx={.db=db,.event_id="evt-t1",.auto_mode=true};
    restore_one(&pf,&ctx);
    ASSERT_EQ(ctx.success,1); ASSERT_EQ(ctx.fail,0);
    char c[64]; rf(orig,c,sizeof(c)); ASSERT_TRUE(strcmp(c,"original-good")==0);
    ASSERT_EQ(access(bak,F_OK),-1);          /* 备份已消费 */
    struct stat st; ASSERT_EQ(lstat("/tmp/trec_store/quarantine/evt-t1",&st),0); /* 污染副本进隔离区 */
    db_close(db); }
TEST(restore_symlink_victim){ setup();
    sqlite3 *db=NULL; db_open(DB_PATH,&db);
    char t[300],orig[300],bak[300];
    snprintf(t,sizeof(t),"%s/target",RD); snprintf(orig,sizeof(orig),"%s/link",RD);
    snprintf(bak,sizeof(bak),"%s/bak",RD);
    wf(t,"do-not-touch"); if(symlink(t,orig)!=0){} wf(bak,"good");
    struct rguard_protected_file pf; mkpf(&pf,1,"evt-t2",orig,bak);
    struct restore_ctx ctx={.db=db,.event_id="evt-t2",.auto_mode=true};
    restore_one(&pf,&ctx);
    ASSERT_EQ(ctx.success,1);
    char c[64]; rf(t,c,sizeof(c)); ASSERT_TRUE(strcmp(c,"do-not-touch")==0); /* 链接目标未动 */
    ASSERT_FALSE(is_symlink(orig));          /* 原位已是常规文件 */
    rf(orig,c,sizeof(c)); ASSERT_TRUE(strcmp(c,"good")==0);
    db_close(db); }
TEST(restore_unsafe_path){ setup();
    sqlite3 *db=NULL; db_open(DB_PATH,&db);
    struct rguard_protected_file pf; mkpf(&pf,1,"evt-t3","/a/../etc/x","/tmp/nope");
    struct restore_ctx ctx={.db=db,.event_id="evt-t3",.auto_mode=true};
    restore_one(&pf,&ctx);
    ASSERT_EQ(ctx.fail,1); ASSERT_EQ(ctx.success,0);
    db_close(db); }
/* quarantine 覆盖：两个受害文件映射到同一 qpath，先到的隔离副本不得被覆盖 */
TEST(quarantine_no_overwrite){ setup();
    sqlite3 *db=NULL; db_open(DB_PATH,&db);
    char orig[300],bak1[300],bak2[300],q[512];
    snprintf(orig,sizeof(orig),"%s/v.txt",RD);
    snprintf(bak1,sizeof(bak1),"%s/b1",RD); snprintf(bak2,sizeof(bak2),"%s/b2",RD);
    snprintf(q,sizeof(q),"/tmp/trec_store/quarantine/evt-t4%s",orig); /* rel 保留全路径 */
    wf(bak1,"v1"); wf(bak2,"v2");
    wf(orig,"BAD-1");
    struct rguard_protected_file pf; mkpf(&pf,1,"evt-t4",orig,bak1);
    struct restore_ctx ctx={.db=db,.event_id="evt-t4",.auto_mode=true};
    restore_one(&pf,&ctx);
    char c[64]; rf(q,c,sizeof(c)); ASSERT_TRUE(strcmp(c,"BAD-1")==0);
    /* 第二次恢复同路径（另一波攻击在同位置留下的坏文件） */
    wf(orig,"BAD-2");
    mkpf(&pf,2,"evt-t4",orig,bak2);
    restore_one(&pf,&ctx);
    rf(q,c,sizeof(c));
    ASSERT_TRUE(strcmp(c,"BAD-1")==0);    /* 核心：第一份证据没被静默盖掉 */
    db_close(db); }

/* ── delete_created_one ────────────────────────────────────────────── */
TEST(del_created_regular){ setup();
    char f[300]; snprintf(f,sizeof(f),"%s/note.html",RD); wf(f,"ransom note");
    struct delete_created_ctx ctx={.db=NULL,.event_id="evt-d1",.auto_mode=true};
    delete_created_one(1,f,&ctx);
    ASSERT_EQ(ctx.deleted,1); ASSERT_EQ(access(f,F_OK),-1);
    char q[512]; snprintf(q,sizeof(q),"/tmp/trec_store/quarantine/evt-d1%s",f); /* qpath 保留全路径 */
    ASSERT_EQ(access(q,F_OK),0); }         /* 证据移入隔离区 */
TEST(del_created_symlink_only_unlink){ setup();
    char t[300],l[300];
    snprintf(t,sizeof(t),"%s/t",RD); snprintf(l,sizeof(l),"%s/l",RD);
    wf(t,"innocent"); if(symlink(t,l)!=0){}
    struct delete_created_ctx ctx={.db=NULL,.event_id="evt-d2",.auto_mode=true};
    delete_created_one(2,l,&ctx);
    ASSERT_EQ(ctx.deleted,1);
    ASSERT_EQ(access(l,F_OK),-1);          /* 链接没了 */
    char c[64]; rf(t,c,sizeof(c)); ASSERT_TRUE(strcmp(c,"innocent")==0); } /* 目标还在 */
TEST(del_created_dangling_symlink){ setup();
    char l[300]; snprintf(l,sizeof(l),"%s/dangling",RD);
    if(symlink("/nonexistent/target",l)!=0){}
    struct delete_created_ctx ctx={.db=NULL,.event_id="evt-d3",.auto_mode=true};
    delete_created_one(3,l,&ctx);
    ASSERT_EQ(ctx.deleted,1); ASSERT_EQ(lstat(l,&(struct stat){0}),-1); }
TEST(del_created_dir_rmdir){ setup();
    char d[300]; snprintf(d,sizeof(d),"%s/newdir",RD); mkdir(d,0777);
    struct delete_created_ctx ctx={.db=NULL,.event_id="evt-d4",.auto_mode=true};
    delete_created_one(4,d,&ctx);
    ASSERT_EQ(ctx.deleted,1);              /* 空目录 rmdir 删掉 */
    ASSERT_EQ(access(d,F_OK),-1); }
TEST(del_created_unsafe){ setup();
    struct delete_created_ctx ctx={.db=NULL,.event_id="evt-d5",.auto_mode=true};
    delete_created_one(5,"/x/../etc/y",&ctx);
    ASSERT_EQ(ctx.failed,1); ASSERT_EQ(ctx.deleted,0); }

/* ── cmd_status：blocked 文件 >4095 字节时计数不得截断 ─────────────── */
TEST(status_full_count){ setup();
    { int fd=open("/tmp/trec_store/blocked",O_WRONLY|O_CREAT|O_TRUNC,0640);
      for(int i=0;i<2000;i++){ char ip[32]; int l=snprintf(ip,sizeof(ip),"10.%d.%d.%d\n",(i>>16)&255,(i>>8)&255,i&255); if(write(fd,ip,l)<0){} }
      close(fd); }                          /* ~20KB，远超 4095 */
    char cap[320]; snprintf(cap,sizeof(cap),"%s/cap",RD);
    fflush(stdout);
    int saved=dup(1);
    FILE *f=freopen(cap,"w",stdout);
    sqlite3 *db=NULL; db_open(DB_PATH,&db);
    cmd_status(db); db_close(db);
    fflush(stdout);
    dup2(saved,1); close(saved); (void)f;   /* stdout 复回原 fd */
    char c[4096]; rf(cap,c,sizeof(c));
    ASSERT_TRUE(strstr(c,"Blocked sessions : 2000")!=NULL); }

int main(void){ RUN_TEST(path_valid);RUN_TEST(path_reject_relative);RUN_TEST(path_reject_dotdot);
    RUN_TEST(copy_roundtrip);RUN_TEST(copy_src_symlink_refused);RUN_TEST(copy_dst_symlink_refused);
    RUN_TEST(restore_happy);RUN_TEST(restore_symlink_victim);RUN_TEST(restore_unsafe_path);
    RUN_TEST(quarantine_no_overwrite);
    RUN_TEST(del_created_regular);RUN_TEST(del_created_symlink_only_unlink);
    RUN_TEST(del_created_dangling_symlink);RUN_TEST(del_created_dir_rmdir);
    RUN_TEST(del_created_unsafe);RUN_TEST(status_full_count);
    return test_summary();}
