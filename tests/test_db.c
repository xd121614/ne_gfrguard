#include "test_main.h"
#include <sqlite3.h>
#include "../src/common/rguard_db.h"
#include "../src/common/rguard_errors.h"
#include <string.h>
#include <unistd.h>

static void pf_fill(struct rguard_protected_file *p,const char *eid,const char *path){ memset(p,0,sizeof(*p));
    snprintf(p->event_id,sizeof(p->event_id),"%s",eid);
    snprintf(p->original_path,sizeof(p->original_path),"%s",path);
    snprintf(p->backup_path,sizeof(p->backup_path),"/tmp/b"); snprintf(p->share_name,sizeof(p->share_name),"s");
    snprintf(p->username,sizeof(p->username),"u"); snprintf(p->client_ip,sizeof(p->client_ip),"1.1.1.1"); }

static sqlite3 *fresh(void){ unlink("/tmp/tdb.db"); sqlite3 *db=NULL; db_open("/tmp/tdb.db",&db); return db; }

TEST(open_close){ unlink("/tmp/tdb.db"); sqlite3 *db=NULL;
    ASSERT_EQ(db_open("/tmp/tdb.db",&db),RGUARD_OK); ASSERT_TRUE(db!=NULL); db_close(db); }
TEST(open_null){ ASSERT_EQ(db_open(NULL,NULL),RGUARD_ERR_DB); }
TEST(insert_pf){ sqlite3 *db=fresh();
    struct rguard_protected_file pf; pf_fill(&pf,"evt-001","/tmp/a.txt");
    ASSERT_EQ(db_insert_protected_file(db,&pf),RGUARD_OK); db_close(db); }
TEST(insert_event){ sqlite3 *db=fresh();
    struct rguard_event_record ev; memset(&ev,0,sizeof(ev));
    snprintf(ev.event_id,sizeof(ev.event_id),"evt-001"); snprintf(ev.session_key,sizeof(ev.session_key),"sk");
    snprintf(ev.started_at,sizeof(ev.started_at),"2026-07-07T00:00:00");
    ASSERT_EQ(db_insert_event(db,&ev),RGUARD_OK); db_close(db); }
static int cb(const struct rguard_protected_file*pf,void*ctx){ (void)pf;(*(int*)ctx)++;return 0; }
TEST(query_by_event){ sqlite3 *db=fresh();
    struct rguard_protected_file pf; pf_fill(&pf,"evt-001","/tmp/a.txt"); db_insert_protected_file(db,&pf);
    pf_fill(&pf,"evt-001","/tmp/b.txt"); db_insert_protected_file(db,&pf);
    int c=0; db_query_by_event(db,"evt-001",cb,&c); ASSERT_EQ(c,2); db_close(db); }
TEST(count_pending){ sqlite3 *db=fresh();
    long long c=0; db_count_pending(db,&c); ASSERT_EQ((int)c,0);
    struct rguard_protected_file pf; pf_fill(&pf,"evt-001","/tmp/x.txt"); db_insert_protected_file(db,&pf);
    db_count_pending(db,&c); ASSERT_EQ((int)c,1); db_close(db); }

/* ── 字段 roundtrip：写入的每个字段必须原样读回 ─────────────────────── */
static struct rguard_protected_file g_pf;
static int grab(const struct rguard_protected_file *pf,void*ctx){ (void)ctx; g_pf=*pf; return 0; }
TEST(pf_field_roundtrip){ sqlite3 *db=fresh();
    struct rguard_protected_file pf; pf_fill(&pf,"evt-rt","/share/docs/report.docx");
    pf.inode=1234567; pf.mtime=1752000000; pf.file_size=987654;
    pf.file_uid=1000; pf.file_gid=1001; pf.file_mode=0100640; pf.op_type=3;
    snprintf(pf.protected_at,sizeof(pf.protected_at),"2026-07-19 10:00:00");
    ASSERT_EQ(db_insert_protected_file(db,&pf),RGUARD_OK);
    memset(&g_pf,0,sizeof(g_pf));
    int c=0; ASSERT_EQ(db_query_by_event(db,"evt-rt",grab,&c),RGUARD_OK);
    ASSERT_TRUE(strcmp(g_pf.event_id,"evt-rt")==0);
    ASSERT_TRUE(strcmp(g_pf.original_path,"/share/docs/report.docx")==0);
    ASSERT_TRUE(strcmp(g_pf.backup_path,"/tmp/b")==0);
    ASSERT_TRUE(strcmp(g_pf.share_name,"s")==0);
    ASSERT_TRUE(strcmp(g_pf.username,"u")==0);
    ASSERT_TRUE(strcmp(g_pf.client_ip,"1.1.1.1")==0);
    ASSERT_EQ((int)g_pf.inode,1234567);
    ASSERT_EQ((int)(g_pf.mtime/1000000),1752);
    ASSERT_EQ((int)g_pf.file_size,987654);
    ASSERT_EQ(g_pf.file_uid,1000); ASSERT_EQ(g_pf.file_gid,1001);
    ASSERT_EQ(g_pf.file_mode,0100640);
    ASSERT_TRUE(strcmp(g_pf.restore_status,"pending")==0);
    db_close(db); }

/* ── 去重：同 (event_id, original_path) 重复写入只保留一行 ──────────── */
TEST(pf_dedup){ sqlite3 *db=fresh();
    struct rguard_protected_file pf; pf_fill(&pf,"evt-dup","/tmp/same.txt");
    ASSERT_EQ(db_insert_protected_file(db,&pf),RGUARD_OK);
    ASSERT_EQ(db_insert_protected_file(db,&pf),RGUARD_OK); /* INSERT OR IGNORE 不报错 */
    int c=0; db_query_by_event(db,"evt-dup",cb,&c); ASSERT_EQ(c,1);
    db_close(db); }

/* ── update 族：用原始 SQL 验证副作用 ───────────────────────────────── */
static int qint(sqlite3 *db,const char *sql){ sqlite3_stmt *st=NULL; int v=-1;
    if(sqlite3_prepare_v2(db,sql,-1,&st,NULL)==SQLITE_OK && sqlite3_step(st)==SQLITE_ROW)
        v=sqlite3_column_int(st,0);
    sqlite3_finalize(st); return v; }
static void ev_fill(struct rguard_event_record *ev,const char *eid){ memset(ev,0,sizeof(*ev));
    snprintf(ev->event_id,sizeof(ev->event_id),"%s",eid);
    snprintf(ev->session_key,sizeof(ev->session_key),"u@1.1.1.1");
    snprintf(ev->username,sizeof(ev->username),"u"); snprintf(ev->client_ip,sizeof(ev->client_ip),"1.1.1.1");
    snprintf(ev->pname,sizeof(ev->pname),"smbd");
    snprintf(ev->started_at,sizeof(ev->started_at),"2026-07-19 10:00:00"); }
TEST(update_event){ sqlite3 *db=fresh();
    struct rguard_event_record ev; ev_fill(&ev,"evt-up"); db_insert_event(db,&ev);
    ASSERT_EQ(db_update_event(db,"evt-up",5,3,42,"kill","done","2026-07-19 10:01:00"),RGUARD_OK);
    ASSERT_EQ(qint(db,"SELECT files_protected FROM events WHERE event_id='evt-up'"),5);
    ASSERT_EQ(qint(db,"SELECT files_affected FROM events WHERE event_id='evt-up'"),3);
    ASSERT_EQ(qint(db,"SELECT peak_risk_score FROM events WHERE event_id='evt-up'"),42);
    /* MAX 语义：较小的值不得覆盖 */
    ASSERT_EQ(db_update_event(db,"evt-up",2,1,10,NULL,NULL,NULL),RGUARD_OK);
    ASSERT_EQ(qint(db,"SELECT files_protected FROM events WHERE event_id='evt-up'"),5);
    ASSERT_EQ(qint(db,"SELECT peak_risk_score FROM events WHERE event_id='evt-up'"),42);
    db_close(db); }
TEST(upsert_event){ sqlite3 *db=fresh();
    struct rguard_event_record ev; ev_fill(&ev,"evt-ups"); ev.files_protected=1; ev.peak_risk_score=10;
    ASSERT_EQ(db_upsert_event(db,&ev),RGUARD_OK);
    ev.files_protected=7; ev.peak_risk_score=66;
    ASSERT_EQ(db_upsert_event(db,&ev),RGUARD_OK); /* 冲突走 UPDATE 分支 */
    ASSERT_EQ(qint(db,"SELECT COUNT(*) FROM events WHERE event_id='evt-ups'"),1);
    ASSERT_EQ(qint(db,"SELECT files_protected FROM events WHERE event_id='evt-ups'"),7);
    ASSERT_EQ(qint(db,"SELECT peak_risk_score FROM events WHERE event_id='evt-ups'"),66);
    db_close(db); }
TEST(event_source_type){ sqlite3 *db=fresh();
    struct rguard_event_record ev; ev_fill(&ev,"evt-st"); ev.source_type=RGUARD_SOURCE_FTP;
    ASSERT_EQ(db_insert_event(db,&ev),RGUARD_OK);
    ASSERT_EQ(qint(db,"SELECT source_type FROM events WHERE event_id='evt-st'"),RGUARD_SOURCE_FTP);
    /* upsert 传入 0（未知）不得覆盖已知通道 */
    ev.source_type=0;
    ASSERT_EQ(db_upsert_event(db,&ev),RGUARD_OK);
    ASSERT_EQ(qint(db,"SELECT source_type FROM events WHERE event_id='evt-st'"),RGUARD_SOURCE_FTP);
    /* 传入非 0 的新通道则允许纠正 */
    ev.source_type=RGUARD_SOURCE_HOST;
    ASSERT_EQ(db_upsert_event(db,&ev),RGUARD_OK);
    ASSERT_EQ(qint(db,"SELECT source_type FROM events WHERE event_id='evt-st'"),RGUARD_SOURCE_HOST);
    db_close(db); }
TEST(update_restore_status){ sqlite3 *db=fresh();
    struct rguard_protected_file pf; pf_fill(&pf,"evt-rs","/tmp/r.txt"); db_insert_protected_file(db,&pf);
    memset(&g_pf,0,sizeof(g_pf)); int c=0; db_query_by_event(db,"evt-rs",grab,&c);
    long long c2=0; db_count_pending(db,&c2); ASSERT_EQ((int)c2,1);
    ASSERT_EQ(db_update_restore_status(db,g_pf.id,"restored","2026-07-19 11:00:00"),RGUARD_OK);
    db_count_pending(db,&c2); ASSERT_EQ((int)c2,0);
    memset(&g_pf,0,sizeof(g_pf)); db_query_by_event(db,"evt-rs",grab,&c);
    ASSERT_TRUE(strcmp(g_pf.restore_status,"restored")==0);
    ASSERT_TRUE(strcmp(g_pf.restored_at,"2026-07-19 11:00:00")==0);
    db_close(db); }
TEST(query_by_path){ sqlite3 *db=fresh();
    struct rguard_protected_file pf; pf_fill(&pf,"evt-p1","/tmp/target.txt"); db_insert_protected_file(db,&pf);
    pf_fill(&pf,"evt-p2","/tmp/target.txt"); db_insert_protected_file(db,&pf);
    pf_fill(&pf,"evt-p3","/tmp/other.txt"); db_insert_protected_file(db,&pf);
    int c=0; ASSERT_EQ(db_query_by_path(db,"/tmp/target.txt",cb,&c),RGUARD_OK); ASSERT_EQ(c,2);
    db_close(db); }

/* ── created_files 三函数 ───────────────────────────────────────────── */
static int cf_cb(long long id,const char *path,void*ctx){ (void)path;
    long long *ids=ctx; ids[1]++; if(ids[0]==0) ids[0]=id; return 0; }
TEST(created_files){ sqlite3 *db=fresh();
    ASSERT_EQ(db_insert_created_file(db,"evt-cf","/tmp/new1.locked","s","u","1.1.1.1","2026-07-19 10:00:00"),RGUARD_OK);
    ASSERT_EQ(db_insert_created_file(db,"evt-cf","/tmp/new2.locked","s","u","1.1.1.1","2026-07-19 10:00:01"),RGUARD_OK);
    ASSERT_EQ(db_insert_created_file(db,"evt-other","/tmp/other.locked","s","u","1.1.1.1","2026-07-19 10:00:02"),RGUARD_OK);
    long long ctx[2]={0,0};
    ASSERT_EQ(db_query_created_by_event(db,"evt-cf",cf_cb,ctx),RGUARD_OK);
    ASSERT_EQ((int)ctx[1],2); ASSERT_TRUE(ctx[0]!=0);
    ASSERT_EQ(db_delete_created_file(db,ctx[0]),RGUARD_OK);
    ctx[0]=0; ctx[1]=0; db_query_created_by_event(db,"evt-cf",cf_cb,ctx);
    ASSERT_EQ((int)ctx[1],1);
    db_close(db); }
TEST(created_files_empty){ sqlite3 *db=fresh();
    long long ctx[2]={0,0};
    ASSERT_EQ(db_query_created_by_event(db,"evt-none",cf_cb,ctx),RGUARD_OK);
    ASSERT_EQ((int)ctx[1],0); db_close(db); }

/* ── cloud_task_configs 三函数 + M28 错误码 ─────────────────────────── */
TEST(cloud_task_roundtrip){ sqlite3 *db=fresh();
    ASSERT_EQ(db_save_cloud_task_config(db,"evt-c1","photos-sync","0 2 * * *","rclone sync","2026-07-19 10:00:00"),RGUARD_OK);
    char expr[128]={0},cmd[256]={0};
    ASSERT_EQ(db_get_cloud_task_config(db,"photos-sync",expr,sizeof(expr),cmd,sizeof(cmd)),RGUARD_OK);
    ASSERT_TRUE(strcmp(expr,"0 2 * * *")==0); ASSERT_TRUE(strcmp(cmd,"rclone sync")==0);
    db_close(db); }
TEST(cloud_task_latest_wins){ sqlite3 *db=fresh();
    db_save_cloud_task_config(db,"evt-c1","t","0 1 * * *","cmd-old","2026-07-19 10:00:00");
    db_save_cloud_task_config(db,"evt-c2","t","0 2 * * *","cmd-new","2026-07-19 11:00:00");
    char expr[128]={0},cmd[256]={0};
    ASSERT_EQ(db_get_cloud_task_config(db,"t",expr,sizeof(expr),cmd,sizeof(cmd)),RGUARD_OK);
    ASSERT_TRUE(strcmp(cmd,"cmd-new")==0); /* ORDER BY id DESC 取最近 */
    db_close(db); }
TEST(cloud_task_not_found){ sqlite3 *db=fresh();
    char expr[128]={0},cmd[256]={0};
    /* M28：未找到必须返回正数错误码 RGUARD_ERR_NOT_FOUND，不是 -1 */
    ASSERT_EQ(db_get_cloud_task_config(db,"nonexistent",expr,sizeof(expr),cmd,sizeof(cmd)),RGUARD_ERR_NOT_FOUND);
    db_close(db); }
TEST(cloud_task_restored_not_returned){ sqlite3 *db=fresh();
    db_save_cloud_task_config(db,"evt-c1","t","0 2 * * *","cmd","2026-07-19 10:00:00");
    ASSERT_EQ(db_mark_cloud_task_restored(db,"t","2026-07-19 12:00:00"),RGUARD_OK);
    char expr[128]={0},cmd[256]={0};
    ASSERT_EQ(db_get_cloud_task_config(db,"t",expr,sizeof(expr),cmd,sizeof(cmd)),RGUARD_ERR_NOT_FOUND);
    ASSERT_EQ(qint(db,"SELECT COUNT(*) FROM cloud_task_configs WHERE status='restored'"),1);
    db_close(db); }

/* ── daily seq ─────────────────────────────────────────────────────── */
TEST(daily_seq){ sqlite3 *db=fresh();
    int seq=-1; ASSERT_EQ(db_get_max_daily_seq(db,"20260719",&seq),RGUARD_OK); ASSERT_EQ(seq,0);
    struct rguard_event_record ev; ev_fill(&ev,"evt-20260719-001"); db_insert_event(db,&ev);
    ev_fill(&ev,"evt-20260719-007"); db_insert_event(db,&ev);
    ev_fill(&ev,"evt-20260718-099"); db_insert_event(db,&ev); /* 别的日期不混入 */
    ASSERT_EQ(db_get_max_daily_seq(db,"20260719",&seq),RGUARD_OK); ASSERT_EQ(seq,7);
    /* LIKE 通配符前缀必须被拒（ digits only ） */
    ASSERT_EQ(db_get_max_daily_seq(db,"2026%",&seq),RGUARD_ERR_DB);
    ASSERT_EQ(db_get_max_daily_seq(db,"2026_719",&seq),RGUARD_ERR_DB);
    db_close(db); }

/* ── cleanup_restored 边界 ─────────────────────────────────────────── */
TEST(cleanup_negative_days){ sqlite3 *db=fresh();
    long long del=-1;
    /* 负 days 生成非法 modifier，必须报错而不是静默返回 OK */
    ASSERT_EQ(db_cleanup_restored(db,-5,&del),RGUARD_ERR_DB);
    db_close(db); }

int main(void){ RUN_TEST(open_close);RUN_TEST(open_null);RUN_TEST(insert_pf);
    RUN_TEST(insert_event);RUN_TEST(query_by_event);RUN_TEST(count_pending);
    RUN_TEST(pf_field_roundtrip);RUN_TEST(pf_dedup);
    RUN_TEST(update_event);RUN_TEST(upsert_event);RUN_TEST(event_source_type);RUN_TEST(update_restore_status);RUN_TEST(query_by_path);
    RUN_TEST(created_files);RUN_TEST(created_files_empty);
    RUN_TEST(cloud_task_roundtrip);RUN_TEST(cloud_task_latest_wins);
    RUN_TEST(cloud_task_not_found);RUN_TEST(cloud_task_restored_not_returned);
    RUN_TEST(daily_seq);RUN_TEST(cleanup_negative_days);
    return test_summary();}
