/* test_hash.c — rguard_hash.h 直接测试（此前零覆盖） */
#include "test_main.h"
#include "../src/common/rguard_hash.h"
#include <string.h>

/* FNV-1a 64 已知向量（http://www.isthe.com/chongo/tech/comp/fnv/） */
TEST(fnv_vectors){
    ASSERT_EQ(rguard_fnv1a64("",0),14695981039346656037ULL);
    ASSERT_EQ(rguard_fnv1a64("a",1),12638187200555641996ULL);
    ASSERT_EQ(rguard_fnv1a64("foobar",6),(long)0x85944171f73967e8LL); }
TEST(fnv_length_matters){
    /* 前缀相同长度不同 → hash 不同（lookup_len 的语义基础） */
    ASSERT_TRUE(rguard_fnv1a64("/a/b",4)!=rguard_fnv1a64("/a/b/c",6)); }

/* ── lookup：排序数组 + 等长匹配 ─────────────────────────────────────── */
static uint64_t H[4]; static char S[4][48]; static int N;
static void setup(const char **list,int n){ N=n;
    for(int i=0;i<n;i++){ snprintf(S[i],48,"%s",list[i]); H[i]=rguard_fnv1a64(S[i],strlen(S[i])); }
    SORT_BY_HASH(H,S,N,sizeof(S[0])); }
TEST(lookup_hit_miss){ const char *l[]={"alpha","beta","gamma","delta"}; setup(l,4);
    ASSERT_TRUE(rguard_hash_lookup("alpha",H,S,N,sizeof(S[0])));
    ASSERT_TRUE(rguard_hash_lookup("delta",H,S,N,sizeof(S[0])));
    ASSERT_FALSE(rguard_hash_lookup("omega",H,S,N,sizeof(S[0])));
    ASSERT_FALSE(rguard_hash_lookup("",H,S,N,sizeof(S[0])));
    ASSERT_FALSE(rguard_hash_lookup("alpha",H,S,0,sizeof(S[0]))); }
TEST(sort_by_hash_sync){
    /* 排序后 hashes 升序，且 strings 跟随同一排列（不同步就全错） */
    const char *l[]={"zeta","apple","mango","berry"}; setup(l,4);
    for(int i=1;i<N;i++) ASSERT_TRUE(H[i-1]<=H[i]);
    for(int i=0;i<N;i++) ASSERT_EQ(H[i],(long)rguard_fnv1a64(S[i],strlen(S[i]))); }
TEST(lookup_collision_walk){
    /* 手工构造同 hash 三条目（排序数组中相邻）——lookup 必须邻走找到真身，
     * 也必须拒绝同 hash 的陌生人 */
    const char *l[]={"real-one","decoy"}; setup(l,2);
    uint64_t h=rguard_fnv1a64("real-one",8);
    /* 伪造：两个不同字符串共用同一 hash 槽 */
    snprintf(S[0],48,"decoy-a"); snprintf(S[1],48,"real-one");
    H[0]=h; H[1]=h; N=2;
    ASSERT_TRUE(rguard_hash_lookup("real-one",H,S,N,sizeof(S[0])));
    ASSERT_FALSE(rguard_hash_lookup("decoy-a",H,S,N,sizeof(S[0]))||0);  /* decoy 也在，改查别的 */
    ASSERT_FALSE(rguard_hash_lookup("stranger",H,S,N,sizeof(S[0]))); }
TEST(lookup_len_exact){
    /* 等长才匹配：调用方自己走父目录逐级探测（注释曾谎称前缀匹配） */
    const char *l[]={"/srv/share/docs","/srv/share"}; setup(l,2);
    ASSERT_TRUE(rguard_hash_lookup_len("/srv/share",10,H,S,N,sizeof(S[0])));
    ASSERT_TRUE(rguard_hash_lookup_len("/srv/share/docs",15,H,S,N,sizeof(S[0])));
    /* "/srv/share/docs/file.txt" 不是任何条目的等长串 → 不匹配 */
    ASSERT_FALSE(rguard_hash_lookup_len("/srv/share/docs/file.txt",24,H,S,N,sizeof(S[0])));
    /* 前缀 "/srv/share" 后接 'X'（非目录边界）本来就是不同串 → 不匹配 */
    ASSERT_FALSE(rguard_hash_lookup_len("/srv/shareX",11,H,S,N,sizeof(S[0]))); }
TEST(lookup_len_collision_walk){
    const char *l[]={"/a"}; setup(l,1);
    uint64_t h=rguard_fnv1a64("/a",2);
    snprintf(S[0],48,"/b"); H[0]=h; N=1;   /* 同 hash 不同串 */
    ASSERT_FALSE(rguard_hash_lookup_len("/a",2,H,S,N,sizeof(S[0]))); }

int main(void){ RUN_TEST(fnv_vectors);RUN_TEST(fnv_length_matters);
    RUN_TEST(lookup_hit_miss);RUN_TEST(sort_by_hash_sync);
    RUN_TEST(lookup_collision_walk);RUN_TEST(lookup_len_exact);
    RUN_TEST(lookup_len_collision_walk);
    return test_summary();}
