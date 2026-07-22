#include "test_main.h"
#include "../src/daemon/gfrguardd_scorer.h"
#include "../src/common/rguard_config.h"
#include "../src/common/rguard_errors.h"
#include <string.h>
#include <stdlib.h>

/* Helper: build an IP string like "10.0.0.N" */
static void ip_n(int n, char *out, size_t len)
{
    snprintf(out, len, "10.0.0.%d", n);
}

/* ── basic: add one entry ────────────────────────────────────────────── */
TEST(basic_add)
{
    struct rguard_policy p;
    memset(&p, 0, sizeof(p));

    scorer_blacklist_auto_add(&p, "192.168.1.1");
    ASSERT_EQ(p.blacklist.auto_ip_count, 1);
    ASSERT_STREQ(p.blacklist.auto_ips[0].ip, "192.168.1.1");
    ASSERT_TRUE(p.blacklist.auto_ips[0].auto_add);
}

/* ── duplicate: same IP twice, count unchanged ──────────────────────── */
TEST(duplicate)
{
    struct rguard_policy p;
    memset(&p, 0, sizeof(p));

    scorer_blacklist_auto_add(&p, "10.0.0.1");
    scorer_blacklist_auto_add(&p, "10.0.0.1");
    ASSERT_EQ(p.blacklist.auto_ip_count, 1);
}

/* ── nil / empty guards ──────────────────────────────────────────────── */
TEST(nil_guard)
{
    struct rguard_policy p;
    memset(&p, 0, sizeof(p));

    scorer_blacklist_auto_add(NULL, "1.2.3.4");
    scorer_blacklist_auto_add(&p, NULL);
    scorer_blacklist_auto_add(&p, "");
    ASSERT_EQ(p.blacklist.auto_ip_count, 0);
}

/* ── manual skip: IP already in manual list is NOT added to auto ─────── */
TEST(manual_skip)
{
    struct rguard_policy p;
    memset(&p, 0, sizeof(p));

    /* Put it in the manual list first */
    snprintf(p.blacklist.ips[0].ip, RGUARD_IP_LEN, "%s", "10.99.99.99");
    p.blacklist.ips[0].auto_add = false;
    p.blacklist.ip_count = 1;

    scorer_blacklist_auto_add(&p, "10.99.99.99");
    ASSERT_EQ(p.blacklist.auto_ip_count, 0);
}

/* ── scorer_is_blacklisted sees auto entries ─────────────────────────── */
TEST(lookup_auto)
{
    struct rguard_policy p;
    memset(&p, 0, sizeof(p));

    scorer_blacklist_auto_add(&p, "172.16.0.1");
    scorer_blacklist_auto_add(&p, "172.16.0.2");

    ASSERT_TRUE(scorer_is_blacklisted(&p, NULL, "172.16.0.1"));
    ASSERT_TRUE(scorer_is_blacklisted(&p, NULL, "172.16.0.2"));
    ASSERT_FALSE(scorer_is_blacklisted(&p, NULL, "172.16.0.3"));
}

/* ── fill 64, add 65th → oldest evicted ──────────────────────────────── */
TEST(fifo_evict_one)
{
    struct rguard_policy p;
    memset(&p, 0, sizeof(p));

    /* Fill with 0..63 */
    for (int i = 0; i < 64; i++) {
        char buf[48];
        ip_n(i, buf, sizeof(buf));
        scorer_blacklist_auto_add(&p, buf);
    }
    ASSERT_EQ(p.blacklist.auto_ip_count, 64);
    /* Oldest is index 0 = "10.0.0.0" */
    ASSERT_STREQ(p.blacklist.auto_ips[0].ip, "10.0.0.0");

    /* Add 65th — evict "10.0.0.0" */
    scorer_blacklist_auto_add(&p, "10.0.0.64");
    ASSERT_EQ(p.blacklist.auto_ip_count, 64);

    /* "10.0.0.0" must be gone, "10.0.0.1" is new oldest at index 0 */
    ASSERT_FALSE(scorer_is_blacklisted(&p, NULL, "10.0.0.0"));
    /* "10.0.0.1" through "10.0.0.64" must all be present */
    ASSERT_TRUE(scorer_is_blacklisted(&p, NULL, "10.0.0.1"));
    ASSERT_TRUE(scorer_is_blacklisted(&p, NULL, "10.0.0.63"));
    ASSERT_TRUE(scorer_is_blacklisted(&p, NULL, "10.0.0.64"));
}

/* ── fill 64, add 130 more → oldest 130 evicted ─────────────────────── */
TEST(fifo_evict_many)
{
    struct rguard_policy p;
    memset(&p, 0, sizeof(p));

    /* Fill with 0..63 */
    for (int i = 0; i < 64; i++) {
        char buf[48];
        ip_n(i, buf, sizeof(buf));
        scorer_blacklist_auto_add(&p, buf);
    }
    ASSERT_EQ(p.blacklist.auto_ip_count, 64);

    /* Add 64 more (64..127) — evicts 0..63 in order */
    for (int i = 64; i < 128; i++) {
        char buf[48];
        ip_n(i, buf, sizeof(buf));
        scorer_blacklist_auto_add(&p, buf);
    }
    ASSERT_EQ(p.blacklist.auto_ip_count, 64);

    /* First 64 must ALL be gone */
    for (int i = 0; i < 64; i++) {
        char buf[48];
        ip_n(i, buf, sizeof(buf));
        ASSERT_FALSE(scorer_is_blacklisted(&p, NULL, buf));
    }
    /* Last 64 (64..127) must ALL be present */
    for (int i = 64; i < 128; i++) {
        char buf[48];
        ip_n(i, buf, sizeof(buf));
        ASSERT_TRUE(scorer_is_blacklisted(&p, NULL, buf));
    }
}

/* ── evicted entry can be re-added ──────────────────────────────────── */
TEST(re_add_after_evict)
{
    struct rguard_policy p;
    memset(&p, 0, sizeof(p));

    /* Fill with 0..63 */
    for (int i = 0; i < 64; i++) {
        char buf[48];
        ip_n(i, buf, sizeof(buf));
        scorer_blacklist_auto_add(&p, buf);
    }
    /* Evict 0 */
    scorer_blacklist_auto_add(&p, "10.0.0.64");
    ASSERT_FALSE(scorer_is_blacklisted(&p, NULL, "10.0.0.0"));

    /* Re-add 0 — it should come back at the tail */
    scorer_blacklist_auto_add(&p, "10.0.0.0");
    ASSERT_EQ(p.blacklist.auto_ip_count, 64);
    ASSERT_TRUE(scorer_is_blacklisted(&p, NULL, "10.0.0.0"));
}

/* ── insertion order is preserved (FIFO relies on it) ───────────────── */
TEST(insertion_order_preserved)
{
    struct rguard_policy p;
    memset(&p, 0, sizeof(p));

    for (int i = 0; i < 64; i++) {
        char buf[48];
        ip_n(i, buf, sizeof(buf));
        scorer_blacklist_auto_add(&p, buf);
    }
    /* After filling 64 entries (no eviction yet), they must be in order */
    for (int i = 0; i < 64; i++) {
        char expected[48];
        ip_n(i, expected, sizeof(expected));
        ASSERT_STREQ(p.blacklist.auto_ips[i].ip, expected);
    }

    /* Evict index 0, add new — new must be at tail */
    scorer_blacklist_auto_add(&p, "10.0.0.64");
    ASSERT_STREQ(p.blacklist.auto_ips[0].ip, "10.0.0.1");   /* shifted left */
    ASSERT_STREQ(p.blacklist.auto_ips[63].ip, "10.0.0.64");  /* new at tail */
}

/* ── auto_add flag is always true on auto entries ───────────────────── */
TEST(auto_add_flag)
{
    struct rguard_policy p;
    memset(&p, 0, sizeof(p));

    for (int i = 0; i < 100; i++) {
        char buf[48];
        ip_n(i, buf, sizeof(buf));
        scorer_blacklist_auto_add(&p, buf);
    }
    ASSERT_EQ(p.blacklist.auto_ip_count, 64);
    for (int i = 0; i < p.blacklist.auto_ip_count; i++) {
        ASSERT_TRUE(p.blacklist.auto_ips[i].auto_add);
    }
}

/* ══════════════════════════════════════════════════════════════════════ */
int main(void)
{
    RUN_TEST(basic_add);
    RUN_TEST(duplicate);
    RUN_TEST(nil_guard);
    RUN_TEST(manual_skip);
    RUN_TEST(lookup_auto);
    RUN_TEST(fifo_evict_one);
    RUN_TEST(fifo_evict_many);
    RUN_TEST(re_add_after_evict);
    RUN_TEST(insertion_order_preserved);
    RUN_TEST(auto_add_flag);
    return test_summary();
}
