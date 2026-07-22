/* Unit tests for gfrguardd_fangate — flood gate table. */
#include "test_main.h"
#include "../src/daemon/gfrguardd_fangate.h"

static struct fangate g;

TEST(first_send_allowed)
{
    fangate_init(&g);
    ASSERT_TRUE(fangate_allow(&g, "user@1.2.3.4", 100, 1000, 10));
}

TEST(repeat_within_window_denied)
{
    fangate_init(&g);
    ASSERT_TRUE(fangate_allow(&g, "user@1.2.3.4", 100, 1000, 10));
    ASSERT_FALSE(fangate_allow(&g, "user@1.2.3.4", 100, 1005, 10));
    ASSERT_FALSE(fangate_allow(&g, "user@1.2.3.4", 100, 1009, 10));
}

TEST(allowed_after_window)
{
    fangate_init(&g);
    ASSERT_TRUE(fangate_allow(&g, "user@1.2.3.4", 100, 1000, 10));
    ASSERT_TRUE(fangate_allow(&g, "user@1.2.3.4", 100, 1010, 10));
}

TEST(different_inode_allowed)
{
    fangate_init(&g);
    ASSERT_TRUE(fangate_allow(&g, "user@1.2.3.4", 100, 1000, 10));
    ASSERT_TRUE(fangate_allow(&g, "user@1.2.3.4", 101, 1000, 10));
}

TEST(different_session_allowed)
{
    fangate_init(&g);
    ASSERT_TRUE(fangate_allow(&g, "alice@1.1.1.1", 100, 1000, 10));
    ASSERT_TRUE(fangate_allow(&g, "bob@2.2.2.2", 100, 1000, 10));
}

TEST(zero_window_always_allows)
{
    fangate_init(&g);
    ASSERT_TRUE(fangate_allow(&g, "user@1.2.3.4", 100, 1000, 0));
    ASSERT_TRUE(fangate_allow(&g, "user@1.2.3.4", 100, 1000, 0));
    ASSERT_TRUE(fangate_allow(&g, "user@1.2.3.4", 100, 1000, -5));
}

TEST(collision_fail_open)
{
    fangate_init(&g);
    /* Force a bucket collision: same slot index, different key.  With a
     * direct-mapped table any two keys sharing the low 10 bits collide;
     * craft them by probing inodes.  Eviction must always allow. */
    ASSERT_TRUE(fangate_allow(&g, "user@1.2.3.4", 100, 1000, 10));
    /* A different (session, inode) always gets through, even if it lands
     * in an occupied bucket — overwrite semantics. */
    for (uint64_t ino = 0; ino < 4096; ino++) {
        ASSERT_TRUE(fangate_allow(&g, "other@5.6.7.8", ino, 1000, 10));
    }
}

TEST(reset_clears_state)
{
    fangate_init(&g);
    ASSERT_TRUE(fangate_allow(&g, "user@1.2.3.4", 100, 1000, 10));
    ASSERT_FALSE(fangate_allow(&g, "user@1.2.3.4", 100, 1001, 10));
    fangate_reset(&g);
    ASSERT_TRUE(fangate_allow(&g, "user@1.2.3.4", 100, 1002, 10));
}

TEST(null_session_allows)
{
    fangate_init(&g);
    ASSERT_TRUE(fangate_allow(&g, NULL, 100, 1000, 10));
    ASSERT_TRUE(fangate_allow(&g, NULL, 100, 1000, 10));
}

int main(void)
{
    RUN_TEST(first_send_allowed);
    RUN_TEST(repeat_within_window_denied);
    RUN_TEST(allowed_after_window);
    RUN_TEST(different_inode_allowed);
    RUN_TEST(different_session_allowed);
    RUN_TEST(zero_window_always_allows);
    RUN_TEST(collision_fail_open);
    RUN_TEST(reset_clears_state);
    RUN_TEST(null_session_allows);
    return test_summary();
}
