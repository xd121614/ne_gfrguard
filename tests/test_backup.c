/* Unit tests for rguard_backup.h — reflink→copy_file_range→read/write. */
#include "test_main.h"
#include "../src/common/rguard_backup.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_src[64], g_dst[64];

static int make_src(size_t size, unsigned seed)
{
    snprintf(g_src, sizeof(g_src), "/tmp/rgb_src_%d_XXXXXX", getpid());
    int fd = mkstemp(g_src);
    if (fd < 0) return -1;
    srand(seed);
    char buf[4096];
    size_t left = size;
    while (left > 0) {
        size_t n = left < sizeof(buf) ? left : sizeof(buf);
        for (size_t i = 0; i < n; i++) buf[i] = (char)rand();
        if (write(fd, buf, n) != (ssize_t)n) { close(fd); return -1; }
        left -= n;
    }
    lseek(fd, 0, SEEK_SET);
    return fd;
}

static int open_dst(void)
{
    snprintf(g_dst, sizeof(g_dst), "/tmp/rgb_dst_%d_XXXXXX", getpid());
    return mkstemp(g_dst);
}

static bool files_equal(const char *a, const char *b)
{
    FILE *fa = fopen(a, "rb"), *fb = fopen(b, "rb");
    if (!fa || !fb) { if (fa) fclose(fa); if (fb) fclose(fb); return false; }
    bool same = true;
    int ca, cb;
    do {
        ca = fgetc(fa); cb = fgetc(fb);
        if (ca != cb) { same = false; break; }
    } while (ca != EOF);
    fclose(fa); fclose(fb);
    return same;
}

static void copy_case(size_t size, unsigned seed)
{
    int sfd = make_src(size, seed);
    int dfd = open_dst();
    ASSERT_TRUE(sfd >= 0 && dfd >= 0);

    ASSERT_EQ(rguard_copy_fd(sfd, dfd, (off_t)size), 0);

    struct stat st;
    ASSERT_EQ(fstat(dfd, &st), 0);
    ASSERT_EQ((size_t)st.st_size, size);
    ASSERT_TRUE(files_equal(g_src, g_dst));

    close(sfd); close(dfd);
    unlink(g_src); unlink(g_dst);
}

TEST(empty_file)        { copy_case(0, 1); }
TEST(small_file)        { copy_case(4096, 2); }
TEST(unaligned_file)    { copy_case(12345, 3); }
TEST(multi_chunk_file)  { copy_case(3u << 20, 4); }  /* > copy_file_range 1MiB 块 */

TEST(nonseekable_src_fails)
{
    /* pipe 源不可 lseek/clone/cfr → 全链路失败必须返回 -1 而非假成功 */
    int p[2];
    ASSERT_EQ(pipe(p), 0);
    int dfd = open_dst();
    ASSERT_TRUE(dfd >= 0);
    ASSERT_EQ(rguard_copy_fd(p[0], dfd, 100), -1);
    close(p[0]); close(p[1]); close(dfd);
    unlink(g_dst);
}

int main(void)
{
    RUN_TEST(empty_file);
    RUN_TEST(small_file);
    RUN_TEST(unaligned_file);
    RUN_TEST(multi_chunk_file);
    RUN_TEST(nonseekable_src_fails);
    return test_summary();
}
