#include "test_main.h"
#include "../src/daemon/gfrguardd_entropy.h"
#include <stdio.h>
#include <string.h>

TEST(zero) { FILE *f=fopen("/tmp/te_z.bin","wb"); char b[8192]; memset(b,0,8192);
    fwrite(b,1,8192,f); fclose(f); ASSERT_FLOAT_NEAR(entropy_compute_file("/tmp/te_z.bin",8192),0.0,0.01); }
TEST(max)  { FILE *f=fopen("/tmp/te_m.bin","wb"); char b[8192];
    for(int i=0;i<8192;i++) b[i]=(char)(i%256);
    fwrite(b,1,8192,f); fclose(f);
    ASSERT_FLOAT_NEAR(entropy_compute_file("/tmp/te_m.bin",8192),8.0,0.01); }
TEST(empty){ FILE *f=fopen("/tmp/te_e.bin","wb"); fclose(f);
    ASSERT_FLOAT_NEAR(entropy_compute_file("/tmp/te_e.bin",8192),0.0,0.01); }
TEST(nonexistent){ ASSERT_TRUE(entropy_compute_file("/tmp/no_such_file_entropy.bin",8192)<0.0); }
TEST(threshold){ ASSERT_TRUE(entropy_is_suspicious(7.1,7.0)); ASSERT_TRUE(entropy_is_suspicious(7.0,7.0));
    ASSERT_FALSE(entropy_is_suspicious(6.9,7.0)); ASSERT_FALSE(entropy_is_suspicious(-1.0,7.0)); }
TEST(constants){ ASSERT_TRUE(ENTROPY_DEFAULT_THRESHOLD==7.0); ASSERT_EQ(ENTROPY_SAMPLE_SIZE,8192); }
int main(void){ RUN_TEST(zero);RUN_TEST(max);RUN_TEST(empty);RUN_TEST(nonexistent);
    RUN_TEST(threshold);RUN_TEST(constants);return test_summary();}
