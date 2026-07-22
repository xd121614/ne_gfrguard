#define _POSIX_C_SOURCE 200809L
#include "gfrguardd_yara.h"
#include "../common/rguard_log.h"
#include "../common/rguard_protocol.h"   /* RGUARD_PATH_MAX */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include <yara.h>

static YR_COMPILER *g_compiler = NULL;
static YR_RULES    *g_rules    = NULL;
static bool         g_active   = false;

/* Recursively scan a directory for .yar/.yara files, test-compile each
 * individually, and add clean files to g_compiler.  Returns number loaded,
 * or -1 when the compiler is poisoned (a late add failed).
 *
 * depth caps the recursion: stat() follows symlinks, and a symlink loop
 * would otherwise mean unbounded recursion (stack overflow).
 * seen[] dedupes by (dev,ino): a symlinked directory must not add the
 * same rule file twice — a duplicate rule name is a compile ERROR, and
 * yr_compiler_add_file asserts on a compiler that already has errors. */
#define YARA_MAX_DEPTH 8
#define YARA_MAX_FILES 512
struct yara_load_ctx {
    struct { dev_t dev; ino_t ino; } seen[YARA_MAX_FILES];
    int nseen;
};

static int load_rules_recursive(const char *path, int depth,
                                struct yara_load_ctx *lc)
{
    if (depth > YARA_MAX_DEPTH) return 0;
    DIR *dir = opendir(path);
    if (!dir) return 0;

    int loaded = 0;
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') continue;  /* skip . / .. / hidden */

        char full[RGUARD_PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", path, de->d_name);

        struct stat st;
        if (stat(full, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            int r = load_rules_recursive(full, depth + 1, lc);
            if (r < 0) { closedir(dir); return -1; }
            loaded += r;
            continue;
        }

        size_t nlen = strlen(de->d_name);
        bool is_yar  = (nlen > 4 && strcmp(de->d_name + nlen - 4, ".yar") == 0);
        bool is_yara = (nlen > 5 && strcmp(de->d_name + nlen - 5, ".yara") == 0);
        if (!is_yar && !is_yara) continue;
        if (!S_ISREG(st.st_mode)) continue;

        /* Same file via another path (symlink/hardlink) — already loaded. */
        bool dup = false;
        for (int i = 0; i < lc->nseen; i++) {
            if (lc->seen[i].dev == st.st_dev && lc->seen[i].ino == st.st_ino) {
                dup = true;
                break;
            }
        }
        if (dup) continue;
        if (lc->nseen < YARA_MAX_FILES) {
            lc->seen[lc->nseen].dev = st.st_dev;
            lc->seen[lc->nseen].ino = st.st_ino;
            lc->nseen++;
        }

        /* Test-compile in a temporary compiler first. */
        {
            YR_COMPILER *test_comp = NULL;
            if (yr_compiler_create(&test_comp) != ERROR_SUCCESS) continue;
            FILE *fp = fopen(full, "r");
            if (!fp) { yr_compiler_destroy(test_comp); continue; }
            int errors = yr_compiler_add_file(test_comp, fp, NULL, full);
            fclose(fp);
            yr_compiler_destroy(test_comp);
            if (errors > 0) {
                char det[512];
                snprintf(det, sizeof(det),
                         "{\"file\":\"%.450s\",\"errors\":%d,\"action\":\"skipped\"}",
                         full, errors);
                rguard_log_write(LOG_WARN, "YARA_SKIP_FILE", NULL, det);
                continue;
            }
        }

        FILE *fp = fopen(full, "r");
        if (!fp) continue;
        /* The file changed since the test compile (or memory pressure):
         * a failed add POISONS g_compiler (libyara asserts errors==0 on
         * the next add) — fail the whole load instead of limping on. */
        int errors = yr_compiler_add_file(g_compiler, fp, NULL, full);
        fclose(fp);
        if (errors > 0) {
            char det[512];
            snprintf(det, sizeof(det),
                     "{\"file\":\"%.450s\",\"errors\":%d,\"action\":\"load_aborted\"}",
                     full, errors);
            rguard_log_write(LOG_ERROR, "YARA_LOAD_ABORTED", NULL, det);
            closedir(dir);
            return -1;
        }
        loaded++;
    }
    closedir(dir);
    return loaded;
}

/* Rebuild YARA rules skipping any file that has compile errors.
 * Each file is tested individually before adding to the final compiler. */
static int yara_engine_init_clean(const char *rules_dir)
{
    int rc = yr_initialize();
    if (rc != ERROR_SUCCESS) return -1;

    rc = yr_compiler_create(&g_compiler);
    if (rc != ERROR_SUCCESS) { yr_finalize(); return -1; }

    struct yara_load_ctx lc = { .nseen = 0 };
    int rules_loaded = load_rules_recursive(rules_dir, 0, &lc);

    if (rules_loaded <= 0) {
        yr_compiler_destroy(g_compiler);
        g_compiler = NULL;
        yr_finalize();
        if (rules_loaded < 0) {
            rguard_log_write(LOG_ERROR, "YARA_INIT_FAILED", NULL,
                             "{\"reason\":\"compiler poisoned by late add failure\"}");
            return -1;
        }
        rguard_log_write(LOG_WARN, "YARA_NO_RULES", NULL,
                         "{\"reason\":\"all files have errors\"}");
        return 0;
    }

    rc = yr_compiler_get_rules(g_compiler, &g_rules);
    yr_compiler_destroy(g_compiler);
    g_compiler = NULL;

    if (rc != ERROR_SUCCESS) {
        yr_finalize();
        return -1;
    }

    g_active = true;
    char det[128];
    snprintf(det, sizeof(det), "{\"rules_loaded\":%d,\"mode\":\"clean\"}", rules_loaded);
    rguard_log_write(LOG_INFO, "YARA_ENGINE_READY", NULL, det);
    return 0;
}

int yara_engine_init(const char *rules_dir)
{
    if (!rules_dir) rules_dir = YARA_RULES_DIR;

    {
        char det[256];
        snprintf(det, sizeof(det), "{\"rules_dir\":\"%.200s\"}", rules_dir);
        rguard_log_write(LOG_DEBUG, "YARA_INIT_START", NULL, det);
    }

    return yara_engine_init_clean(rules_dir);
}

struct scan_ctx {
    bool matched;
    char rule_name[256];
};

static int yara_callback(YR_SCAN_CONTEXT *context, int message,
                         void *message_data, void *user_data)
{
    (void)context;
    struct scan_ctx *ctx = (struct scan_ctx *)user_data;

    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE *rule = (YR_RULE *)message_data;
        ctx->matched = true;
        if (rule->identifier) {
            snprintf(ctx->rule_name, sizeof(ctx->rule_name), "%s",
                     rule->identifier);
        }
        return CALLBACK_ABORT;  /* One match is enough */
    }
    return CALLBACK_CONTINUE;
}

int yara_scan_file(const char *path, char *matched_rule, size_t len)
{
    if (!g_active || !g_rules) return 0;
    if (!path) return -1;

    /* The path comes from the wire — verify a regular file before
     * letting libyara open it (a FIFO or hung FUSE mount would park
     * the daemon's main thread). */
    {
        int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) return -1;
        struct stat st;
        int bad = fstat(fd, &st) != 0 || !S_ISREG(st.st_mode);
        close(fd);
        if (bad) return -1;
    }

    struct scan_ctx ctx = { .matched = false, .rule_name = {0} };

    int rc = yr_rules_scan_file(g_rules, path, 0, yara_callback, &ctx, 10);
    if (rc != ERROR_SUCCESS && rc != ERROR_SCAN_TIMEOUT) {
        return -1;
    }

    if (ctx.matched && matched_rule && len > 0) {
        snprintf(matched_rule, len, "%s", ctx.rule_name);
    }

    return ctx.matched ? 1 : 0;
}

bool yara_engine_active(void)
{
    return g_active;
}

void yara_engine_destroy(void)
{
    if (g_rules) {
        yr_rules_destroy(g_rules);
        g_rules = NULL;
    }
    if (g_active) {
        yr_finalize();
        g_active = false;
    }
}

int yara_engine_reload(const char *rules_dir)
{
    rguard_log_write(LOG_INFO, "YARA_RELOAD_START", NULL, "{}");

    /* Destroy current state */
    if (g_rules) {
        yr_rules_destroy(g_rules);
        g_rules = NULL;
    }
    if (g_active) {
        yr_finalize();
        g_active = false;
    }

    /* Re-initialize from scratch */
    int rc = yara_engine_init(rules_dir);
    if (rc == 0 && g_active) {
        rguard_log_write(LOG_INFO, "YARA_RELOAD_OK", NULL, "{}");
    } else if (rc == 0) {
        rguard_log_write(LOG_WARN, "YARA_RELOAD_NORULES", NULL,
                         "{\"msg\":\"reload OK but no rules loaded\"}");
    } else {
        rguard_log_write(LOG_ERROR, "YARA_RELOAD_FAILED", NULL, "{}");
    }
    return rc;
}
