#define _POSIX_C_SOURCE 200809L
#include "rguard_log.h"
#include "rguard_protocol.h"   /* RGUARD_PATH_MAX */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <pthread.h>
#include <stdatomic.h>
#include <errno.h>

static FILE *g_fp = NULL;
static char g_component[64] = "rguard";
static _Atomic int g_level = LOG_INFO;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static const char *level_str(int lvl)
{
    switch (lvl) {
    case LOG_DEBUG: return "DEBUG";
    case LOG_INFO:  return "INFO";
    case LOG_WARN:  return "WARN";
    case LOG_ERROR: return "ERROR";
    default:        return "INFO";
    }
}

static int ensure_dir(const char *dir)
{
    struct stat st;
    if (stat(dir, &st) == 0) {
        return 0;
    }
    /* Best-effort: create just the leaf. */
    if (mkdir(dir, 0750) == 0) {
        return 0;
    }
    return errno == EEXIST ? 0 : -1;
}

int rguard_log_init(const char *log_path, const char *component, int level)
{
    if (!log_path || !*log_path) {
        return -1;
    }
    /* Derive directory from path. */
    char dirbuf[RGUARD_PATH_MAX];
    snprintf(dirbuf, sizeof(dirbuf), "%s", log_path);
    char *slash = strrchr(dirbuf, '/');
    if (slash && slash != dirbuf) {
        *slash = '\0';
        (void)ensure_dir(dirbuf);
    }

    pthread_mutex_lock(&g_lock);
    if (g_fp) {
        fclose(g_fp);
        g_fp = NULL;
    }
    g_fp = fopen(log_path, "ae");
    if (!g_fp) {
        pthread_mutex_unlock(&g_lock);
        return -1;
    }
    if (component && *component) {
        snprintf(g_component, sizeof(g_component), "%s", component);
    }
    g_level = level;
    pthread_mutex_unlock(&g_lock);
    return 0;
}

void rguard_log_set_level(int level)
{
    atomic_store(&g_level, level);
}

static void iso8601_now(char *buf, size_t n)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    /* Modulo-bound every field so GCC can prove the worst-case length
     * (31 bytes < caller's 40) — unbounded ints trip -Wformat-truncation. */
    snprintf(buf, n, "%04d-%02d-%02dT%02d:%02d:%02d.%03d",
             (tm.tm_year + 1900) % 10000, (tm.tm_mon + 1) % 100,
             tm.tm_mday % 100, tm.tm_hour % 100, tm.tm_min % 100,
             tm.tm_sec % 100, (int)(ts.tv_nsec / 1000000 % 1000));
}

/* Copy src into dst replacing \n / \r with the two-char escape \\n / \\r.
 * session_key and detail_json carry user-controlled input (client IP,
 * paths, task names) — an unescaped newline forges whole log lines. */
static void escape_line(char *dst, size_t n, const char *src)
{
    size_t o = 0;
    for (size_t i = 0; src[i] && o + 3 < n; i++) {
        if (src[i] == '\n') { dst[o++] = '\\'; dst[o++] = 'n'; }
        else if (src[i] == '\r') { dst[o++] = '\\'; dst[o++] = 'r'; }
        else dst[o++] = src[i];
    }
    dst[o] = '\0';
}

void rguard_log_write(int level, const char *event,
                      const char *session_key, const char *detail_json)
{
    if (level < atomic_load(&g_level)) {
        return;
    }
    char ts[40];
    iso8601_now(ts, sizeof(ts));

    char ev[128], skey[256], det[2048];
    escape_line(ev, sizeof(ev), (event && *event) ? event : "-");
    escape_line(skey, sizeof(skey), (session_key && *session_key) ? session_key : "-");
    escape_line(det, sizeof(det), (detail_json && *detail_json) ? detail_json : "{}");

    pthread_mutex_lock(&g_lock);
    FILE *fp = g_fp ? g_fp : stderr;
    fprintf(fp, "%s|%s|%s|%s|%s|%s\n",
            ts, level_str(level), ev, g_component, skey, det);
    fflush(fp);
    pthread_mutex_unlock(&g_lock);
}

void rguard_log_close(void)
{
    pthread_mutex_lock(&g_lock);
    if (g_fp) {
        fclose(g_fp);
        g_fp = NULL;
    }
    pthread_mutex_unlock(&g_lock);
}
