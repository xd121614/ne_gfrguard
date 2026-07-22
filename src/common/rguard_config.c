#define _POSIX_C_SOURCE 200809L
#include "rguard_config.h"
#include "rguard_errors.h"
#include "rguard_hash.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <arpa/inet.h>

static char *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    /* A policy file is kilobytes; anything huge is garbage or an attack
     * on the malloc — refuse it instead of trusting ftell blindly. */
    if (sz < 0 || sz > 4 * 1024 * 1024) { fclose(f); errno = EFBIG; return NULL; }
    rewind(f);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[n] = '\0';
    if (out_len) *out_len = n;
    return buf;
}

static void apply_defaults(struct rguard_policy *p)
{
    memset(p, 0, sizeof(*p));
    snprintf(p->store_path, sizeof(p->store_path), "%s", "/var/lib/gf2000/rguard-store");
    snprintf(p->log_path,   sizeof(p->log_path),   "%s", "/var/log/gfrguard");
    snprintf(p->log_level,  sizeof(p->log_level),  "%s", "info");
    snprintf(p->mode,       sizeof(p->mode),       "%s", "strict");

    p->scoring.window_short = 10;
    p->scoring.window_long  = 30;
    p->scoring.cloud_window_short = 60;
    p->scoring.cloud_window_long  = 180;
    p->scoring.weights.modified   = 3;
    p->scoring.weights.rename_w   = 4;
    p->scoring.weights.delete_w   = 3;
    p->scoring.weights.dirs       = 5;
    p->scoring.weights.ext_change = 5;
    p->scoring.weights.ransom_ext   = 20;
    p->scoring.weights.high_entropy = 8;
    p->scoring.weights.yara_match   = 40;
    p->scoring.thresholds.warn     = 30;
    p->scoring.thresholds.high     = 60;
    p->scoring.thresholds.critical = 80;
    p->scoring.entropy_threshold   = 7.0;
    p->scoring.entropy_enabled     = true;
    p->scoring.yara_enabled        = true;

    p->space.max_usage_percent = 80;
    p->space.cleanup_days      = 30;

    p->auto_restore.enabled       = true;
    p->auto_restore.delay_seconds = 3;

    /* Protection switches: on by default — admin opts out if needed. */
    p->protection.enabled    = true;
    p->protection.smb        = true;
    p->protection.cloud_sync = true;
    p->protection.ftp        = true;
    p->protection.host       = true;

    /* File extension filter: protect all types by default. */
    p->file_ext.all = true;
    p->file_ext.manual_count = 0;
}

static void copy_string(char *dst, size_t dstlen, const cJSON *node)
{
    if (cJSON_IsString(node) && node->valuestring) {
        /* Silent truncation = a config entry that silently stops working. */
        if (strlen(node->valuestring) >= dstlen)
            fprintf(stderr, "config_load: string too long, truncated: %.40s...\n",
                    node->valuestring);
        snprintf(dst, dstlen, "%s", node->valuestring);
    }
}

static void copy_int(int *dst, const cJSON *node)
{
    if (cJSON_IsNumber(node)) {
        *dst = node->valueint;
    }
}

static void copy_bool(bool *dst, const cJSON *node)
{
    if (cJSON_IsBool(node)) {
        *dst = cJSON_IsTrue(node);
    }
}

static int dir_writable(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return -1;   /* must already exist */
    if (!S_ISDIR(st.st_mode)) return -1;
    return access(path, W_OK) == 0 ? 0 : -1;
}

int config_load(const char *path, struct rguard_policy *out)
{
    if (!path || !out) {
        fprintf(stderr, "config_load: bad args\n");
        return RGUARD_ERR_CONFIG;
    }
    apply_defaults(out);

    size_t len = 0;
    char *text = read_file(path, &len);
    if (!text) {
        fprintf(stderr, "config_load: cannot read %s: %s\n", path, strerror(errno));
        return RGUARD_ERR_CONFIG;
    }
    cJSON *root = cJSON_Parse(text);
    free(text);
    if (!root) {
        fprintf(stderr, "config_load: JSON parse error in %s\n", path);
        return RGUARD_ERR_CONFIG;
    }

    copy_string(out->store_path, sizeof(out->store_path), cJSON_GetObjectItem(root, "store_path"));
    copy_string(out->log_path,   sizeof(out->log_path),   cJSON_GetObjectItem(root, "log_path"));
    copy_string(out->log_level,  sizeof(out->log_level),  cJSON_GetObjectItem(root, "log_level"));
    copy_string(out->mode,       sizeof(out->mode),       cJSON_GetObjectItem(root, "mode"));
    copy_string(out->scoring_config, sizeof(out->scoring_config),
                cJSON_GetObjectItem(root, "scoring_config"));

    /* Load scoring: prefer external scoring_config file, fallback to inline "scoring" object. */
    cJSON *scoring = NULL;
    cJSON *scoring_root = NULL;  /* for standalone scoring file lifecycle */

    if (out->scoring_config[0] != '\0') {
        size_t slen = 0;
        char *stext = read_file(out->scoring_config, &slen);
        if (stext) {
            scoring_root = cJSON_Parse(stext);
            free(stext);
            if (scoring_root) {
                scoring = scoring_root;  /* top-level object IS the scoring */
            } else {
                fprintf(stderr, "config_load: JSON parse error in scoring file %s\n",
                        out->scoring_config);
            }
        } else {
            fprintf(stderr, "config_load: cannot read scoring file %s: %s\n",
                    out->scoring_config, strerror(errno));
        }
    }
    /* Fallback: inline "scoring" object in main policy file */
    if (!scoring) {
        scoring = cJSON_GetObjectItem(root, "scoring");
    }

    if (cJSON_IsObject(scoring)) {
        copy_int(&out->scoring.window_short, cJSON_GetObjectItem(scoring, "window_short"));
        copy_int(&out->scoring.window_long,  cJSON_GetObjectItem(scoring, "window_long"));

        /* Optional per-channel override: "cloud_sync": {"window_short":..,
         * "window_long":..} — cloud events are API-rate-paced. */
        cJSON *cs = cJSON_GetObjectItem(scoring, "cloud_sync");
        if (cJSON_IsObject(cs)) {
            copy_int(&out->scoring.cloud_window_short,
                     cJSON_GetObjectItem(cs, "window_short"));
            copy_int(&out->scoring.cloud_window_long,
                     cJSON_GetObjectItem(cs, "window_long"));
        }

        cJSON *w = cJSON_GetObjectItem(scoring, "weights");
        if (cJSON_IsObject(w)) {
            copy_int(&out->scoring.weights.modified,   cJSON_GetObjectItem(w, "modified"));
            copy_int(&out->scoring.weights.rename_w,   cJSON_GetObjectItem(w, "rename"));
            copy_int(&out->scoring.weights.delete_w,   cJSON_GetObjectItem(w, "delete"));
            copy_int(&out->scoring.weights.dirs,       cJSON_GetObjectItem(w, "dirs"));
            copy_int(&out->scoring.weights.ext_change, cJSON_GetObjectItem(w, "ext_change"));
            copy_int(&out->scoring.weights.ransom_ext,   cJSON_GetObjectItem(w, "ransom_ext"));
            copy_int(&out->scoring.weights.high_entropy, cJSON_GetObjectItem(w, "high_entropy"));
            copy_int(&out->scoring.weights.yara_match,   cJSON_GetObjectItem(w, "yara_match"));
        }
        cJSON *t = cJSON_GetObjectItem(scoring, "thresholds");
        if (cJSON_IsObject(t)) {
            copy_int(&out->scoring.thresholds.warn,     cJSON_GetObjectItem(t, "warn"));
            copy_int(&out->scoring.thresholds.high,     cJSON_GetObjectItem(t, "high"));
            copy_int(&out->scoring.thresholds.critical, cJSON_GetObjectItem(t, "critical"));
        }
        cJSON *et = cJSON_GetObjectItem(scoring, "entropy_threshold");
        if (cJSON_IsNumber(et)) {
            out->scoring.entropy_threshold = et->valuedouble;
        }
        cJSON *ee = cJSON_GetObjectItem(scoring, "entropy_enabled");
        if (cJSON_IsBool(ee)) {
            out->scoring.entropy_enabled = cJSON_IsTrue(ee);
        }
        cJSON *ye = cJSON_GetObjectItem(scoring, "yara_enabled");
        if (cJSON_IsBool(ye)) {
            out->scoring.yara_enabled = cJSON_IsTrue(ye);
        }
    }
    if (scoring_root) cJSON_Delete(scoring_root);

    cJSON *wl = cJSON_GetObjectItem(root, "whitelist");
    if (cJSON_IsObject(wl)) {
        cJSON *users = cJSON_GetObjectItem(wl, "users");
        cJSON *ips   = cJSON_GetObjectItem(wl, "ips");
        if (cJSON_IsArray(users)) {
            int n = cJSON_GetArraySize(users);
            int cnt = 0;
            for (int i = 0; i < n && cnt < RGUARD_WHITELIST_MAX; i++) {
                cJSON *e = cJSON_GetArrayItem(users, i);
                if (cJSON_IsString(e) && e->valuestring) {
                    snprintf(out->whitelist.users[cnt], RGUARD_USER_LEN, "%s", e->valuestring);
                    cnt++;
                }
            }
            if (n > RGUARD_WHITELIST_MAX)
                fprintf(stderr, "config_load: whitelist.user list has %d entries, max %d — extra dropped\n", (int)RGUARD_WHITELIST_MAX, n);
            out->whitelist.user_count = cnt;
        }
        if (cJSON_IsArray(ips)) {
            int n = cJSON_GetArraySize(ips);
            int cnt = 0;
            for (int i = 0; i < n && cnt < RGUARD_WHITELIST_MAX; i++) {
                cJSON *e = cJSON_GetArrayItem(ips, i);
                if (cJSON_IsString(e) && e->valuestring) {
                    snprintf(out->whitelist.ips[cnt], RGUARD_IP_LEN, "%s", e->valuestring);
                    cnt++;
                }
            }
            if (n > RGUARD_WHITELIST_MAX)
                fprintf(stderr, "config_load: whitelist.ip list has %d entries, max %d — extra dropped\n", (int)RGUARD_WHITELIST_MAX, n);
            out->whitelist.ip_count = cnt;
        }
    }

    cJSON *bl = cJSON_GetObjectItem(root, "blacklist");
    if (cJSON_IsObject(bl)) {
        cJSON *busers = cJSON_GetObjectItem(bl, "users");
        cJSON *bips   = cJSON_GetObjectItem(bl, "ips");
        if (cJSON_IsArray(busers)) {
            int n = cJSON_GetArraySize(busers);
            int cnt = 0;
            for (int i = 0; i < n && cnt < RGUARD_WHITELIST_MAX; i++) {
                cJSON *e = cJSON_GetArrayItem(busers, i);
                if (cJSON_IsString(e) && e->valuestring) {
                    snprintf(out->blacklist.users[cnt], RGUARD_USER_LEN, "%s", e->valuestring);
                    cnt++;
                }
            }
            if (n > RGUARD_WHITELIST_MAX)
                fprintf(stderr, "config_load: blacklist.user list has %d entries, max %d — extra dropped\n", (int)RGUARD_WHITELIST_MAX, n);
            out->blacklist.user_count = cnt;
        }
        if (cJSON_IsArray(bips)) {
            int n = cJSON_GetArraySize(bips);
            int cnt = 0;
            for (int i = 0; i < n && cnt < RGUARD_WHITELIST_MAX; i++) {
                cJSON *e = cJSON_GetArrayItem(bips, i);
                if (cJSON_IsString(e) && e->valuestring) {
                    /* Old format: plain string, default auto_add=false */
                    snprintf(out->blacklist.ips[cnt].ip, RGUARD_IP_LEN, "%s", e->valuestring);
                    out->blacklist.ips[cnt].auto_add = false;
                    cnt++;
                } else if (cJSON_IsObject(e)) {
                    cJSON *ipnode  = cJSON_GetObjectItem(e, "ip");
                    cJSON *autonode = cJSON_GetObjectItem(e, "auto_add");
                    if (cJSON_IsString(ipnode) && ipnode->valuestring) {
                        snprintf(out->blacklist.ips[cnt].ip, RGUARD_IP_LEN, "%s", ipnode->valuestring);
                        out->blacklist.ips[cnt].auto_add = cJSON_IsTrue(autonode);
                        cnt++;
                    }
                }
            }
            if (n > RGUARD_WHITELIST_MAX)
                fprintf(stderr, "config_load: blacklist.ip list has %d entries, max %d — extra dropped\n", (int)RGUARD_WHITELIST_MAX, n);
            out->blacklist.ip_count = cnt;
        }
    }

    cJSON *ex = cJSON_GetObjectItem(root, "exceptions");
    if (cJSON_IsObject(ex)) {
        cJSON *exfiles  = cJSON_GetObjectItem(ex, "files");
        cJSON *exfolders = cJSON_GetObjectItem(ex, "folders");
        if (cJSON_IsArray(exfiles)) {
            int n = cJSON_GetArraySize(exfiles);
            int cnt = 0;
            for (int i = 0; i < n && cnt < RGUARD_EXCEPTION_MAX; i++) {
                cJSON *e = cJSON_GetArrayItem(exfiles, i);
                if (cJSON_IsString(e) && e->valuestring) {
                    snprintf(out->exceptions.files[cnt],
                             RGUARD_EXCEPTION_PATH_LEN, "%s", e->valuestring);
                    cnt++;
                }
            }
            if (n > RGUARD_EXCEPTION_MAX)
                fprintf(stderr, "config_load: exceptions.file list has %d entries, max %d — extra dropped\n", (int)RGUARD_EXCEPTION_MAX, n);
            out->exceptions.file_count = cnt;
        }
        if (cJSON_IsArray(exfolders)) {
            int n = cJSON_GetArraySize(exfolders);
            int cnt = 0;
            for (int i = 0; i < n && cnt < RGUARD_EXCEPTION_MAX; i++) {
                cJSON *e = cJSON_GetArrayItem(exfolders, i);
                if (cJSON_IsString(e) && e->valuestring) {
                    snprintf(out->exceptions.folders[cnt],
                             RGUARD_EXCEPTION_PATH_LEN, "%s", e->valuestring);
                    cnt++;
                }
            }
            if (n > RGUARD_EXCEPTION_MAX)
                fprintf(stderr, "config_load: exceptions.folder list has %d entries, max %d — extra dropped\n", (int)RGUARD_EXCEPTION_MAX, n);
            out->exceptions.folder_count = cnt;
        }
    }

    /* Parse ransom extensions: try external config file first,
     * then fall back to inline "ransom_extensions" array. */
    {
        cJSON *rext_path = cJSON_GetObjectItem(root, "ransom_extensions_config");
        copy_string(out->ransom_extensions_config, sizeof(out->ransom_extensions_config),
                    rext_path);

        if (out->ransom_extensions_config[0] != '\0') {
            size_t rlen = 0;
            char *rtext = read_file(out->ransom_extensions_config, &rlen);
            if (rtext) {
                cJSON *rroot = cJSON_Parse(rtext);
                free(rtext);
                if (rroot) {
                    cJSON *exts = cJSON_GetObjectItem(rroot, "extensions");
                    if (cJSON_IsArray(exts)) {
                        int n2 = cJSON_GetArraySize(exts);
                        int cnt = 0;
                        for (int i = 0; i < n2 && cnt < RGUARD_RANSOM_EXT_MAX; i++) {
                            cJSON *e2 = cJSON_GetArrayItem(exts, i);
                            if (cJSON_IsString(e2) && e2->valuestring &&
                                e2->valuestring[0] != '\0') {
                                snprintf(out->ransom_exts[cnt], RGUARD_RANSOM_EXT_LEN,
                                         "%s", e2->valuestring);
                                cnt++;
                            }
                        }
                        if (n2 > RGUARD_RANSOM_EXT_MAX)
                            fprintf(stderr, "config_load: ransom_ext list has %d entries, max %d — extra dropped\n", (int)RGUARD_RANSOM_EXT_MAX, n2);
                        out->ransom_ext_count = cnt;
                    }
                    cJSON_Delete(rroot);
                }
            }
        }
        /* Fallback: inline array */
        if (out->ransom_ext_count == 0) {
            cJSON *rexts = cJSON_GetObjectItem(root, "ransom_extensions");
            if (cJSON_IsArray(rexts)) {
                int n2 = cJSON_GetArraySize(rexts);
                int cnt = 0;
                for (int i = 0; i < n2 && cnt < RGUARD_RANSOM_EXT_MAX; i++) {
                    cJSON *e2 = cJSON_GetArrayItem(rexts, i);
                    if (cJSON_IsString(e2) && e2->valuestring &&
                        e2->valuestring[0] != '\0') {
                        snprintf(out->ransom_exts[cnt], RGUARD_RANSOM_EXT_LEN,
                                 "%s", e2->valuestring);
                        cnt++;
                    }
                }
                if (n2 > RGUARD_RANSOM_EXT_MAX)
                    fprintf(stderr, "config_load: ransom_ext list has %d entries, max %d — extra dropped\n", (int)RGUARD_RANSOM_EXT_MAX, n2);
                out->ransom_ext_count = cnt;
            }
        }
    }

    cJSON *sp = cJSON_GetObjectItem(root, "space");
    if (cJSON_IsObject(sp)) {
        copy_int(&out->space.max_usage_percent, cJSON_GetObjectItem(sp, "max_usage_percent"));
        copy_int(&out->space.cleanup_days,      cJSON_GetObjectItem(sp, "cleanup_days"));
    }

    cJSON *ar = cJSON_GetObjectItem(root, "auto_restore");
    if (cJSON_IsObject(ar)) {
        copy_bool(&out->auto_restore.enabled,       cJSON_GetObjectItem(ar, "enabled"));
        copy_int (&out->auto_restore.delay_seconds, cJSON_GetObjectItem(ar, "delay_seconds"));
    }

    cJSON *prot = cJSON_GetObjectItem(root, "protection");
    if (cJSON_IsObject(prot)) {
        copy_bool(&out->protection.enabled,    cJSON_GetObjectItem(prot, "enabled"));
        copy_bool(&out->protection.smb,        cJSON_GetObjectItem(prot, "smb"));
        copy_bool(&out->protection.cloud_sync, cJSON_GetObjectItem(prot, "cloud_sync"));
        copy_bool(&out->protection.ftp,        cJSON_GetObjectItem(prot, "ftp"));
        copy_bool(&out->protection.host,       cJSON_GetObjectItem(prot, "host"));
    }

    cJSON *fe = cJSON_GetObjectItem(root, "file_extensions");
    if (cJSON_IsObject(fe)) {
        copy_bool(&out->file_ext.all, cJSON_GetObjectItem(fe, "all"));
        cJSON *man = cJSON_GetObjectItem(fe, "manual");
        if (cJSON_IsArray(man)) {
            int n = cJSON_GetArraySize(man);
            int cnt = 0;
            for (int i = 0; i < n && cnt < RGUARD_PROTECT_EXT_MAX; i++) {
                cJSON *e = cJSON_GetArrayItem(man, i);
                if (cJSON_IsString(e) && e->valuestring && e->valuestring[0] != '\0') {
                    snprintf(out->file_ext.manual[cnt], RGUARD_PROTECT_EXT_LEN,
                             "%s", e->valuestring);
                    cnt++;
                }
            }
            if (n > RGUARD_PROTECT_EXT_MAX)
                fprintf(stderr, "config_load: file_ext.manual list has %d entries, max %d — extra dropped\n", (int)RGUARD_PROTECT_EXT_MAX, n);
            out->file_ext.manual_count = cnt;
        }
    }

    /* Build O(1) hash set from manual[] for fast lookup. */
    if (!out->file_ext.all && out->file_ext.manual_count > 0) {
        memset(out->file_ext.manual_hashes, 0, sizeof(out->file_ext.manual_hashes));
        for (int i = 0; i < out->file_ext.manual_count; i++) {
            uint64_t h = rguard_fnv1a64(out->file_ext.manual[i],
                                        strlen(out->file_ext.manual[i]));
            if (h == 0) h = 1;  /* 0 = empty sentinel */
            size_t idx = h % RGUARD_PROTECT_EXT_HSIZE;
            while (out->file_ext.manual_hashes[idx] != 0) {
                if (out->file_ext.manual_hashes[idx] == h) break;  /* dup */
                idx = (idx + 1) % RGUARD_PROTECT_EXT_HSIZE;
            }
            out->file_ext.manual_hashes[idx] = h;
        }
    }

    /* ── monitor_path: { ftp:[], cloud_sync:[], local:[] } ──────────── */
    {
        cJSON *mp_root = cJSON_GetObjectItem(root, "monitor_path");
        if (cJSON_IsObject(mp_root)) {
            const char *keys[] = {"ftp", "cloud_sync", "local"};
            struct rguard_path_config *cfgs[] = {&out->ftp_paths, &out->cloud_paths, &out->local_paths};
            for (int s = 0; s < 3; s++) {
                cJSON *arr = cJSON_GetObjectItem(mp_root, keys[s]);
                if (!cJSON_IsArray(arr)) continue;
                int n = cJSON_GetArraySize(arr), cnt = 0;
                for (int i = 0; i < n && cnt < RGUARD_MONITOR_MAX; i++) {
                    cJSON *e = cJSON_GetArrayItem(arr, i);
                    if (cJSON_IsString(e) && e->valuestring)
                        snprintf(cfgs[s]->monitor_path[cnt++], RGUARD_MONITOR_PATH_LEN, "%s", e->valuestring);
                }
                if (n > RGUARD_MONITOR_MAX)
                    fprintf(stderr, "config_load: monitor_path.%s has %d entries, max %d — extra dropped\n",
                            keys[s], n, (int)RGUARD_MONITOR_MAX);
                cfgs[s]->monitor_count = cnt;
            }
        }
    }

    cJSON_Delete(root);

    /* --- Pre-compute FNV-1a hashes for all exact-match lists, then sort
     *     by hash so the daemon can use binary search at lookup time. --- */
    for (int i = 0; i < out->exceptions.file_count; i++)
        out->exceptions.file_hashes[i] =
            rguard_fnv1a64(out->exceptions.files[i],
                           strlen(out->exceptions.files[i]));
    SORT_BY_HASH(out->exceptions.file_hashes, out->exceptions.files,
                 out->exceptions.file_count, sizeof(out->exceptions.files[0]));

    for (int i = 0; i < out->exceptions.folder_count; i++)
        out->exceptions.folder_hashes[i] =
            rguard_fnv1a64(out->exceptions.folders[i],
                           strlen(out->exceptions.folders[i]));
    SORT_BY_HASH(out->exceptions.folder_hashes, out->exceptions.folders,
                 out->exceptions.folder_count, sizeof(out->exceptions.folders[0]));

    for (int i = 0; i < out->whitelist.user_count; i++)
        out->whitelist.user_hashes[i] =
            rguard_fnv1a64(out->whitelist.users[i],
                           strlen(out->whitelist.users[i]));
    SORT_BY_HASH(out->whitelist.user_hashes, out->whitelist.users,
                 out->whitelist.user_count, sizeof(out->whitelist.users[0]));

    for (int i = 0; i < out->whitelist.ip_count; i++)
        out->whitelist.ip_hashes[i] =
            rguard_fnv1a64(out->whitelist.ips[i],
                           strlen(out->whitelist.ips[i]));
    SORT_BY_HASH(out->whitelist.ip_hashes, out->whitelist.ips,
                 out->whitelist.ip_count, sizeof(out->whitelist.ips[0]));

    for (int i = 0; i < out->blacklist.user_count; i++)
        out->blacklist.user_hashes[i] =
            rguard_fnv1a64(out->blacklist.users[i],
                           strlen(out->blacklist.users[i]));
    SORT_BY_HASH(out->blacklist.user_hashes, out->blacklist.users,
                 out->blacklist.user_count, sizeof(out->blacklist.users[0]));

    for (int i = 0; i < out->blacklist.ip_count; i++)
        out->blacklist.ip_hashes[i] =
            rguard_fnv1a64(out->blacklist.ips[i].ip,
                           strlen(out->blacklist.ips[i].ip));
    SORT_BY_HASH(out->blacklist.ip_hashes, out->blacklist.ips,
                 out->blacklist.ip_count, sizeof(out->blacklist.ips[0]));

    /* Validation. */
    if (dir_writable(out->store_path) != 0) {
        fprintf(stderr, "config_load: store_path %s is not a writable directory\n", out->store_path);
        return RGUARD_ERR_CONFIG;
    }
    /* log_path's parent directory: tolerate missing leaf, just check parent. */
    if (out->log_path[0]) {
        struct stat st;
        if (stat(out->log_path, &st) != 0) {
            /* allow if we can mkdir later; do a soft check on parent */
            char tmp[RGUARD_LOGPATH_LEN];
            snprintf(tmp, sizeof(tmp), "%s", out->log_path);
            char *slash = strrchr(tmp, '/');
            if (slash && slash != tmp) {
                *slash = '\0';
                if (dir_writable(tmp) != 0) {
                    fprintf(stderr, "config_load: log_path parent %s not writable\n", tmp);
                    return RGUARD_ERR_CONFIG;
                }
            }
        } else if (!S_ISDIR(st.st_mode) || access(out->log_path, W_OK) != 0) {
            fprintf(stderr, "config_load: log_path %s not writable directory\n", out->log_path);
            return RGUARD_ERR_CONFIG;
        }
    }

    int w = out->scoring.thresholds.warn;
    int h = out->scoring.thresholds.high;
    int c = out->scoring.thresholds.critical;
    if (!(w >= 1 && w < h && h < c && c <= 100)) {
        fprintf(stderr, "config_load: thresholds invalid (warn=%d high=%d critical=%d)\n", w, h, c);
        return RGUARD_ERR_CONFIG;
    }

    if (strcmp(out->mode, "strict") != 0 && strcmp(out->mode, "permissive") != 0) {
        fprintf(stderr, "config_load: mode must be strict|permissive (got %s)\n", out->mode);
        return RGUARD_ERR_CONFIG;
    }

    /* Numeric range validation (H13/M23) — garbage numbers are not
     * "admin's choice", they silently break scoring and cleanup:
     *   weight < 0            → events SUBTRACT score (protection bypass)
     *   window <= 0           → counters never reset / gate divides by it
     *   entropy < 0 or > 8    → everything or nothing flagged high-entropy
     *   percent <= 0 or > 100 → space check never/always fires
     *   cleanup_days <= 0     → cleanup deletes everything or nothing
     *   delay_seconds < 0     → cast to unsigned sleeps for centuries */
    const struct rguard_weights *wt = &out->scoring.weights;
    if (wt->modified < 0 || wt->rename_w < 0 || wt->delete_w < 0 ||
        wt->dirs < 0 || wt->ext_change < 0 || wt->ransom_ext < 0 ||
        wt->high_entropy < 0 || wt->yara_match < 0) {
        fprintf(stderr, "config_load: scoring weights must be >= 0\n");
        return RGUARD_ERR_CONFIG;
    }
    if (out->scoring.window_short <= 0 || out->scoring.window_long <= 0 ||
        out->scoring.cloud_window_short <= 0 || out->scoring.cloud_window_long <= 0) {
        fprintf(stderr, "config_load: scoring windows must be > 0\n");
        return RGUARD_ERR_CONFIG;
    }
    if (out->scoring.entropy_threshold < 0.0 || out->scoring.entropy_threshold > 8.0) {
        fprintf(stderr, "config_load: entropy_threshold must be in [0,8] (got %.2f)\n",
                out->scoring.entropy_threshold);
        return RGUARD_ERR_CONFIG;
    }
    if (out->space.max_usage_percent <= 0 || out->space.max_usage_percent > 100) {
        fprintf(stderr, "config_load: space.max_usage_percent must be in (0,100] (got %d)\n",
                out->space.max_usage_percent);
        return RGUARD_ERR_CONFIG;
    }
    if (out->space.cleanup_days <= 0) {
        fprintf(stderr, "config_load: space.cleanup_days must be > 0 (got %d)\n",
                out->space.cleanup_days);
        return RGUARD_ERR_CONFIG;
    }
    if (out->auto_restore.delay_seconds < 0) {
        fprintf(stderr, "config_load: auto_restore.delay_seconds must be >= 0 (got %d)\n",
                out->auto_restore.delay_seconds);
        return RGUARD_ERR_CONFIG;
    }

    return RGUARD_OK;
}

/* Persist a runtime auto-blacklisted IP into the policy JSON, appended to
 * blacklist.ips in OBJECT form {"ip": ..., "auto_add": true} — the flag
 * lets the frontend distinguish daemon verdicts from admin entries (both
 * removable), and config_load carries it into rguard_bl_ip.auto_add on the
 * next load.  Blocking semantics are unaffected either way.
 *
 * The inet_pton gate mirrors scorer_blacklist_auto_add: channels without a
 * real client (cloud task name, "local:<pid>", ftp "unknown") have nothing
 * to persist — return OK silently, it is not an error.
 *
 * Best-effort: the in-memory auto list stays authoritative for this
 * process; a failed persist only loses durability across restart.
 *
 * Persisted auto entries are capped at RGUARD_BLACKLIST_AUTO_MAX, same as
 * the in-memory list: appends land at the tail, so when the cap is hit the
 * FIRST auto entry in array order (the oldest) is evicted.  Manual entries
 * (string form or auto_add:false) are never evicted. */
int config_persist_blacklist_ip(const char *config_path, const char *ip)
{
    if (!config_path || !ip || !*ip) return RGUARD_ERR_CONFIG;

    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, ip, &a4) != 1 &&
        inet_pton(AF_INET6, ip, &a6) != 1)
        return RGUARD_OK;   /* not a real IP — nothing to persist */

    size_t len = 0;
    char *text = read_file(config_path, &len);
    if (!text) return RGUARD_ERR_CONFIG;
    cJSON *root = cJSON_Parse(text);
    free(text);
    if (!root) return RGUARD_ERR_CONFIG;

    cJSON *bl = cJSON_GetObjectItem(root, "blacklist");
    if (!cJSON_IsObject(bl)) {
        if (bl) cJSON_DeleteItemFromObject(root, "blacklist");
        bl = cJSON_AddObjectToObject(root, "blacklist");
    }
    cJSON *ips = bl ? cJSON_GetObjectItem(bl, "ips") : NULL;
    if (bl && !cJSON_IsArray(ips)) {
        if (ips) cJSON_DeleteItemFromObject(bl, "ips");
        ips = cJSON_AddArrayToObject(bl, "ips");
    }
    if (!bl || !ips) { cJSON_Delete(root); return RGUARD_ERR_CONFIG; }

    /* One pass: dedup (any form, manual or auto → skip) and locate the
     * oldest auto entry for the FIFO cap. */
    cJSON *e;
    int idx = 0, auto_count = 0, first_auto_idx = -1;
    cJSON_ArrayForEach(e, ips) {
        const char *s = NULL;
        bool is_auto = false;
        if (cJSON_IsString(e)) {
            s = e->valuestring;
        } else if (cJSON_IsObject(e)) {
            cJSON *n = cJSON_GetObjectItem(e, "ip");
            if (cJSON_IsString(n)) s = n->valuestring;
            is_auto = cJSON_IsTrue(cJSON_GetObjectItem(e, "auto_add"));
        }
        if (s && strcmp(s, ip) == 0) {
            cJSON_Delete(root);
            return RGUARD_OK;
        }
        if (is_auto) {
            if (first_auto_idx < 0) first_auto_idx = idx;
            auto_count++;
        }
        idx++;
    }

    /* FIFO cap on persisted auto entries: appends always land at the
     * tail, so the first auto entry in array order is the oldest.
     * Manual entries are never evicted. */
    if (auto_count >= RGUARD_BLACKLIST_AUTO_MAX && first_auto_idx >= 0)
        cJSON_DeleteItemFromArray(ips, first_auto_idx);

    cJSON *entry = cJSON_CreateObject();
    if (!entry) { cJSON_Delete(root); return RGUARD_ERR_CONFIG; }
    cJSON_AddStringToObject(entry, "ip", ip);
    cJSON_AddBoolToObject(entry, "auto_add", 1);
    cJSON_AddItemToArray(ips, entry);

    char *out = cJSON_Print(root);
    cJSON_Delete(root);
    if (!out) return RGUARD_ERR_CONFIG;

    /* Atomic replace (tmp + fsync + rename): readers never see a torn
     * file, even with the middleware writing the same path. */
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", config_path);
    FILE *f = fopen(tmp, "w");
    if (!f) { free(out); return RGUARD_ERR_CONFIG; }
    int rc = RGUARD_OK;
    if (fputs(out, f) == EOF || fputc('\n', f) == EOF ||
        fflush(f) != 0 || fsync(fileno(f)) != 0)
        rc = RGUARD_ERR_CONFIG;
    if (fclose(f) != 0) rc = RGUARD_ERR_CONFIG;
    free(out);
    if (rc == RGUARD_OK && rename(tmp, config_path) != 0)
        rc = RGUARD_ERR_CONFIG;
    if (rc != RGUARD_OK) unlink(tmp);
    return rc;
}

void config_free(struct rguard_policy *p)
{
    (void)p;
}
