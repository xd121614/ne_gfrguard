#ifndef RGUARD_LOG_H
#define RGUARD_LOG_H

#include <stddef.h>

enum rguard_log_level {
    LOG_DEBUG = 0,
    LOG_INFO  = 1,
    LOG_WARN  = 2,
    LOG_ERROR = 3,
};

/* Escape a user-controlled string for embedding inside a JSON string
 * value in detail_json.  Handles " \ and control chars (< 0x20).
 * Without this, a crafted filename/cmdline breaks the JSON structure
 * of the whole log line. */
static inline void rguard_json_escape(char *dst, size_t n, const char *src)
{
    size_t o = 0;
    for (size_t i = 0; src[i] && o + 7 < n; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"' || c == '\\') {
            dst[o++] = '\\'; dst[o++] = (char)c;
        } else if (c < 0x20) {
            static const char hx[] = "0123456789abcdef";
            dst[o++] = '\\'; dst[o++] = 'u'; dst[o++] = '0'; dst[o++] = '0';
            dst[o++] = hx[c >> 4]; dst[o++] = hx[c & 0xf];
        } else {
            dst[o++] = (char)c;
        }
    }
    dst[o] = '\0';
}

/* Initialize the log file (append). component is a short module tag. */
int rguard_log_init(const char *log_path, const char *component, int level);

/* Write one structured log line:
 *   <ISO8601>|<LEVEL>|<EVENT>|<COMPONENT>|<session_key>|<detail_json>\n
 * session_key may be NULL/empty. detail_json should be valid JSON or "{}".
 */
void rguard_log_write(int level, const char *event,
                      const char *session_key, const char *detail_json);

void rguard_log_close(void);

void rguard_log_set_level(int level);

#endif /* RGUARD_LOG_H */
