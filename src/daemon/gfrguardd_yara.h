#ifndef GFRGUARDD_YARA_H
#define GFRGUARDD_YARA_H

#include <stdbool.h>
#include <stddef.h>

#define YARA_RULES_DIR "/etc/gf2000/yara-rules"

/* Initialize YARA engine and load all .yar/.yara files from rules_dir.
 * Returns 0 on success, -1 on failure.
 * If libyara is not available or no rules found, returns 0 (no-op mode). */
int yara_engine_init(const char *rules_dir);

/* Scan a file against loaded YARA rules.
 * Returns:
 *   1  = at least one rule matched (ransomware detected)
 *   0  = no match
 *  -1  = error (file not readable, engine not initialized, etc.)
 * If matched_rule is non-NULL, first matching rule name is copied (up to len). */
int yara_scan_file(const char *path, char *matched_rule, size_t len);

/* Check if YARA engine is active (rules loaded successfully). */
bool yara_engine_active(void);

/* Reload YARA rules from disk (hot-reload).
 * Destroys current rules and re-compiles from rules_dir.
 * Returns 0 on success, -1 on failure (old rules remain destroyed). */
int yara_engine_reload(const char *rules_dir);

/* Cleanup YARA engine resources. */
void yara_engine_destroy(void);

#endif /* GFRGUARDD_YARA_H */
