#ifndef GFRGUARDD_ENTROPY_H
#define GFRGUARDD_ENTROPY_H

#include <stdbool.h>
#include <stddef.h>

/* Compute Shannon entropy of first sample_bytes of a file.
 * Returns entropy in bits/byte (0.0 - 8.0).
 * Returns -1.0 on error (file not readable, etc.). */
double entropy_compute_file(const char *path, size_t sample_bytes);

/* Check if entropy exceeds the ransomware threshold (default 7.0).
 * Encrypted/compressed data is typically >7.0 bits/byte. */
bool entropy_is_suspicious(double entropy, double threshold);

#define ENTROPY_DEFAULT_THRESHOLD  7.0
#define ENTROPY_SAMPLE_SIZE        8192  /* first 8KB */

#endif /* GFRGUARDD_ENTROPY_H */
