#define _POSIX_C_SOURCE 200809L
#include "gfrguardd_entropy.h"

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

double entropy_compute_file(const char *path, size_t sample_bytes)
{
    if (!path || sample_bytes == 0) return -1.0;

    /* The path comes from the wire — O_NONBLOCK so a FIFO or hung FUSE
     * mount can never park the daemon, and only regular files count. */
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return -1.0;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return -1.0;
    }

    unsigned char buf[8192];
    size_t total_read = 0;
    unsigned long freq[256];
    memset(freq, 0, sizeof(freq));

    while (total_read < sample_bytes) {
        size_t to_read = sizeof(buf);
        if (to_read > sample_bytes - total_read)
            to_read = sample_bytes - total_read;
        ssize_t n = read(fd, buf, to_read);
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) {
            freq[buf[i]]++;
        }
        total_read += (size_t)n;
    }
    close(fd);

    if (total_read == 0) return 0.0;

    double entropy = 0.0;
    double total = (double)total_read;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / total;
        entropy -= p * log2(p);
    }
    return entropy;
}

bool entropy_is_suspicious(double entropy, double threshold)
{
    if (entropy < 0.0) return false;  /* error reading file */
    return entropy >= threshold;
}
