/*
 * rguard_backup.h — shared file-copy helper for backup paths.
 *
 * Copy strategy, fastest first:
 *   1. FICLONE (reflink)      — instant CoW clone; needs same filesystem
 *                               with reflink support (btrfs, XFS reflink=1)
 *   2. copy_file_range        — in-kernel copy, no userspace bounce
 *   3. read/write             — works everywhere
 *
 * Kept as static inline so the Samba VFS module and the daemon each get
 * their own copy — no link-time dependency (same pattern as rguard_hash.h).
 */
#ifndef RGUARD_BACKUP_H
#define RGUARD_BACKUP_H

#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <errno.h>

/* From <linux/fs.h>; defined locally to avoid pulling kernel headers
 * into the Samba VFS translation unit (header conflicts). */
#ifndef FICLONE
#define FICLONE _IOW(0x94, 9, int)
#endif

/* Copy src_fd (regular file, size bytes) to dst_fd from offset 0.
 * Returns 0 when the full size was copied, -1 otherwise.
 * File offsets of both fds are clobbered. */
static inline int rguard_copy_fd(int src_fd, int dst_fd, off_t size)
{
    /* 1. reflink: all-or-nothing CoW clone.  Fails with EOPNOTSUPP /
     * EXDEV / EINVAL when the fs (or fs pair) can't do it — fall through. */
    if (ioctl(dst_fd, FICLONE, src_fd) == 0)
        return 0;

    off_t total = 0;

    /* 2. copy_file_range: explicit offsets, fd positions untouched.
     * Cap each call at the remaining size — the loop must stop at
     * `size`, not at EOF (the file may have grown since the stat that
     * produced `size`, and size==0 must copy nothing). */
    {
        loff_t off_in = 0, off_out = 0;
        while (total < size) {
            size_t want = (size - total < (off_t)(1u << 20))
                          ? (size_t)(size - total) : (size_t)(1u << 20);
            ssize_t n = copy_file_range(src_fd, &off_in, dst_fd, &off_out,
                                        want, 0);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            total += n;
        }
    }

    /* 3. read/write from wherever copy_file_range stopped.  Seek BOTH
     * fds — a partial copy_file_range leaves the fd positions at 0. */
    if (total < size) {
        if (lseek(src_fd, total, SEEK_SET) == (off_t)-1) return -1;
        if (lseek(dst_fd, total, SEEK_SET) == (off_t)-1) return -1;
        char buf[64 * 1024];
        ssize_t n;
        while (total < size) {
            n = read(src_fd, buf, sizeof(buf));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            ssize_t w = 0;
            while (w < n) {
                ssize_t k = write(dst_fd, buf + w, (size_t)(n - w));
                if (k <= 0) return -1;
                w += k;
            }
            total += n;
        }
    }

    return (total >= size) ? 0 : -1;
}

#endif /* RGUARD_BACKUP_H */
