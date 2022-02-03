/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Missing glibc definitions to access certain kernel APIs */

#include <errno.h>
#include <fcntl.h>
#if HAVE_LINUX_TIME_TYPES_H
/* This header defines __kernel_timespec for us, but is only available since Linux 5.1, hence conditionally
 * include this. */
#include <linux/time_types.h>
#endif
#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef ARCH_MIPS
#include <asm/sgidefs.h>
#endif

#include "macro.h"
#include "missing_keyctl.h"
#include "missing_stat.h"
#include "missing_syscall_def.h"

#if 0 /* NM_IGNORED */

/* linux/kcmp.h */
#ifndef KCMP_FILE /* 3f4994cfc15f38a3159c6e3a4b3ab2e1481a6b02 (3.19) */
#define KCMP_FILE 0
#endif

/* ======================================================================= */

#if !HAVE_PIVOT_ROOT
static inline int missing_pivot_root(const char *new_root, const char *put_old) {
        return syscall(__NR_pivot_root, new_root, put_old);
}

#  define pivot_root missing_pivot_root
#endif

/* ======================================================================= */

#if !HAVE_IOPRIO_GET
static inline int missing_ioprio_get(int which, int who) {
        return syscall(__NR_ioprio_get, which, who);
}

#  define ioprio_get missing_ioprio_get
#endif

/* ======================================================================= */

#if !HAVE_IOPRIO_SET
static inline int missing_ioprio_set(int which, int who, int ioprio) {
        return syscall(__NR_ioprio_set, which, who, ioprio);
}

#  define ioprio_set missing_ioprio_set
#endif

/* ======================================================================= */

#if !HAVE_MEMFD_CREATE
static inline int missing_memfd_create(const char *name, unsigned int flags) {
#  ifdef __NR_memfd_create
        return syscall(__NR_memfd_create, name, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define memfd_create missing_memfd_create
#endif

/* ======================================================================= */

#if !HAVE_GETRANDOM
/* glibc says getrandom() returns ssize_t */
static inline ssize_t missing_getrandom(void *buffer, size_t count, unsigned flags) {
#  ifdef __NR_getrandom
        return syscall(__NR_getrandom, buffer, count, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define getrandom missing_getrandom
#endif

/* ======================================================================= */

/* The syscall has been defined since forever, but the glibc wrapper was missing. */
#if !HAVE_GETTID
static inline pid_t missing_gettid(void) {
#  if defined __NR_gettid && __NR_gettid >= 0
        return (pid_t) syscall(__NR_gettid);
#  else
#    error "__NR_gettid not defined"
#  endif
}

#  define gettid missing_gettid
#endif

/* ======================================================================= */

#if !HAVE_NAME_TO_HANDLE_AT
struct file_handle {
        unsigned int handle_bytes;
        int handle_type;
        unsigned char f_handle[0];
};

static inline int missing_name_to_handle_at(int fd, const char *name, struct file_handle *handle, int *mnt_id, int flags) {
#  ifdef __NR_name_to_handle_at
        return syscall(__NR_name_to_handle_at, fd, name, handle, mnt_id, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define name_to_handle_at missing_name_to_handle_at
#endif

/* ======================================================================= */

#if !HAVE_SETNS
static inline int missing_setns(int fd, int nstype) {
#  ifdef __NR_setns
        return syscall(__NR_setns, fd, nstype);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define setns missing_setns
#endif

/* ======================================================================= */

static inline pid_t raw_getpid(void) {
#if defined(__alpha__)
        return (pid_t) syscall(__NR_getxpid);
#else
        return (pid_t) syscall(__NR_getpid);
#endif
}

/* ======================================================================= */

#if !HAVE_RENAMEAT2
static inline int missing_renameat2(int oldfd, const char *oldname, int newfd, const char *newname, unsigned flags) {
#  ifdef __NR_renameat2
        return syscall(__NR_renameat2, oldfd, oldname, newfd, newname, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define renameat2 missing_renameat2
#endif

/* ======================================================================= */

#if !HAVE_KCMP
static inline int missing_kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2) {
#  if defined __NR_kcmp && __NR_kcmp >= 0
        return syscall(__NR_kcmp, pid1, pid2, type, idx1, idx2);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define kcmp missing_kcmp
#endif

/* ======================================================================= */

#if !HAVE_KEYCTL
static inline long missing_keyctl(int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
#  if defined __NR_keyctl && __NR_keyctl >= 0
        return syscall(__NR_keyctl, cmd, arg2, arg3, arg4, arg5);
#  else
        errno = ENOSYS;
        return -1;
#  endif

#  define keyctl missing_keyctl
}

static inline key_serial_t missing_add_key(const char *type, const char *description, const void *payload, size_t plen, key_serial_t ringid) {
#  if defined __NR_add_key && __NR_add_key >= 0
        return syscall(__NR_add_key, type, description, payload, plen, ringid);
#  else
        errno = ENOSYS;
        return -1;
#  endif

#  define add_key missing_add_key
}

static inline key_serial_t missing_request_key(const char *type, const char *description, const char * callout_info, key_serial_t destringid) {
#  if defined __NR_request_key && __NR_request_key >= 0
        return syscall(__NR_request_key, type, description, callout_info, destringid);
#  else
        errno = ENOSYS;
        return -1;
#  endif

#  define request_key missing_request_key
}
#endif

/* ======================================================================= */

#if !HAVE_COPY_FILE_RANGE
static inline ssize_t missing_copy_file_range(int fd_in, loff_t *off_in,
                                              int fd_out, loff_t *off_out,
                                              size_t len,
                                              unsigned int flags) {
#  ifdef __NR_copy_file_range
        return syscall(__NR_copy_file_range, fd_in, off_in, fd_out, off_out, len, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define copy_file_range missing_copy_file_range
#endif

/* ======================================================================= */

#if !HAVE_BPF
union bpf_attr;

static inline int missing_bpf(int cmd, union bpf_attr *attr, size_t size) {
#ifdef __NR_bpf
        return (int) syscall(__NR_bpf, cmd, attr, size);
#else
        errno = ENOSYS;
        return -1;
#endif
}

#  define bpf missing_bpf
#endif

/* ======================================================================= */

#if !HAVE_STATX
struct statx;

static inline ssize_t missing_statx(int dfd, const char *filename, unsigned flags, unsigned int mask, struct statx *buffer) {
#  ifdef __NR_statx
        return syscall(__NR_statx, dfd, filename, flags, mask, buffer);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}
#endif

/* This typedef is supposed to be always defined. */
typedef struct statx struct_statx;

#if !HAVE_STATX
#  define statx(dfd, filename, flags, mask, buffer) missing_statx(dfd, filename, flags, mask, buffer)
#endif

/* ======================================================================= */

#if !HAVE_SET_MEMPOLICY
enum {
        MPOL_DEFAULT,
        MPOL_PREFERRED,
        MPOL_BIND,
        MPOL_INTERLEAVE,
        MPOL_LOCAL,
};

static inline long missing_set_mempolicy(int mode, const unsigned long *nodemask,
                           unsigned long maxnode) {
        long i;
#  if defined __NR_set_mempolicy && __NR_set_mempolicy >= 0
        i = syscall(__NR_set_mempolicy, mode, nodemask, maxnode);
#  else
        errno = ENOSYS;
        i = -1;
#  endif
        return i;
}

#  define set_mempolicy missing_set_mempolicy
#endif

#if !HAVE_GET_MEMPOLICY
static inline long missing_get_mempolicy(int *mode, unsigned long *nodemask,
                           unsigned long maxnode, void *addr,
                           unsigned long flags) {
        long i;
#  if defined __NR_get_mempolicy && __NR_get_mempolicy >= 0
        i = syscall(__NR_get_mempolicy, mode, nodemask, maxnode, addr, flags);
#  else
        errno = ENOSYS;
        i = -1;
#  endif
        return i;
}

#  define get_mempolicy missing_get_mempolicy
#endif

#endif /* NM_IGNORED */

/* ======================================================================= */

#if !HAVE_PIDFD_SEND_SIGNAL
static inline int missing_pidfd_send_signal(int fd, int sig, siginfo_t *info, unsigned flags) {
#  ifdef __NR_pidfd_send_signal
        return syscall(__NR_pidfd_send_signal, fd, sig, info, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define pidfd_send_signal missing_pidfd_send_signal
#endif

#if !HAVE_PIDFD_OPEN
static inline int missing_pidfd_open(pid_t pid, unsigned flags) {
#  ifdef __NR_pidfd_open
        return syscall(__NR_pidfd_open, pid, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define pidfd_open missing_pidfd_open
#endif

/* ======================================================================= */

#if !HAVE_RT_SIGQUEUEINFO
static inline int missing_rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *info) {
#  if defined __NR_rt_sigqueueinfo && __NR_rt_sigqueueinfo >= 0
        return syscall(__NR_rt_sigqueueinfo, tgid, sig, info);
#  else
#    error "__NR_rt_sigqueueinfo not defined"
#  endif
}

#  define rt_sigqueueinfo missing_rt_sigqueueinfo
#endif

/* ======================================================================= */

#if 0 /* NM_IGNORED */
#if !HAVE_EXECVEAT
static inline int missing_execveat(int dirfd, const char *pathname,
                                   char *const argv[], char *const envp[],
                                   int flags) {
#  if defined __NR_execveat && __NR_execveat >= 0
        return syscall(__NR_execveat, dirfd, pathname, argv, envp, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  undef AT_EMPTY_PATH
#  define AT_EMPTY_PATH 0x1000
#  define execveat missing_execveat
#endif

/* ======================================================================= */

#if !HAVE_CLOSE_RANGE
static inline int missing_close_range(int first_fd, int end_fd, unsigned flags) {
#  ifdef __NR_close_range
        /* Kernel-side the syscall expects fds as unsigned integers (just like close() actually), while
         * userspace exclusively uses signed integers for fds. We don't know just yet how glibc is going to
         * wrap this syscall, but let's assume it's going to be similar to what they do for close(),
         * i.e. make the same unsigned → signed type change from the raw kernel syscall compared to the
         * userspace wrapper. There's only one caveat for this: unlike for close() there's the special
         * UINT_MAX fd value for the 'end_fd' argument. Let's safely map that to -1 here. And let's refuse
         * any other negative values. */
        if ((first_fd < 0) || (end_fd < 0 && end_fd != -1)) {
                errno = -EBADF;
                return -1;
        }

        return syscall(__NR_close_range,
                       (unsigned) first_fd,
                       end_fd == -1 ? UINT_MAX : (unsigned) end_fd, /* Of course, the compiler should figure out that this is the identity mapping IRL */
                       flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define close_range missing_close_range
#endif

/* ======================================================================= */

#if !HAVE_EPOLL_PWAIT2

/* Defined to be equivalent to the kernel's _NSIG_WORDS, i.e. the size of the array of longs that is
 * encapsulated by sigset_t. */
#define KERNEL_NSIG_WORDS (64 / (sizeof(long) * 8))
#define KERNEL_NSIG_BYTES (KERNEL_NSIG_WORDS * sizeof(long))

struct epoll_event;

static inline int missing_epoll_pwait2(
                int fd,
                struct epoll_event *events,
                int maxevents,
                const struct timespec *timeout,
                const sigset_t *sigset) {

#  if defined(__NR_epoll_pwait2) && HAVE_LINUX_TIME_TYPES_H
        if (timeout) {
                /* Convert from userspace timespec to kernel timespec */
                struct __kernel_timespec ts = {
                        .tv_sec = timeout->tv_sec,
                        .tv_nsec = timeout->tv_nsec,
                };

                return syscall(__NR_epoll_pwait2, fd, events, maxevents, &ts, sigset, sigset ? KERNEL_NSIG_BYTES : 0);
        } else
                return syscall(__NR_epoll_pwait2, fd, events, maxevents, NULL, sigset, sigset ? KERNEL_NSIG_BYTES : 0);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define epoll_pwait2 missing_epoll_pwait2
#endif

/* ======================================================================= */

#if !HAVE_MOUNT_SETATTR

#if !HAVE_STRUCT_MOUNT_ATTR
struct mount_attr {
        uint64_t attr_set;
        uint64_t attr_clr;
        uint64_t propagation;
        uint64_t userns_fd;
};
#else
struct mount_attr;
#endif

#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY       0x00000001 /* Mount read-only */
#endif

#ifndef MOUNT_ATTR_NOSUID
#define MOUNT_ATTR_NOSUID       0x00000002 /* Ignore suid and sgid bits */
#endif

#ifndef MOUNT_ATTR_NODEV
#define MOUNT_ATTR_NODEV        0x00000004 /* Disallow access to device special files */
#endif

#ifndef MOUNT_ATTR_NOEXEC
#define MOUNT_ATTR_NOEXEC       0x00000008 /* Disallow program execution */
#endif

#ifndef MOUNT_ATTR__ATIME
#define MOUNT_ATTR__ATIME       0x00000070 /* Setting on how atime should be updated */
#endif

#ifndef MOUNT_ATTR_RELATIME
#define MOUNT_ATTR_RELATIME     0x00000000 /* - Update atime relative to mtime/ctime. */
#endif

#ifndef MOUNT_ATTR_NOATIME
#define MOUNT_ATTR_NOATIME      0x00000010 /* - Do not update access times. */
#endif

#ifndef MOUNT_ATTR_STRICTATIME
#define MOUNT_ATTR_STRICTATIME  0x00000020 /* - Always perform atime updates */
#endif

#ifndef MOUNT_ATTR_NODIRATIME
#define MOUNT_ATTR_NODIRATIME   0x00000080 /* Do not update directory access times */
#endif

#ifndef MOUNT_ATTR_IDMAP
#define MOUNT_ATTR_IDMAP        0x00100000 /* Idmap mount to @userns_fd in struct mount_attr. */
#endif

#ifndef MOUNT_ATTR_NOSYMFOLLOW
#define MOUNT_ATTR_NOSYMFOLLOW  0x00200000 /* Do not follow symlinks */
#endif

#ifndef MOUNT_ATTR_SIZE_VER0
#define MOUNT_ATTR_SIZE_VER0    32 /* sizeof first published struct */
#endif

#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif

static inline int missing_mount_setattr(
                int dfd,
                const char *path,
                unsigned flags,
                struct mount_attr *attr,
                size_t size) {

#  if defined __NR_mount_setattr && __NR_mount_setattr >= 0
        return syscall(__NR_mount_setattr, dfd, path, flags, attr, size);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define mount_setattr missing_mount_setattr
#endif

/* ======================================================================= */

#if !HAVE_OPEN_TREE

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#endif

#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif

static inline int missing_open_tree(
                int dfd,
                const char *filename,
                unsigned flags) {

#  if defined __NR_open_tree && __NR_open_tree >= 0
        return syscall(__NR_open_tree, dfd, filename, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define open_tree missing_open_tree
#endif

/* ======================================================================= */

#if !HAVE_MOVE_MOUNT

#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004 /* Empty from path permitted */
#endif

static inline int missing_move_mount(
                int from_dfd,
                const char *from_pathname,
                int to_dfd,
                const char *to_pathname,
                unsigned flags) {

#  if defined __NR_move_mount && __NR_move_mount >= 0
        return syscall(__NR_move_mount, from_dfd, from_pathname, to_dfd, to_pathname, flags);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define move_mount missing_move_mount
#endif

/* ======================================================================= */

#if !HAVE_GETDENTS64

static inline ssize_t missing_getdents64(int fd, void *buffer, size_t length) {
#  if defined __NR_getdents64 && __NR_getdents64 >= 0
        return syscall(__NR_getdents64, fd, buffer, length);
#  else
        errno = ENOSYS;
        return -1;
#  endif
}

#  define getdents64 missing_getdents64
#endif
#endif /* NM_IGNORED */
