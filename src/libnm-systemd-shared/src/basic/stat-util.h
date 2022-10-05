/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/vfs.h>

#include "macro.h"
#include "missing_stat.h"

int is_symlink(const char *path);
int is_dir_full(int atfd, const char *fname, bool follow);
static inline int is_dir(const char *path, bool follow) {
        return is_dir_full(AT_FDCWD, path, follow);
}
static inline int is_dir_fd(int fd) {
        return is_dir_full(fd, NULL, false);
}
int is_device_node(const char *path);

int dir_is_empty_at(int dir_fd, const char *path, bool ignore_hidden_or_backup);
static inline int dir_is_empty(const char *path, bool ignore_hidden_or_backup) {
        return dir_is_empty_at(AT_FDCWD, path, ignore_hidden_or_backup);
}

bool null_or_empty(struct stat *st) _pure_;
int null_or_empty_path_with_root(const char *fn, const char *root);
int null_or_empty_fd(int fd);

static inline int null_or_empty_path(const char *fn) {
        return null_or_empty_path_with_root(fn, NULL);
}

int path_is_read_only_fs(const char *path);

int files_same(const char *filea, const char *fileb, int flags);

/* The .f_type field of struct statfs is really weird defined on
 * different archs. Let's give its type a name. */
typedef typeof(((struct statfs*)NULL)->f_type) statfs_f_type_t;

bool is_fs_type(const struct statfs *s, statfs_f_type_t magic_value) _pure_;
int fd_is_fs_type(int fd, statfs_f_type_t magic_value);
int path_is_fs_type(const char *path, statfs_f_type_t magic_value);

bool is_temporary_fs(const struct statfs *s) _pure_;
bool is_network_fs(const struct statfs *s) _pure_;

int fd_is_temporary_fs(int fd);
int fd_is_network_fs(int fd);

int path_is_temporary_fs(const char *path);
int path_is_network_fs(const char *path);

/* Because statfs.t_type can be int on some architectures, we have to cast
 * the const magic to the type, otherwise the compiler warns about
 * signed/unsigned comparison, because the magic can be 32 bit unsigned.
 */
#define F_TYPE_EQUAL(a, b) (a == (typeof(a)) b)

int stat_verify_regular(const struct stat *st);
int fd_verify_regular(int fd);

int stat_verify_directory(const struct stat *st);
int fd_verify_directory(int fd);

int proc_mounted(void);

bool stat_inode_same(const struct stat *a, const struct stat *b);
bool stat_inode_unmodified(const struct stat *a, const struct stat *b);

bool statx_inode_same(const struct statx *a, const struct statx *b);
bool statx_mount_same(const struct new_statx *a, const struct new_statx *b);

int statx_fallback(int dfd, const char *path, int flags, unsigned mask, struct statx *sx);

#if HAS_FEATURE_MEMORY_SANITIZER
#  warning "Explicitly initializing struct statx, to work around msan limitation. Please remove as soon as msan has been updated to not require this."
#  define STRUCT_STATX_DEFINE(var)              \
        struct statx var = {}
#  define STRUCT_NEW_STATX_DEFINE(var)          \
        union {                                 \
                struct statx sx;                \
                struct new_statx nsx;           \
        } var = {}
#else
#  define STRUCT_STATX_DEFINE(var)              \
        struct statx var
#  define STRUCT_NEW_STATX_DEFINE(var)          \
        union {                                 \
                struct statx sx;                \
                struct new_statx nsx;           \
        } var
#endif
