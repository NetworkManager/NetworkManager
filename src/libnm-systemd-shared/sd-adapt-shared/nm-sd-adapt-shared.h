/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2014 - 2018 Red Hat, Inc.
 */

#ifndef __NM_SD_ADAPT_SHARED_H__
#define __NM_SD_ADAPT_SHARED_H__

#include "libnm-systemd-shared/nm-default-systemd-shared.h"

#include "libnm-glib-aux/nm-logging-fwd.h"

/*****************************************************************************/

/* strerror() is not thread-safe. Patch systemd-sources via a define. */
#define strerror(errsv) nm_strerror_native(errsv)

/*****************************************************************************/

/* systemd detects whether compiler supports "-Wstringop-truncation" to disable
 * the warning at particular places. Since we anyway build with -Wno-pragma,
 * we don't do that and just let systemd call
 *
 *   _Pragma("GCC diagnostic ignored \"-Wstringop-truncation\"")
 *
 * regadless whether that would result in a -Wpragma warning. */
#define HAVE_WSTRINGOP_TRUNCATION 1

/*****************************************************************************/

#ifndef VALGRIND
#define VALGRIND 0
#endif

#define ENABLE_DEBUG_HASHMAP 0

/*****************************************************************************
 * The remainder of the header is only enabled when building the systemd code
 * itself.
 *****************************************************************************/

#if (NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_SYSTEMD

#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <pthread.h>

#define ENABLE_GSHADOW FALSE

#define HAVE_SECCOMP 0

#define LOG_TRACE 0

#define WANT_LINUX_FS_H 0

#define BUILD_MODE_DEVELOPER (NM_MORE_ASSERTS > 0)

#define LOG_MESSAGE_VERIFICATION (NM_MORE_ASSERTS > 0)

/*****************************************************************************/

/* systemd cannot be compiled with "-Wdeclaration-after-statement". In particular
 * in combination with assert_cc(). */
NM_PRAGMA_WARNING_DISABLE("-Wdeclaration-after-statement")

/*****************************************************************************/

struct statx;

/*****************************************************************************/

static inline pid_t
raw_getpid(void)
{
#if defined(__alpha__)
    return (pid_t) syscall(__NR_getxpid);
#else
    return (pid_t) syscall(__NR_getpid);
#endif
}

#define gettid() nm_utils_gettid()

/* we build with C11 and thus <uchar.h> provides char32_t,char16_t. */
#define HAVE_CHAR32_T 1
#define HAVE_CHAR16_T 1

#if defined(HAVE_DECL_REALLOCARRAY) && HAVE_DECL_REALLOCARRAY == 1
#define HAVE_REALLOCARRAY 1
#else
#define HAVE_REALLOCARRAY 0
#endif

#if defined(HAVE_DECL_EXPLICIT_BZERO) && HAVE_DECL_EXPLICIT_BZERO == 1
#define HAVE_EXPLICIT_BZERO 1
#else
#define HAVE_EXPLICIT_BZERO 0
#endif

#if defined(HAVE_DECL_PIDFD_OPEN) && HAVE_DECL_PIDFD_OPEN == 1
#define HAVE_PIDFD_OPEN 1
#else
#define HAVE_PIDFD_OPEN 0
#endif

#if defined(HAVE_DECL_PIDFD_SEND_SIGNAL) && HAVE_DECL_PIDFD_SEND_SIGNAL == 1
#define HAVE_PIDFD_SEND_SIGNAL 1
#else
#define HAVE_PIDFD_SEND_SIGNAL 0
#endif

#if defined(HAVE_DECL_RT_SIGQUEUEINFO) && HAVE_DECL_RT_SIGQUEUEINFO == 1
#define HAVE_RT_SIGQUEUEINFO 1
#else
#define HAVE_RT_SIGQUEUEINFO 0
#endif

#ifndef ALTIFNAMSIZ
#define ALTIFNAMSIZ 128
#endif

#define HAVE_LINUX_TIME_TYPES_H 0

#ifndef __COMPAR_FN_T
#define __COMPAR_FN_T
typedef int (*__compar_fn_t)(const void *, const void *);
typedef __compar_fn_t comparison_fn_t;
typedef int (*__compar_d_fn_t)(const void *, const void *, void *);
#endif

#ifndef __GLIBC__
static inline int
__register_atfork(void (*prepare)(void),
                  void (*parent)(void),
                  void (*child)(void),
                  void *dso_handle)
{
    return pthread_atfork(prepare, parent, child);
}
#endif

#endif /* (NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_SYSTEMD */

/*****************************************************************************/

#endif /* __NM_SD_ADAPT_SHARED_H__ */
