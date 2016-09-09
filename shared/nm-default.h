/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2015 Red Hat, Inc.
 */

#ifndef __NM_DEFAULT_H__
#define __NM_DEFAULT_H__

/* makefiles define NETWORKMANAGER_COMPILATION for compiling NetworkManager.
 * Depending on which parts are compiled, different values are set. */
#define NM_NETWORKMANAGER_COMPILATION_DEFAULT             0x0001
#define NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON       0x0002
#define NM_NETWORKMANAGER_COMPILATION_LIB                 0x0004
#define NM_NETWORKMANAGER_COMPILATION_SYSTEMD             0x0008
#define NM_NETWORKMANAGER_COMPILATION_LIB_LEGACY          0x0010

#ifndef NETWORKMANAGER_COMPILATION
/* For convenience, we don't require our Makefile.am to define
 * -DNETWORKMANAGER_COMPILATION. As we now include this internal header,
 *  we know we do a NETWORKMANAGER_COMPILATION. */
#define NETWORKMANAGER_COMPILATION NM_NETWORKMANAGER_COMPILATION_DEFAULT
#endif

/*****************************************************************************/

/* always include these headers for our internal source files. */

#ifndef ___CONFIG_H__
#define ___CONFIG_H__
#include <config.h>
#endif

/* for internal compilation we don't want the deprecation macros
 * to be in effect. Define the widest range of versions to effectively
 * disable deprecation checks */
#define NM_VERSION_MAX_ALLOWED   NM_VERSION_NEXT_STABLE
#define NM_VERSION_MIN_REQUIRED  NM_VERSION_0_9_8

#ifndef NM_MORE_ASSERTS
#define NM_MORE_ASSERTS 0
#endif

#if NM_MORE_ASSERTS == 0
/* The cast macros like NM_TYPE() are implemented via G_TYPE_CHECK_INSTANCE_CAST()
 * and _G_TYPE_CIC(). The latter, by default performs runtime checks of the type
 * by calling g_type_check_instance_cast().
 * This check has a certain overhead without being helpful.
 *
 * Example 1:
 *     static void foo (NMType *obj)
 *     {
 *         access_obj_without_check (obj);
 *     }
 *     foo ((NMType *) obj);
 *     // There is no runtime check and passing an invalid pointer
 *     // leads to a crash.
 *
 * Example 2:
 *     static void foo (NMType *obj)
 *     {
 *         access_obj_without_check (obj);
 *     }
 *     foo (NM_TYPE (obj));
 *     // There is a runtime check which prints a g_warning(), but that doesn't
 *     // avoid the crash as NM_TYPE() cannot do anything then passing on the
 *     // invalid pointer.
 *
 * Example 3:
 *     static void foo (NMType *obj)
 *     {
 *         g_return_if_fail (NM_IS_TYPE (obj));
 *         access_obj_without_check (obj);
 *     }
 *     foo ((NMType *) obj);
 *     // There is a runtime check which prints a g_critical() which also avoids
 *     // the crash. That is actually helpful to catch bugs and avoid crashes.
 *
 * Example 4:
 *     static void foo (NMType *obj)
 *     {
 *         g_return_if_fail (NM_IS_TYPE (obj));
 *         access_obj_without_check (obj);
 *     }
 *     foo (NM_TYPE (obj));
 *     // The runtime check is performed twice, with printing a g_warning() and
 *     // a g_critical() and avoiding the crash.
 *
 * Example 3 is how it should be done. Type checks in NM_TYPE() are pointless.
 * Disable them for our production builds.
 */
#ifndef G_DISABLE_CAST_CHECKS
#define G_DISABLE_CAST_CHECKS
#endif
#endif

#include <stdlib.h>
#include <glib.h>

/*****************************************************************************/

#if NM_MORE_ASSERTS == 0

/* glib assertions (g_return_*(), g_assert*()) contain a textual representation
 * of the checked statement. This part of the assertion blows up the size of the
 * binary. Unless we compile a debug-build with NM_MORE_ASSERTS, drop these
 * parts. Note that the failed assertion still prints the file and line where the
 * assertion fails. That shall suffice. */

static inline void
_nm_g_return_if_fail_warning (const char *log_domain,
                              const char *file,
                              int line)
{
	char file_buf[256 + 15];

	g_snprintf (file_buf, sizeof (file_buf), "((%s:%d))", file, line);
	g_return_if_fail_warning (log_domain, file_buf, "<dropped>");
}

#define g_return_if_fail_warning(log_domain, pretty_function, expression) \
	_nm_g_return_if_fail_warning (log_domain, __FILE__, __LINE__)

#define g_assertion_message_expr(domain, file, line, func, expr) \
	g_assertion_message_expr(domain, file, line, "<unknown-fcn>", (expr) ? "<dropped>" : NULL)

#undef g_return_val_if_reached
#define g_return_val_if_reached(val) \
    G_STMT_START { \
        g_log (G_LOG_DOMAIN, \
               G_LOG_LEVEL_CRITICAL, \
               "file %s: line %d (%s): should not be reached", \
               __FILE__, \
               __LINE__, \
               "<dropped>"); \
        return (val); \
    } G_STMT_END

#undef g_return_if_reached
#define g_return_if_reached() \
    G_STMT_START { \
        g_log (G_LOG_DOMAIN, \
               G_LOG_LEVEL_CRITICAL, \
               "file %s: line %d (%s): should not be reached", \
               __FILE__, \
               __LINE__, \
               "<dropped>"); \
        return; \
    } G_STMT_END

#define NM_ASSERT_G_RETURN_EXPR(expr) "<dropped>"
#define NM_ASSERT_NO_MSG 1

#else

#define NM_ASSERT_G_RETURN_EXPR(expr) ""expr""
#define NM_ASSERT_NO_MSG 0

#endif

/*****************************************************************************/

#include "nm-utils/nm-macros-internal.h"
#include "nm-utils/nm-shared-utils.h"

#include "nm-version.h"

/*****************************************************************************/

#if ((NETWORKMANAGER_COMPILATION) == NM_NETWORKMANAGER_COMPILATION_LIB) || ((NETWORKMANAGER_COMPILATION) == NM_NETWORKMANAGER_COMPILATION_LIB_LEGACY)

#include <glib/gi18n-lib.h>

#else

#include <glib/gi18n.h>

#endif /* NM_NETWORKMANAGER_COMPILATION_LIB || NM_NETWORKMANAGER_COMPILATION_LIB_LEGACY */

/*****************************************************************************/

#if (NETWORKMANAGER_COMPILATION) == NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON || (NETWORKMANAGER_COMPILATION) == NM_NETWORKMANAGER_COMPILATION_SYSTEMD

/* the header is used inside src/, where additional
 * headers are available. */

#include "nm-types.h"
#include "nm-logging.h"

#endif /* NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON */

/*****************************************************************************/

#endif /* __NM_DEFAULT_H__ */
