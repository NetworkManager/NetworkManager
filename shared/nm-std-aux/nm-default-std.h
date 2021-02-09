/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_DEFAULT_STD_H__
#define __NM_DEFAULT_STD_H__

#include "nm-networkmanager-compilation.h"

#ifdef NETWORKMANAGER_COMPILATION
    #error Dont define NETWORKMANAGER_COMPILATION
#endif

#ifndef G_LOG_DOMAIN
    #error Define G_LOG_DOMAIN
#endif

/*****************************************************************************/

#define NETWORKMANAGER_COMPILATION 0

/*****************************************************************************/

/* always include these headers for our internal source files. */

#ifndef ___CONFIG_H__
    #define ___CONFIG_H__
    #include <config.h>
#endif

#include "config-extra.h"

/* for internal compilation we don't want the deprecation macros
 * to be in effect. Define the widest range of versions to effectively
 * disable deprecation checks */
#define NM_VERSION_MIN_REQUIRED NM_VERSION_0_9_8

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

/*****************************************************************************/

#include <stdlib.h>

/*****************************************************************************/

#endif /* __NM_DEFAULT_STD_H__ */
