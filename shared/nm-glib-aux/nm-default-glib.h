/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_DEFAULT_GLIB_H__
#define __NM_DEFAULT_GLIB_H__

/*****************************************************************************/

#include "nm-std-aux/nm-default-std.h"

#undef NETWORKMANAGER_COMPILATION
#define NETWORKMANAGER_COMPILATION NM_NETWORKMANAGER_COMPILATION_WITH_GLIB

/*****************************************************************************/

#include <glib.h>

#if defined(_NETWORKMANAGER_COMPILATION_GLIB_I18N_PROG)
    #if defined(_NETWORKMANAGER_COMPILATION_GLIB_I18N_LIB)
        #error Cannot define _NETWORKMANAGER_COMPILATION_GLIB_I18N_LIB and _NETWORKMANAGER_COMPILATION_GLIB_I18N_PROG together
    #endif
    #undef _NETWORKMANAGER_COMPILATION_GLIB_I18N_PROG
    #include <glib/gi18n.h>
#elif defined(_NETWORKMANAGER_COMPILATION_GLIB_I18N_LIB)
    #undef _NETWORKMANAGER_COMPILATION_GLIB_I18N_LIB
    #include <glib/gi18n-lib.h>
#endif

/*****************************************************************************/

#if NM_MORE_ASSERTS == 0
    #ifndef G_DISABLE_CAST_CHECKS
        /* Unless compiling with G_DISABLE_CAST_CHECKS, glib performs type checking
         * during G_VARIANT_TYPE() via g_variant_type_checked_(). This is not necessary
         * because commonly this cast is needed during something like
         *
         *   g_variant_builder_init (&props, G_VARIANT_TYPE ("a{sv}"));
         *
         * Note that in if the variant type would be invalid, the check still
         * wouldn't make the buggy code magically work. Instead of passing a
         * bogus type string (bad), it would pass %NULL to g_variant_builder_init()
         * (also bad).
         *
         * Also, a function like g_variant_builder_init() already validates
         * the input type via something like
         *
         *   g_return_if_fail (g_variant_type_is_container (type));
         *
         * So, by having G_VARIANT_TYPE() also validate the type, we validate
         * twice, whereas the first validation is rather pointless because it
         * doesn't prevent the function to be called with invalid arguments.
         *
         * Just patch G_VARIANT_TYPE() to perform no check.
         */
        #undef G_VARIANT_TYPE
        #define G_VARIANT_TYPE(type_string) ((const GVariantType *) (type_string))
    #endif
#endif

/*****************************************************************************/

#include "nm-gassert-patch.h"

#include "nm-std-aux/nm-std-aux.h"
#include "nm-std-aux/nm-std-utils.h"
#include "nm-glib-aux/nm-macros-internal.h"
#include "nm-glib-aux/nm-shared-utils.h"
#include "nm-glib-aux/nm-errno.h"
#include "nm-glib-aux/nm-hash-utils.h"

/*****************************************************************************/

#endif /* __NM_DEFAULT_GLIB_H__ */
