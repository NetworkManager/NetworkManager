/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_DEFAULT_GLIB_H__
#define __NM_DEFAULT_GLIB_H__

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

#include "nm-gassert-patch.h"

#include "nm-std-aux/nm-std-aux.h"
#include "nm-std-aux/nm-std-utils.h"
#include "nm-glib-aux/nm-macros-internal.h"
#include "nm-glib-aux/nm-shared-utils.h"
#include "nm-glib-aux/nm-errno.h"
#include "nm-glib-aux/nm-hash-utils.h"

/*****************************************************************************/

#endif /* __NM_DEFAULT_GLIB_H__ */
