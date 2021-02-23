/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_DEFAULT_GLIB_I18N_PROG_H__
#define __NM_DEFAULT_GLIB_I18N_PROG_H__

/*****************************************************************************/

#define _NETWORKMANAGER_COMPILATION_GLIB_I18N_PROG

#include "libnm-glib-aux/nm-default-glib.h"

#undef NETWORKMANAGER_COMPILATION
#define NETWORKMANAGER_COMPILATION \
    (NM_NETWORKMANAGER_COMPILATION_GLIB | NM_NETWORKMANAGER_COMPILATION_WITH_GLIB_I18N_PROG)

/*****************************************************************************/

#endif /* __NM_DEFAULT_GLIB_I18N_PROG_H__ */
