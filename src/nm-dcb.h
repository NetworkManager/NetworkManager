/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NM_DCB_H
#define NM_DCB_H

#include <glib.h>
#include "nm-setting-dcb.h"

/**
 * NMDcbError:
 * @NM_DCB_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_DCB_ERROR_INTERNAL: a internal programmer error
 * @NM_DCB_ERROR_BAD_CONFIG: configuration was invalid
 * @NM_DCB_ERROR_HELPER_NOT_FOUND: the required helper program was not found
 * @NM_DCB_ERROR_HELPER_FAILED: the helper program failed
 *
 * NOTE: these errors are internal-use only and should never be used with D-Bus.
 **/
typedef enum {
	NM_DCB_ERROR_UNKNOWN = 0,
	NM_DCB_ERROR_INTERNAL,
	NM_DCB_ERROR_BAD_CONFIG,
	NM_DCB_ERROR_HELPER_NOT_FOUND,
	NM_DCB_ERROR_HELPER_FAILED,
} NMDcbError;

#define NM_DCB_ERROR (nm_dcb_error_quark ())
GQuark nm_dcb_error_quark (void);
#define NM_TYPE_DCB_ERROR (nm_dcb_error_get_type ())
GType  nm_dcb_error_get_type (void);


gboolean nm_dcb_enable (const char *iface, gboolean enable, GError **error);
gboolean nm_dcb_setup (const char *iface, NMSettingDcb *s_dcb, GError **error);
gboolean nm_dcb_cleanup (const char *iface, GError **error);

/* For testcases only! */
typedef gboolean (*DcbFunc) (char **argv,
                             guint which,
                             gpointer user_data,
                             GError **error);

#define DCBTOOL 0
#define FCOEADM 1

gboolean do_helper (const char *iface,
                    guint which,
                    DcbFunc run_func,
                    gpointer user_data,
                    GError **error,
                    const char *fmt,
                    ...) G_GNUC_PRINTF(6, 7);

gboolean _dcb_enable (const char *iface,
                      gboolean enable,
                      DcbFunc run_func,
                      gpointer user_data,
                      GError **error);

gboolean _dcb_setup (const char *iface,
                     NMSettingDcb *s_dcb,
                     DcbFunc run_func,
                     gpointer user_data,
                     GError **error);

gboolean _dcb_cleanup (const char *iface,
                       DcbFunc run_func,
                       gpointer user_data,
                       GError **error);

gboolean _fcoe_setup (const char *iface,
                      NMSettingDcb *s_dcb,
                      DcbFunc run_func,
                      gpointer user_data,
                      GError **error);

gboolean _fcoe_cleanup (const char *iface,
                        DcbFunc run_func,
                        gpointer user_data,
                        GError **error);

#endif /* NM_DCB_H */
