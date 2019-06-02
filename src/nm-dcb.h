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

#ifndef __NETWORKMANAGER_DCB_H__
#define __NETWORKMANAGER_DCB_H__

#include "nm-setting-dcb.h"

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

#endif /* __NETWORKMANAGER_DCB_H__ */
