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
 * Copyright (C) 2016 Red Hat, Inc.
 */

#ifndef __NM_VPN_EDITOR_PLUGIN_CALL_H__
#define __NM_VPN_EDITOR_PLUGIN_CALL_H__

/* This header is an internal, header-only file that can be copied to
 * other projects to call well-known service functions on VPN plugins.
 *
 * This uses the NMVpnEditorPluginVT and allows a user (nm-applet)
 * to directly communicate with a VPN plugin using API that is newer
 * then the current libnm version. That is, it allows to call to a VPN
 * plugin bypassing libnm. */

#include <NetworkManager.h>

/* we make use of other internal header files, you need those too. */
#include "nm-glib-aux/nm-macros-internal.h"

/*****************************************************************************/

/**
 * NMVpnEditorPluginServiceFlags:
 * @NM_VPN_EDITOR_PLUGIN_SERVICE_FLAGS_NONE: no flags
 * @NM_VPN_EDITOR_PLUGIN_SERVICE_FLAGS_CAN_ADD: whether the plugin can
 *   add a new connection for the given service-type.
 **/
typedef enum { /*< skip >*/
	NM_VPN_EDITOR_PLUGIN_SERVICE_FLAGS_NONE     = 0x00,
	NM_VPN_EDITOR_PLUGIN_SERVICE_FLAGS_CAN_ADD  = 0x01,
} NMVpnEditorPluginServiceFlags;

struct _NMVpnEditorPluginVT {
	gboolean (*fcn_get_service_info) (NMVpnEditorPlugin *plugin,
	                                  const char *service_type,
	                                  char **out_short_name,
	                                  char **out_pretty_name,
	                                  char **out_description,
	                                  NMVpnEditorPluginServiceFlags *out_flags);
	char **(*fcn_get_service_add_details) (NMVpnEditorPlugin *plugin,
	                                       const char *service_name);
	gboolean (*fcn_get_service_add_detail) (NMVpnEditorPlugin *plugin,
	                                        const char *service_type,
	                                        const char *add_detail,
	                                        char **out_pretty_name,
	                                        char **out_description,
	                                        char **out_add_detail_key,
	                                        char **out_add_detail_val,
	                                        guint *out_flags);
};

/*****************************************************************************
 * Call
 *
 * The following wrap the calling of generic functions for a VPN plugin.
 * They are used by callers (for example nm-connection-editor).
 *****************************************************************************/

static inline gboolean
nm_vpn_editor_plugin_get_service_info (NMVpnEditorPlugin *plugin,
                                       const char *service_type,
                                       char **out_short_name,
                                       char **out_pretty_name,
                                       char **out_description,
                                       NMVpnEditorPluginServiceFlags *out_flags)
{
	NMVpnEditorPluginVT vt;
	gs_free char *short_name_local = NULL;
	gs_free char *pretty_name_local = NULL;
	gs_free char *description_local = NULL;
	guint flags_local = 0;

	g_return_val_if_fail (NM_IS_VPN_EDITOR_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (service_type, FALSE);

	nm_vpn_editor_plugin_get_vt (plugin, &vt, sizeof (vt));
	if (   !vt.fcn_get_service_info
	    || !vt.fcn_get_service_info (plugin,
	                                 service_type,
	                                 out_short_name  ? &short_name_local : NULL,
	                                 out_pretty_name ? &pretty_name_local : NULL,
	                                 out_description ? &description_local : NULL,
	                                 out_flags       ? &flags_local : NULL))
		return FALSE;
	NM_SET_OUT (out_short_name, g_steal_pointer (&short_name_local));
	NM_SET_OUT (out_pretty_name, g_steal_pointer (&pretty_name_local));
	NM_SET_OUT (out_description, g_steal_pointer (&description_local));
	NM_SET_OUT (out_flags, flags_local);
	return TRUE;
}

static inline char **
nm_vpn_editor_plugin_get_service_add_details (NMVpnEditorPlugin *plugin,
                                              const char *service_name)
{
	NMVpnEditorPluginVT vt;
	char **details = NULL;

	g_return_val_if_fail (NM_IS_VPN_EDITOR_PLUGIN (plugin), NULL);
	g_return_val_if_fail (service_name, NULL);

	nm_vpn_editor_plugin_get_vt (plugin, &vt, sizeof (vt));
	if (vt.fcn_get_service_add_details)
		details = vt.fcn_get_service_add_details (plugin, service_name);
	if (!details)
		return g_new0 (char *, 1);
	return details;
}

static inline gboolean
nm_vpn_editor_plugin_get_service_add_detail (NMVpnEditorPlugin *plugin,
                                             const char *service_type,
                                             const char *add_detail,
                                             char **out_pretty_name,
                                             char **out_description,
                                             char **out_add_detail_key,
                                             char **out_add_detail_val,
                                             guint *out_flags)
{
	NMVpnEditorPluginVT vt;
	gs_free char *pretty_name_local = NULL;
	gs_free char *description_local = NULL;
	gs_free char *add_detail_key_local = NULL;
	gs_free char *add_detail_val_local = NULL;
	guint flags_local = 0;

	g_return_val_if_fail (NM_IS_VPN_EDITOR_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (service_type, FALSE);
	g_return_val_if_fail (add_detail, FALSE);

	nm_vpn_editor_plugin_get_vt (plugin, &vt, sizeof (vt));
	if (   !vt.fcn_get_service_add_detail
	    || !vt.fcn_get_service_add_detail (plugin,
	                                       service_type,
	                                       add_detail,
	                                       out_pretty_name    ? &pretty_name_local : NULL,
	                                       out_description    ? &description_local : NULL,
	                                       out_add_detail_key ? &add_detail_key_local : NULL,
	                                       out_add_detail_val ? &add_detail_val_local : NULL,
	                                       out_flags          ? &flags_local : NULL))
		return FALSE;
	NM_SET_OUT (out_pretty_name, g_steal_pointer (&pretty_name_local));
	NM_SET_OUT (out_description, g_steal_pointer (&description_local));
	NM_SET_OUT (out_add_detail_key, g_steal_pointer (&add_detail_key_local));
	NM_SET_OUT (out_add_detail_val, g_steal_pointer (&add_detail_val_local));
	NM_SET_OUT (out_flags, flags_local);
	return TRUE;
}

/*****************************************************************************
 * Implementation
 *
 * The following glue code can be used to implement calls in a VPN plugin.
 *****************************************************************************/

#define NM_VPN_EDITOR_PLUGIN_VT_DEFINE(vt_name, get_vt, ...) \
static const NMVpnEditorPluginVT vt_name = { \
		__VA_ARGS__ \
	}; \
static const NMVpnEditorPluginVT * \
get_vt (NMVpnEditorPlugin *plugin, \
        gsize *out_vt_size) \
{ \
	nm_assert (NM_IS_VPN_EDITOR_PLUGIN (plugin)); \
	nm_assert (out_vt_size); \
	\
	*out_vt_size = sizeof (vt_name); \
	return &vt_name; \
}

#endif /* __NM_VPN_EDITOR_PLUGIN_CALL_H__ */
