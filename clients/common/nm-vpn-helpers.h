/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 - 2015 Red Hat, Inc.
 */

#ifndef __NM_VPN_HELPERS_H__
#define __NM_VPN_HELPERS_H__

#include <glib.h>
#include <NetworkManager.h>

#include <nm-vpn-editor-plugin.h>

struct {
	const char *name;
	const char *ui_name;
} typedef VpnPasswordName;

GSList *nm_vpn_get_plugins (GError **error);

NMVpnEditorPlugin *nm_vpn_get_plugin_by_service (const char *service);

gboolean nm_vpn_supports_ipv6 (NMConnection *connection);

const VpnPasswordName * nm_vpn_get_secret_names (const char *vpn_type);

#endif  /* __NM_VPN_HELPERS_H__ */
