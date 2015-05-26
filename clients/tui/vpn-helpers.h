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
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef _VPN_HELPERS_H_
#define _VPN_HELPERS_H_

#include <NetworkManager.h>

#include "nm-glib.h"

GSList *vpn_get_plugins (void);

NMVpnEditorPlugin *vpn_get_plugin_by_service (const char *service);

typedef void (*VpnImportSuccessCallback) (NMConnection *connection, gpointer user_data);
void vpn_import (VpnImportSuccessCallback callback, gpointer user_data);

void vpn_export (NMConnection *connection);

gboolean vpn_supports_ipv6 (NMConnection *connection);

#endif  /* _VPN_HELPERS_H_ */
