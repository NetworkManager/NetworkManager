/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service (ifupdown)
 *
 * Alexander Sack <asac@ubuntu.com>
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
 * (C) Copyright 2007,2008 Canonical Ltd.
 */

#include "nm-default.h"

#include "nms-ifupdown-connection.h"

#include <glib/gstdio.h>

#include "nm-dbus-interface.h"
#include "nm-utils.h"
#include "nm-setting-wireless-security.h"
#include "settings/nm-settings-connection.h"
#include "settings/nm-settings-plugin.h"

#include "nms-ifupdown-parser.h"

/*****************************************************************************/

struct _NMIfupdownConnection {
	NMSettingsConnection parent;
};

struct _NMIfupdownConnectionClass {
	NMSettingsConnectionClass parent;
};

G_DEFINE_TYPE (NMIfupdownConnection, nm_ifupdown_connection, NM_TYPE_SETTINGS_CONNECTION)

/*****************************************************************************/

#define _NMLOG_PREFIX_NAME      "ifupdown"
#define _NMLOG_DOMAIN           LOGD_SETTINGS
#define _NMLOG(level, ...) \
    nm_log ((level), _NMLOG_DOMAIN, NULL, NULL, \
            "%s" _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
            _NMLOG_PREFIX_NAME": " \
            _NM_UTILS_MACRO_REST (__VA_ARGS__))

/*****************************************************************************/

static gboolean
supports_secrets (NMSettingsConnection *connection, const char *setting_name)
{
	_LOGI ("supports_secrets() for setting_name: '%s'", setting_name);

	return (strcmp (setting_name, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME) == 0);
}

/*****************************************************************************/

static void
nm_ifupdown_connection_init (NMIfupdownConnection *connection)
{
}

NMIfupdownConnection *
nm_ifupdown_connection_new (if_block *block)
{
	NMIfupdownConnection *connection;
	GError *error = NULL;

	g_return_val_if_fail (block != NULL, NULL);

	connection = g_object_new (NM_TYPE_IFUPDOWN_CONNECTION, NULL);

	/* FIXME(copy-on-write-connection): avoid modifying NMConnection instances and share them via copy-on-write. */
	if (!ifupdown_update_connection_from_if_block (nm_settings_connection_get_connection (NM_SETTINGS_CONNECTION (connection)),
	                                               block,
	                                               &error)) {
		_LOGW ("invalid connection read from /etc/network/interfaces: %s",
		       error->message);
		g_object_unref (connection);
		return NULL;
	}

	return connection;
}

static void
nm_ifupdown_connection_class_init (NMIfupdownConnectionClass *ifupdown_connection_class)
{
	NMSettingsConnectionClass *connection_class = NM_SETTINGS_CONNECTION_CLASS (ifupdown_connection_class);

	connection_class->supports_secrets = supports_secrets;
}

