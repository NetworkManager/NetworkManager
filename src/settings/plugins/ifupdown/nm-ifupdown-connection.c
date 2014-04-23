/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

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

#include <string.h>
#include <glib/gstdio.h>
#include <NetworkManager.h>
#include <nm-utils.h>
#include <nm-setting-wireless-security.h>
#include <nm-settings-connection.h>
#include <nm-system-config-interface.h>
#include <nm-settings-error.h>
#include <nm-logging.h>
#include "nm-ifupdown-connection.h"
#include "parser.h"

G_DEFINE_TYPE (NMIfupdownConnection, nm_ifupdown_connection, NM_TYPE_SETTINGS_CONNECTION)

#define NM_IFUPDOWN_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_IFUPDOWN_CONNECTION, NMIfupdownConnectionPrivate))

typedef struct {
	if_block *ifblock;
} NMIfupdownConnectionPrivate;

enum {
	PROP_ZERO,
	PROP_IFBLOCK,
	_PROP_END,
};


NMIfupdownConnection*
nm_ifupdown_connection_new (if_block *block)
{
	g_return_val_if_fail (block != NULL, NULL);

	return (NMIfupdownConnection *) g_object_new (NM_TYPE_IFUPDOWN_CONNECTION,
										 NM_IFUPDOWN_CONNECTION_IFBLOCK, block,
										 NULL);
}

static gboolean
supports_secrets (NMSettingsConnection *connection, const char *setting_name)
{
	nm_log_info (LOGD_SETTINGS, "supports_secrets() for setting_name: '%s'", setting_name);

	return (strcmp (setting_name, NM_SETTING_WIRELESS_SECURITY_SETTING_NAME) == 0);
}

static void
nm_ifupdown_connection_init (NMIfupdownConnection *connection)
{
}

static GObject *
constructor (GType type,
		   guint n_construct_params,
		   GObjectConstructParam *construct_params)
{
	GObject *object;
	NMIfupdownConnectionPrivate *priv;
	GError *error = NULL;

	object = G_OBJECT_CLASS (nm_ifupdown_connection_parent_class)->constructor (type, n_construct_params, construct_params);
	g_return_val_if_fail (object, NULL);

	priv = NM_IFUPDOWN_CONNECTION_GET_PRIVATE (object);
	if (!priv) {
		nm_log_warn (LOGD_SETTINGS, "%s.%d - no private instance.", __FILE__, __LINE__);
		goto err;
	}
	if (!priv->ifblock) {
		nm_log_warn (LOGD_SETTINGS, "(ifupdown) ifblock not provided to constructor.");
		goto err;
	}

	if (!ifupdown_update_connection_from_if_block (NM_CONNECTION (object), priv->ifblock, &error)) {
		nm_log_warn (LOGD_SETTINGS, "%s.%d - invalid connection read from /etc/network/interfaces: (%d) %s",
		             __FILE__,
		             __LINE__,
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		goto err;
	}

	return object;

 err:
	g_object_unref (object);
	return NULL;
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMIfupdownConnectionPrivate *priv = NM_IFUPDOWN_CONNECTION_GET_PRIVATE (object);
	g_return_if_fail (priv);

	switch (prop_id) {
	case PROP_IFBLOCK:
		priv->ifblock = g_value_get_pointer (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	NMIfupdownConnectionPrivate *priv = NM_IFUPDOWN_CONNECTION_GET_PRIVATE (object);
	g_return_if_fail (priv);

	switch (prop_id) {
	case PROP_IFBLOCK:
		g_value_set_pointer (value, priv->ifblock);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_ifupdown_connection_class_init (NMIfupdownConnectionClass *ifupdown_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ifupdown_connection_class);
	NMSettingsConnectionClass *connection_class = NM_SETTINGS_CONNECTION_CLASS (ifupdown_connection_class);

	g_type_class_add_private (ifupdown_connection_class, sizeof (NMIfupdownConnectionPrivate));

	/* Virtual methods */
	object_class->constructor  = constructor;
	object_class->set_property = set_property;
	object_class->get_property = get_property;

	connection_class->supports_secrets = supports_secrets;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_IFBLOCK,
		 g_param_spec_pointer (NM_IFUPDOWN_CONNECTION_IFBLOCK,
						   "ifblock",
						   "",
						   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

