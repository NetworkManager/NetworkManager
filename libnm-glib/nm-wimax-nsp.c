/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2011 Red Hat, Inc.
 */

#include <config.h>
#include <string.h>

#include <nm-connection.h>
#include <nm-setting-connection.h>
#include <nm-setting-wimax.h>

#include "nm-wimax-nsp.h"
#include "NetworkManager.h"
#include "nm-types-private.h"
#include "nm-object-private.h"

G_DEFINE_TYPE (NMWimaxNsp, nm_wimax_nsp, NM_TYPE_OBJECT)

#define NM_WIMAX_NSP_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_WIMAX_NSP, NMWimaxNspPrivate))

typedef struct {
	gboolean disposed;
	DBusGProxy *proxy;

	char *name;
	guint32 signal_quality;
	NMWimaxNspNetworkType network_type;
} NMWimaxNspPrivate;

enum {
	PROP_0,
	PROP_NAME,
	PROP_SIGNAL_QUALITY,
	PROP_NETWORK_TYPE,

	LAST_PROP
};

#define DBUS_PROP_NAME "Name"
#define DBUS_PROP_SIGNAL_QUALITY "SignalQuality"
#define DBUS_PROP_NETWORK_TYPE "NetworkType"

/**
 * nm_wimax_nsp_new:
 * @connection: the #DBusGConnection
 * @path: the D-Bus object path of the WiMAX NSP
 *
 * Creates a new #NMWimaxNsp.
 *
 * Returns: (transfer full): a new WiMAX NSP
 **/
GObject *
nm_wimax_nsp_new (DBusGConnection *connection, const char *path)
{
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return (GObject *) g_object_new (NM_TYPE_WIMAX_NSP,
									 NM_OBJECT_DBUS_CONNECTION, connection,
									 NM_OBJECT_DBUS_PATH, path,
									 NULL);
}

/**
 * nm_wimax_nsp_get_name:
 * @nsp: a #NMWimaxNsp
 *
 * Gets the name of the wimax NSP
 *
 * Returns: the name
 **/
const char *
nm_wimax_nsp_get_name (NMWimaxNsp *nsp)
{
	NMWimaxNspPrivate *priv;

	g_return_val_if_fail (NM_IS_WIMAX_NSP (nsp), NULL);

	priv = NM_WIMAX_NSP_GET_PRIVATE (nsp);
	if (!priv->name)
		priv->name = _nm_object_get_string_property (NM_OBJECT (nsp),
		                                             NM_DBUS_INTERFACE_WIMAX_NSP,
		                                             DBUS_PROP_NAME,
		                                             NULL);

	return priv->name;
}

/**
 * nm_wimax_nsp_get_signal_quality:
 * @nsp: a #NMWimaxNsp
 *
 * Gets the WPA signal quality of the wimax NSP.
 *
 * Returns: the signal quality
 **/
guint32
nm_wimax_nsp_get_signal_quality (NMWimaxNsp *nsp)
{
	NMWimaxNspPrivate *priv;

	g_return_val_if_fail (NM_IS_WIMAX_NSP (nsp), 0);

	priv = NM_WIMAX_NSP_GET_PRIVATE (nsp);
	if (!priv->signal_quality) {
		priv->signal_quality = _nm_object_get_uint_property (NM_OBJECT (nsp),
		                                                     NM_DBUS_INTERFACE_WIMAX_NSP,
		                                                     DBUS_PROP_SIGNAL_QUALITY,
		                                                     NULL);
	}

	return priv->signal_quality;
}

/**
 * nm_wimax_nsp_get_network_type:
 * @nsp: a #NMWimaxNsp
 *
 * Gets the network type of the wimax NSP.
 *
 * Returns: the network type
 **/
NMWimaxNspNetworkType
nm_wimax_nsp_get_network_type (NMWimaxNsp *nsp)
{
	NMWimaxNspPrivate *priv;

	g_return_val_if_fail (NM_IS_WIMAX_NSP (nsp), NM_WIMAX_NSP_NETWORK_TYPE_UNKNOWN);

	priv = NM_WIMAX_NSP_GET_PRIVATE (nsp);
	if (!priv->network_type) {
		priv->network_type = _nm_object_get_uint_property (NM_OBJECT (nsp),
		                                                   NM_DBUS_INTERFACE_WIMAX_NSP,
		                                                   DBUS_PROP_NETWORK_TYPE,
		                                                   NULL);
	}

	return priv->network_type;
}

/**
 * nm_wimax_nsp_filter_connections:
 * @nsp: an #NMWimaxNsp to validate @connection against
 * @connection: an #NMConnection to validate against @nsp
 *
 * Validates a given connection against a given WiMAX NSP to ensure that the
 * connection may be activated with that NSP.  The connection must match the
 * @nsp's network name and other attributes.
 *
 * Returns: %TRUE if the connection may be activated with this WiMAX NSP,
 * %FALSE if it cannot be.
 **/
gboolean
nm_wimax_nsp_connection_valid (NMWimaxNsp *nsp, NMConnection *connection)
{
	NMSettingConnection *s_con;
	NMSettingWimax *s_wimax;
	const char *ctype;
	const char *nsp_name;
	const char *setting_name;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	ctype = nm_setting_connection_get_connection_type (s_con);
	if (strcmp (ctype, NM_SETTING_WIMAX_SETTING_NAME) != 0)
		return FALSE;

	s_wimax = nm_connection_get_setting_wimax (connection);
	if (!s_wimax)
		return FALSE;

	setting_name = nm_setting_wimax_get_network_name (s_wimax);
	if (!setting_name)
		return FALSE;

	nsp_name = nm_wimax_nsp_get_name (nsp);
	g_warn_if_fail (nsp_name != NULL);
	if (g_strcmp0 (nsp_name, setting_name) != 0)
		return FALSE;

	return TRUE;
}

/**
 * nm_wimax_nsp_filter_connections:
 * @nsp: an #NMWimaxNsp to filter connections for
 * @connections: (element-type NetworkManager.Connection): a list of
 * #NMConnection objects to filter
 *
 * Filters a given list of connections for a given #NMWimaxNsp object and
 * return connections which may be activated with the access point.  Any
 * returned connections will match the @nsp's network name and other attributes.
 *
 * Returns: (transfer container) (element-type NetworkManager.Connection): a
 * list of #NMConnection objects that could be activated with the given @nsp.
 * The elements of the list are owned by their creator and should not be freed
 * by the caller, but the returned list itself is owned by the caller and should
 * be freed with g_slist_free() when it is no longer required.
 **/
GSList *
nm_wimax_nsp_filter_connections (NMWimaxNsp *nsp, const GSList *connections)
{
	GSList *filtered = NULL;
	const GSList *iter;

	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *candidate = NM_CONNECTION (iter->data);

		if (nm_wimax_nsp_connection_valid (nsp, candidate))
			filtered = g_slist_prepend (filtered, candidate);
	}

	return g_slist_reverse (filtered);
}

/************************************************************/

static void
nm_wimax_nsp_init (NMWimaxNsp *nsp)
{
}

static void
dispose (GObject *object)
{
	NMWimaxNspPrivate *priv = NM_WIMAX_NSP_GET_PRIVATE (object);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_wimax_nsp_parent_class)->dispose (object);
		return;
	}

	priv->disposed = TRUE;

	g_object_unref (priv->proxy);

	G_OBJECT_CLASS (nm_wimax_nsp_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMWimaxNspPrivate *priv = NM_WIMAX_NSP_GET_PRIVATE (object);

	g_free (priv->name);

	G_OBJECT_CLASS (nm_wimax_nsp_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMWimaxNsp *nsp = NM_WIMAX_NSP (object);

	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, nm_wimax_nsp_get_name (nsp));
		break;
	case PROP_SIGNAL_QUALITY:
		g_value_set_uint (value, nm_wimax_nsp_get_signal_quality (nsp));
		break;
	case PROP_NETWORK_TYPE:
		g_value_set_uint (value, nm_wimax_nsp_get_network_type (nsp));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
register_for_property_changed (NMWimaxNsp *nsp)
{
	NMWimaxNspPrivate *priv = NM_WIMAX_NSP_GET_PRIVATE (nsp);
	const NMPropertiesChangedInfo property_changed_info[] = {
		{ NM_WIMAX_NSP_SIGNAL_QUALITY, _nm_object_demarshal_generic, &priv->signal_quality },
		{ NULL },
	};

	_nm_object_handle_properties_changed (NM_OBJECT (nsp),
										  priv->proxy,
										  property_changed_info);
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	NMObject *object;
	NMWimaxNspPrivate *priv;

	object = (NMObject *) G_OBJECT_CLASS (nm_wimax_nsp_parent_class)->constructor (type,
																				   n_construct_params,
																				   construct_params);
	if (!object)
		return NULL;

	priv = NM_WIMAX_NSP_GET_PRIVATE (object);

	priv->proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (object),
											 NM_DBUS_SERVICE,
											 nm_object_get_path (object),
											 NM_DBUS_INTERFACE_WIMAX_NSP);

	register_for_property_changed (NM_WIMAX_NSP (object));

	return G_OBJECT (object);
}


static void
nm_wimax_nsp_class_init (NMWimaxNspClass *nsp_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (nsp_class);

	g_type_class_add_private (nsp_class, sizeof (NMWimaxNspPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* properties */

	/**
	 * NMWimaxNsp:name:
	 *
	 * The name of the WiMAX NSP.
	 **/
	g_object_class_install_property
		(object_class, PROP_NAME,
		 g_param_spec_string (NM_WIMAX_NSP_NAME,
							  "Name",
							  "Name",
							  NULL,
							  G_PARAM_READABLE));

	/**
	 * NMWimaxNsp:signal-quality:
	 *
	 * The signal quality of the WiMAX NSP.
	 **/
	g_object_class_install_property
		(object_class, PROP_SIGNAL_QUALITY,
		 g_param_spec_uint (NM_WIMAX_NSP_SIGNAL_QUALITY,
		                    "Signal Quality",
		                    "Signal Quality",
		                    0, 100, 0,
		                    G_PARAM_READABLE));

	/**
	 * NMWimaxNsp:network-type:
	 *
	 * The network type of the WiMAX NSP.
	 **/
	g_object_class_install_property
		(object_class, PROP_NETWORK_TYPE,
		 g_param_spec_uint (NM_WIMAX_NSP_NETWORK_TYPE,
		                    "Network Type",
		                    "Network Type",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE));
}
