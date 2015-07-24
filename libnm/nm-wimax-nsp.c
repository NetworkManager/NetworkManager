/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * Copyright 2011 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>

#include <nm-connection.h>
#include <nm-setting-connection.h>
#include <nm-setting-wimax.h>

#include "nm-glib.h"
#include "nm-wimax-nsp.h"
#include "nm-dbus-interface.h"
#include "nm-object-private.h"
#include "nm-enum-types.h"

G_DEFINE_TYPE (NMWimaxNsp, nm_wimax_nsp, NM_TYPE_OBJECT)

#define NM_WIMAX_NSP_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_WIMAX_NSP, NMWimaxNspPrivate))

typedef struct {
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
	g_return_val_if_fail (NM_IS_WIMAX_NSP (nsp), NULL);

	return NM_WIMAX_NSP_GET_PRIVATE (nsp)->name;
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
	g_return_val_if_fail (NM_IS_WIMAX_NSP (nsp), 0);

	return NM_WIMAX_NSP_GET_PRIVATE (nsp)->signal_quality;
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
	g_return_val_if_fail (NM_IS_WIMAX_NSP (nsp), NM_WIMAX_NSP_NETWORK_TYPE_UNKNOWN);

	return NM_WIMAX_NSP_GET_PRIVATE (nsp)->network_type;
}

/**
 * nm_wimax_nsp_connection_valid:
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
 * @connections: (element-type NMConnection): an array of #NMConnections to
 * filter
 *
 * Filters a given array of connections for a given #NMWimaxNsp object and
 * return connections which may be activated with the NSP.  Any returned
 * connections will match the @nsp's network name and other attributes.
 *
 * Returns: (transfer container) (element-type NMConnection): an array of
 * #NMConnections that could be activated with the given @nsp.  The array should
 * be freed with g_ptr_array_unref() when it is no longer required.
 **/
GPtrArray *
nm_wimax_nsp_filter_connections (NMWimaxNsp *nsp, const GPtrArray *connections)
{
	GPtrArray *filtered;
	int i;

	filtered = g_ptr_array_new_with_free_func (g_object_unref);
	for (i = 0; i < connections->len; i++) {
		NMConnection *candidate = connections->pdata[i];

		if (nm_wimax_nsp_connection_valid (nsp, candidate))
			g_ptr_array_add (filtered, g_object_ref (candidate));
	}

	return filtered;
}

/************************************************************/

static void
nm_wimax_nsp_init (NMWimaxNsp *nsp)
{
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
		g_value_set_enum (value, nm_wimax_nsp_get_network_type (nsp));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
init_dbus (NMObject *object)
{
	NMWimaxNspPrivate *priv = NM_WIMAX_NSP_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_WIMAX_NSP_NAME,           &priv->name },
		{ NM_WIMAX_NSP_SIGNAL_QUALITY, &priv->signal_quality },
		{ NM_WIMAX_NSP_NETWORK_TYPE,   &priv->network_type },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_wimax_nsp_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_WIMAX_NSP,
	                                property_info);
}

static void
nm_wimax_nsp_class_init (NMWimaxNspClass *nsp_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (nsp_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (nsp_class);

	g_type_class_add_private (nsp_class, sizeof (NMWimaxNspPrivate));

	_nm_object_class_add_interface (nm_object_class, NM_DBUS_INTERFACE_WIMAX_NSP);

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	nm_object_class->init_dbus = init_dbus;

	/* properties */

	/**
	 * NMWimaxNsp:name:
	 *
	 * The name of the WiMAX NSP.
	 **/
	g_object_class_install_property
		(object_class, PROP_NAME,
		 g_param_spec_string (NM_WIMAX_NSP_NAME, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMWimaxNsp:signal-quality:
	 *
	 * The signal quality of the WiMAX NSP.
	 **/
	g_object_class_install_property
		(object_class, PROP_SIGNAL_QUALITY,
		 g_param_spec_uint (NM_WIMAX_NSP_SIGNAL_QUALITY, "", "",
		                    0, 100, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMWimaxNsp:network-type:
	 *
	 * The network type of the WiMAX NSP.
	 **/
	g_object_class_install_property
		(object_class, PROP_NETWORK_TYPE,
		 g_param_spec_enum (NM_WIMAX_NSP_NETWORK_TYPE, "", "",
		                    NM_TYPE_WIMAX_NSP_NETWORK_TYPE,
		                    NM_WIMAX_NSP_NETWORK_TYPE_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));
}
