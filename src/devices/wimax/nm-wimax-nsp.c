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
 * Copyright (C) 2010 - 2012 Red Hat, Inc.
 * Copyright (C) 2009 Novell, Inc.
 */

#include "nm-wimax-nsp.h"
#include "NetworkManager.h"
#include "nm-dbus-manager.h"
#include "nm-setting-wimax.h"
#include "nm-wimax-nsp-glue.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMWimaxNsp, nm_wimax_nsp, G_TYPE_OBJECT)

enum {
	PROP_0,

	PROP_NAME,
	PROP_SIGNAL_QUALITY,
	PROP_NETWORK_TYPE,

	LAST_PROP
};

#define GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_WIMAX_NSP, NMWimaxNspPrivate))

typedef struct {
	char *dbus_path;

	char *name;
	guint32 signal_quality;
	NMWimaxNspNetworkType network_type;
} NMWimaxNspPrivate;

NMWimaxNsp *
nm_wimax_nsp_new (const char *name)
{
	g_return_val_if_fail (name != NULL, NULL);

	return NM_WIMAX_NSP (g_object_new (NM_TYPE_WIMAX_NSP,
									   NM_WIMAX_NSP_NAME, name,
									   NULL));
}

const char *
nm_wimax_nsp_get_name (NMWimaxNsp *self)
{
	g_return_val_if_fail (NM_IS_WIMAX_NSP (self), NULL);

	return GET_PRIVATE (self)->name;
}

guint32
nm_wimax_nsp_get_signal_quality (NMWimaxNsp *self)
{
	g_return_val_if_fail (NM_IS_WIMAX_NSP (self), 0);

	return GET_PRIVATE (self)->signal_quality;
}

NMWimaxNspNetworkType
nm_wimax_nsp_get_network_type (NMWimaxNsp *self)
{
	g_return_val_if_fail (NM_IS_WIMAX_NSP (self), 0);

	return GET_PRIVATE (self)->network_type;
}

void
nm_wimax_nsp_export_to_dbus (NMWimaxNsp *self)
{
	NMWimaxNspPrivate *priv;
	static guint32 counter = 0;

	g_return_if_fail (NM_IS_WIMAX_NSP (self));

	priv = GET_PRIVATE (self);

	g_return_if_fail (priv->dbus_path == NULL);

	priv->dbus_path = g_strdup_printf (NM_DBUS_PATH_WIMAX_NSP "/%d", counter++);
	nm_dbus_manager_register_object (nm_dbus_manager_get (), priv->dbus_path, self);
}

const char *
nm_wimax_nsp_get_dbus_path (NMWimaxNsp *self)
{
	g_return_val_if_fail (NM_IS_WIMAX_NSP (self), NULL);

	return GET_PRIVATE (self)->dbus_path;
}

gboolean
nm_wimax_nsp_check_compatible (NMWimaxNsp *self,
							   NMConnection *connection)
{
	NMWimaxNspPrivate *priv;
	NMSettingWimax *s_wimax;

	g_return_val_if_fail (NM_IS_WIMAX_NSP (self), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	priv = GET_PRIVATE (self);

	s_wimax = nm_connection_get_setting_wimax (connection);
	if (!s_wimax)
		return FALSE;

	return g_strcmp0 (nm_wimax_nsp_get_name (self), nm_setting_wimax_get_network_name (s_wimax)) == 0;
}

static void
nm_wimax_nsp_init (NMWimaxNsp *self)
{
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMWimaxNspPrivate *priv = GET_PRIVATE (object);
	guint32 quality;
	guint network_type;

	switch (prop_id) {
	case PROP_NAME:
		/* Construct only */
		priv->name = g_value_dup_string (value);
		break;
	case PROP_SIGNAL_QUALITY:
		quality = g_value_get_uint (value);
		if (quality != priv->signal_quality) {
			priv->signal_quality = CLAMP (quality, 0, 100);
			g_object_notify (object, NM_WIMAX_NSP_SIGNAL_QUALITY);
		}
		break;
	case PROP_NETWORK_TYPE:
		network_type = g_value_get_uint (value);
		if (network_type != priv->network_type) {
			priv->network_type = network_type;
			g_object_notify (object, NM_WIMAX_NSP_NETWORK_TYPE);
		}
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
	NMWimaxNsp *self = NM_WIMAX_NSP (object);

	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, nm_wimax_nsp_get_name (self));
		break;
	case PROP_SIGNAL_QUALITY:
		g_value_set_uint (value, nm_wimax_nsp_get_signal_quality (self));
		break;
	case PROP_NETWORK_TYPE:
		g_value_set_uint (value, nm_wimax_nsp_get_network_type (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
finalize (GObject *object)
{
	NMWimaxNspPrivate *priv = GET_PRIVATE (object);

	g_free (priv->name);
	g_free (priv->dbus_path);

	G_OBJECT_CLASS (nm_wimax_nsp_parent_class)->finalize (object);
}

static void
nm_wimax_nsp_class_init (NMWimaxNspClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMWimaxNspPrivate));

	/* Virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	g_object_class_install_property
		(object_class, PROP_NAME,
		 g_param_spec_string (NM_WIMAX_NSP_NAME,
							  "Name",
							  "Name",
							  NULL,
							  G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_SIGNAL_QUALITY,
		 g_param_spec_uint (NM_WIMAX_NSP_SIGNAL_QUALITY,
							"SignalQuality",
							"SignalQuality",
							0,
							100,
							0,
							G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_NETWORK_TYPE,
		 g_param_spec_uint (NM_WIMAX_NSP_NETWORK_TYPE,
		                    "NetworkType",
		                    "NetworkType",
		                    NM_WIMAX_NSP_NETWORK_TYPE_UNKNOWN,
		                    NM_WIMAX_NSP_NETWORK_TYPE_ROAMING_PARTNER,
		                    NM_WIMAX_NSP_NETWORK_TYPE_UNKNOWN,
		                    G_PARAM_READWRITE));

	nm_dbus_manager_register_exported_type (nm_dbus_manager_get (),
	                                        G_TYPE_FROM_CLASS (klass),
	                                        &dbus_glib_nm_wimax_nsp_object_info);
}
