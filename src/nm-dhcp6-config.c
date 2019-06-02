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
 * Copyright (C) 2008 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-dhcp6-config.h"

#include "nm-dbus-interface.h"
#include "nm-utils.h"
#include "nm-dbus-object.h"
#include "nm-core-utils.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMDhcp6Config,
	PROP_OPTIONS,
);

typedef struct {
	GVariant *options;
} NMDhcp6ConfigPrivate;

struct _NMDhcp6Config {
	NMDBusObject parent;
	NMDhcp6ConfigPrivate _priv;
};

struct _NMDhcp6ConfigClass {
	NMDBusObjectClass parent;
};

G_DEFINE_TYPE (NMDhcp6Config, nm_dhcp6_config, NM_TYPE_DBUS_OBJECT)

#define NM_DHCP6_CONFIG_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDhcp6Config, NM_IS_DHCP6_CONFIG)

/*****************************************************************************/

void
nm_dhcp6_config_set_options (NMDhcp6Config *self,
                             GHashTable *options)
{
	NMDhcp6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (self);
	GVariant *val;

	g_return_if_fail (NM_IS_DHCP6_CONFIG (self));
	g_return_if_fail (options);

	val = nm_utils_strdict_to_variant (options);
	g_variant_unref (priv->options);
	priv->options = g_variant_ref_sink (val);
	_notify (self, PROP_OPTIONS);
}

const char *
nm_dhcp6_config_get_option (NMDhcp6Config *self, const char *key)
{
	NMDhcp6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (self);
	const char *value;

	g_return_val_if_fail (NM_IS_DHCP6_CONFIG (self), NULL);
	g_return_val_if_fail (key != NULL, NULL);

	if (g_variant_lookup (priv->options, key, "&s", &value))
		return value;
	else
		return NULL;
}

GVariant *
nm_dhcp6_config_get_options (NMDhcp6Config *self)
{
	g_return_val_if_fail (NM_IS_DHCP6_CONFIG (self), NULL);

	return g_variant_ref (NM_DHCP6_CONFIG_GET_PRIVATE (self)->options);
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDhcp6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE ((NMDhcp6Config *) object);

	switch (prop_id) {
	case PROP_OPTIONS:
		g_value_set_variant (value, priv->options);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_dhcp6_config_init (NMDhcp6Config *self)
{
	NMDhcp6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (self);

	priv->options = g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0);
	g_variant_ref_sink (priv->options);
}

NMDhcp6Config *
nm_dhcp6_config_new (void)
{
	return NM_DHCP6_CONFIG (g_object_new (NM_TYPE_DHCP6_CONFIG, NULL));
}

static void
finalize (GObject *object)
{
	NMDhcp6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE ((NMDhcp6Config *) object);

	g_variant_unref (priv->options);

	G_OBJECT_CLASS (nm_dhcp6_config_parent_class)->finalize (object);
}

static const NMDBusInterfaceInfoExtended interface_info_dhcp6_config = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_DHCP6_CONFIG,
		.signals = NM_DEFINE_GDBUS_SIGNAL_INFOS (
			&nm_signal_info_property_changed_legacy,
		),
		.properties = NM_DEFINE_GDBUS_PROPERTY_INFOS (
			NM_DEFINE_DBUS_PROPERTY_INFO_EXTENDED_READABLE_L ("Options", "a{sv}",  NM_DHCP6_CONFIG_OPTIONS),
		),
	),
	.legacy_property_changed = TRUE,
};

static void
nm_dhcp6_config_class_init (NMDhcp6ConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (config_class);

	object_class->get_property = get_property;
	object_class->finalize = finalize;

	dbus_object_class->export_path = NM_DBUS_EXPORT_PATH_NUMBERED (NM_DBUS_PATH"/DHCP6Config");
	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_dhcp6_config);
	dbus_object_class->export_on_construction = TRUE;

	obj_properties[PROP_OPTIONS] =
	     g_param_spec_variant (NM_DHCP6_CONFIG_OPTIONS, "", "",
	                           G_VARIANT_TYPE ("a{sv}"),
	                           NULL,
	                           G_PARAM_READABLE |
	                           G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
