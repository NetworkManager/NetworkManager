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
 * Copyright 2007 - 2011 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#include "config.h"

#include <string.h>
#include <glib/gi18n-lib.h>
#include <gio/gio.h>

#include "nm-setting.h"
#include "nm-setting-private.h"
#include "nm-utils.h"
#include "nm-core-internal.h"
#include "nm-utils-private.h"
#include "nm-property-compare.h"

#include "nm-setting-connection.h"
#include "nm-setting-bond.h"
#include "nm-setting-bridge.h"
#include "nm-setting-bridge-port.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-team.h"
#include "nm-setting-team-port.h"
#include "nm-setting-vpn.h"

/**
 * SECTION:nm-setting
 * @short_description: Describes related configuration information
 *
 * Each #NMSetting contains properties that describe configuration that applies
 * to a specific network layer (like IPv4 or IPv6 configuration) or device type
 * (like Ethernet, or Wi-Fi).  A collection of individual settings together
 * make up an #NMConnection. Each property is strongly typed and usually has
 * a number of allowed values.  See each #NMSetting subclass for a description
 * of properties and allowed values.
 */

G_DEFINE_ABSTRACT_TYPE (NMSetting, nm_setting, G_TYPE_OBJECT)

#define NM_SETTING_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING, NMSettingPrivate))

typedef struct {
	const char *name;
	GType type;
	guint32 priority;
} SettingInfo;

typedef struct {
	const SettingInfo *info;
} NMSettingPrivate;

enum {
	PROP_0,
	PROP_NAME,

	PROP_LAST
};

/*************************************************************/

static GHashTable *registered_settings = NULL;
static GHashTable *registered_settings_by_type = NULL;

static gboolean
_nm_gtype_equal (gconstpointer v1, gconstpointer v2)
{
	return *((const GType *) v1) == *((const GType *) v2);
}
static guint
_nm_gtype_hash (gconstpointer v)
{
	return *((const GType *) v);
}

static void
_ensure_registered (void)
{
	if (G_UNLIKELY (registered_settings == NULL)) {
#if !GLIB_CHECK_VERSION (2, 35, 0)
		g_type_init ();
#endif
		registered_settings = g_hash_table_new (g_str_hash, g_str_equal);
		registered_settings_by_type = g_hash_table_new (_nm_gtype_hash, _nm_gtype_equal);
	}
}

static void __attribute__((constructor))
_ensure_registered_constructor (void)
{
	_ensure_registered ();
}

#define _ensure_setting_info(self, priv) \
	G_STMT_START { \
		NMSettingPrivate *_priv_esi = (priv); \
		if (G_UNLIKELY (!_priv_esi->info)) { \
			_priv_esi->info = _nm_setting_lookup_setting_by_type (G_OBJECT_TYPE (self)); \
			g_assert (_priv_esi->info); \
		} \
	} G_STMT_END

/*************************************************************/

/*
 * _nm_register_setting:
 * @name: the name of the #NMSetting object to register
 * @type: the #GType of the #NMSetting
 * @priority: the sort priority of the setting, see below
 *
 * INTERNAL ONLY: registers a setting's internal properties with libnm.
 *
 * A setting's priority should roughly follow the OSI layer model, but it also
 * controls which settings get asked for secrets first.  Thus settings which
 * relate to things that must be working first, like hardware, should get a
 * higher priority than things which layer on top of the hardware.  For example,
 * the GSM/CDMA settings should provide secrets before the PPP setting does,
 * because a PIN is required to unlock the device before PPP can even start.
 * Even settings without secrets should be assigned the right priority.
 *
 * 0: reserved for the Connection setting
 *
 * 1: hardware-related settings like Ethernet, Wi-Fi, InfiniBand, Bridge, etc.
 * These priority 1 settings are also "base types", which means that at least
 * one of them is required for the connection to be valid, and their name is
 * valid in the 'type' property of the Connection setting.
 *
 * 2: hardware-related auxiliary settings that require a base setting to be
 * successful first, like Wi-Fi security, 802.1x, etc.
 *
 * 3: hardware-independent settings that are required before IP connectivity
 * can be established, like PPP, PPPoE, etc.
 *
 * 4: IP-level stuff
 */
void
(_nm_register_setting) (const char *name,
                        const GType type,
                        const guint32 priority)
{
	SettingInfo *info;

	g_return_if_fail (name != NULL && *name);
	g_return_if_fail (type != G_TYPE_INVALID);
	g_return_if_fail (type != G_TYPE_NONE);
	g_return_if_fail (priority <= 4);

	_ensure_registered ();

	if (G_LIKELY ((info = g_hash_table_lookup (registered_settings, name)))) {
		g_return_if_fail (info->type == type);
		g_return_if_fail (info->priority == priority);
		g_return_if_fail (g_strcmp0 (info->name, name) == 0);
		return;
	}
	g_return_if_fail (g_hash_table_lookup (registered_settings_by_type, &type) == NULL);

	if (priority == 0)
		g_assert_cmpstr (name, ==, NM_SETTING_CONNECTION_SETTING_NAME);

	info = g_slice_new0 (SettingInfo);
	info->type = type;
	info->priority = priority;
	info->name = name;
	g_hash_table_insert (registered_settings, (void *) info->name, info);
	g_hash_table_insert (registered_settings_by_type, &info->type, info);
}

static const SettingInfo *
_nm_setting_lookup_setting_by_type (GType type)
{
	_ensure_registered ();
	return g_hash_table_lookup (registered_settings_by_type, &type);
}

static guint32
_get_setting_type_priority (GType type)
{
	const SettingInfo *info;

	g_return_val_if_fail (g_type_is_a (type, NM_TYPE_SETTING), G_MAXUINT32);

	info = _nm_setting_lookup_setting_by_type (type);
	return info->priority;
}

guint32
_nm_setting_get_setting_priority (NMSetting *setting)
{
	NMSettingPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING (setting), G_MAXUINT32);
	priv = NM_SETTING_GET_PRIVATE (setting);
	_ensure_setting_info (setting, priv);
	return priv->info->priority;
}

gboolean
_nm_setting_type_is_base_type (GType type)
{
	/* Historical oddity: PPPoE is a base-type even though it's not
	 * priority 1.  It needs to be sorted *after* lower-level stuff like
	 * Wi-Fi security or 802.1x for secrets, but it's still allowed as a
	 * base type.
	 */
	return _get_setting_type_priority (type) == 1 || (type == NM_TYPE_SETTING_PPPOE);
}

gboolean
_nm_setting_is_base_type (NMSetting *setting)
{
	return _nm_setting_type_is_base_type (G_OBJECT_TYPE (setting));
}

/**
 * nm_setting_lookup_type:
 * @name: a setting name
 *
 * Returns the #GType of the setting's class for a given setting name.
 *
 * Returns: the #GType of the setting's class, or %G_TYPE_INVALID if
 *   @name is not recognized.
 **/
GType
nm_setting_lookup_type (const char *name)
{
	SettingInfo *info;

	g_return_val_if_fail (name != NULL, G_TYPE_INVALID);

	_ensure_registered ();

	info = g_hash_table_lookup (registered_settings, name);
	return info ? info->type : G_TYPE_INVALID;
}

gint
_nm_setting_compare_priority (gconstpointer a, gconstpointer b)
{
	guint32 prio_a, prio_b;

	prio_a = _nm_setting_get_setting_priority ((NMSetting *) a);
	prio_b = _nm_setting_get_setting_priority ((NMSetting *) b);

	if (prio_a < prio_b)
		return -1;
	else if (prio_a == prio_b)
		return 0;
	return 1;
}

/*************************************************************/

gboolean
_nm_setting_slave_type_is_valid (const char *slave_type, const char **out_port_type)
{
	const char *port_type = NULL;
	gboolean found = TRUE;

	if (!slave_type)
		found = FALSE;
	else if (!strcmp (slave_type, NM_SETTING_BOND_SETTING_NAME))
		;
	else if (!strcmp (slave_type, NM_SETTING_BRIDGE_SETTING_NAME))
		port_type = NM_SETTING_BRIDGE_PORT_SETTING_NAME;
	else if (!strcmp (slave_type, NM_SETTING_TEAM_SETTING_NAME))
		port_type = NM_SETTING_TEAM_PORT_SETTING_NAME;
	else
		found = FALSE;

	if (out_port_type)
		*out_port_type = port_type;
	return found;
}

/*************************************************************/

typedef struct {
	const char *name;
	GParamSpec *param_spec;
	const GVariantType *dbus_type;

	NMSettingPropertyGetFunc get_func;
	NMSettingPropertySynthFunc synth_func;
	NMSettingPropertySetFunc set_func;
	NMSettingPropertyNotSetFunc not_set_func;

	NMSettingPropertyTransformToFunc to_dbus;
	NMSettingPropertyTransformFromFunc from_dbus;
} NMSettingProperty;

static GQuark setting_property_overrides_quark;
static GQuark setting_properties_quark;

static NMSettingProperty *
find_property (GArray *properties, const char *name)
{
	NMSettingProperty *property;
	int i;

	if (!properties)
		return NULL;

	for (i = 0; i < properties->len; i++) {
		property = &g_array_index (properties, NMSettingProperty, i);
		if (strcmp (name, property->name) == 0)
			return property;
	}

	return NULL;
}

static void
add_property_override (NMSettingClass *setting_class,
                       const char *property_name,
                       GParamSpec *param_spec,
                       const GVariantType *dbus_type,
                       NMSettingPropertyGetFunc get_func,
                       NMSettingPropertySynthFunc synth_func,
                       NMSettingPropertySetFunc set_func,
                       NMSettingPropertyNotSetFunc not_set_func,
                       NMSettingPropertyTransformToFunc to_dbus,
                       NMSettingPropertyTransformFromFunc from_dbus)
{
	GType setting_type = G_TYPE_FROM_CLASS (setting_class);
	GArray *overrides;
	NMSettingProperty override;

	g_return_if_fail (g_type_get_qdata (setting_type, setting_properties_quark) == NULL);

	memset (&override, 0, sizeof (override));
	override.name = property_name;
	override.param_spec = param_spec;
	override.dbus_type = dbus_type;
	override.get_func = get_func;
	override.synth_func = synth_func;
	override.set_func = set_func;
	override.not_set_func = not_set_func;
	override.to_dbus = to_dbus;
	override.from_dbus = from_dbus;

	overrides = g_type_get_qdata (setting_type, setting_property_overrides_quark);
	if (!overrides) {
		overrides = g_array_new (FALSE, FALSE, sizeof (NMSettingProperty));
		g_type_set_qdata (setting_type, setting_property_overrides_quark, overrides);
	}
	g_return_if_fail (find_property (overrides, property_name) == NULL);

	g_array_append_val (overrides, override);
}

/**
 * _nm_setting_class_add_dbus_only_property:
 * @setting_class: the setting class
 * @property_name: the name of the property to override
 * @dbus_type: the type of the property (in its D-Bus representation)
 * @synth_func: (allow-none): function to call to synthesize a value for the property
 * @set_func: (allow-none): function to call to set the value of the property
 *
 * Registers a property named @property_name, which will be used in the D-Bus
 * serialization of objects of @setting_class, but which does not correspond to
 * a #GObject property.
 *
 * When serializing a setting to D-Bus, @synth_func will be called to synthesize
 * a value for the property. (If it returns %NULL, no value will be added to the
 * serialization. If @synth_func is %NULL, the property will always be omitted
 * in the serialization.)
 *
 * When deserializing a D-Bus representation into a setting, if @property_name
 * is present, then @set_func will be called to set it. (If @set_func is %NULL
 * then the property will be ignored when deserializing.)
 */
void
_nm_setting_class_add_dbus_only_property (NMSettingClass *setting_class,
                                          const char *property_name,
                                          const GVariantType *dbus_type,
                                          NMSettingPropertySynthFunc synth_func,
                                          NMSettingPropertySetFunc set_func)
{
	g_return_if_fail (NM_IS_SETTING_CLASS (setting_class));
	g_return_if_fail (property_name != NULL);

	/* Must not match any GObject property. */
	g_return_if_fail (!g_object_class_find_property (G_OBJECT_CLASS (setting_class), property_name));

	add_property_override (setting_class,
	                       property_name, NULL, dbus_type,
	                       NULL, synth_func, set_func, NULL,
	                       NULL, NULL);
}

/**
 * _nm_setting_class_override_property:
 * @setting_class: the setting class
 * @property_name: the name of the property to override
 * @dbus_type: the type of the property (in its D-Bus representation)
 * @get_func: (allow-none): function to call to get the value of the property
 * @set_func: (allow-none): function to call to set the value of the property
 * @not_set_func: (allow-none): function to call to indicate the property was not set
 *
 * Overrides the D-Bus representation of the #GObject property named
 * @property_name on @setting_class.
 *
 * When serializing a setting to D-Bus, if @get_func is non-%NULL, then it will
 * be called to get the property's value. If it returns a #GVariant, the
 * property will be added to the hash, and if it returns %NULL, the property
 * will be omitted. (If @get_func is %NULL, the property will be read normally
 * with g_object_get_property(), and added to the hash if it is not the default
 * value.)
 *
 * When deserializing a D-Bus representation into a setting, if @property_name
 * is present, then @set_func will be called to set it. (If @set_func is %NULL
 * then the property will be set normally with g_object_set_property().)
 *
 * If @not_set_func is non-%NULL, then it will be called when deserializing a
 * representation that does NOT contain @property_name. This can be used, eg, if
 * a new property needs to be initialized from some older deprecated property
 * when it is not present.
 */
void
_nm_setting_class_override_property (NMSettingClass *setting_class,
                                     const char *property_name,
                                     const GVariantType *dbus_type,
                                     NMSettingPropertyGetFunc get_func,
                                     NMSettingPropertySetFunc set_func,
                                     NMSettingPropertyNotSetFunc not_set_func)
{
	GParamSpec *param_spec;

	param_spec = g_object_class_find_property (G_OBJECT_CLASS (setting_class), property_name);
	g_return_if_fail (param_spec != NULL);

	add_property_override (setting_class,
	                       property_name, param_spec, dbus_type,
	                       get_func, NULL, set_func, not_set_func,
	                       NULL, NULL);
}

/**
 * _nm_setting_class_transform_property:
 * @setting_class: the setting class
 * @property: the name of the property to transform
 * @dbus_type: the type of the property (in its D-Bus representation)
 * @to_dbus: function to convert from object to D-Bus format
 * @from_dbus: function to convert from D-Bus to object format
 *
 * Indicates that @property on @setting_class does not have the same format as
 * its corresponding D-Bus representation, and so must be transformed when
 * serializing/deserializing.
 *
 * The transformation will also be used by nm_setting_compare(), meaning that
 * the underlying object property does not need to be of a type that
 * nm_property_compare() recognizes, as long as it recognizes @dbus_type.
 */
void
_nm_setting_class_transform_property (NMSettingClass *setting_class,
                                      const char *property,
                                      const GVariantType *dbus_type,
                                      NMSettingPropertyTransformToFunc to_dbus,
                                      NMSettingPropertyTransformFromFunc from_dbus)
{
	GParamSpec *param_spec;

	param_spec = g_object_class_find_property (G_OBJECT_CLASS (setting_class), property);
	g_return_if_fail (param_spec != NULL);

	add_property_override (setting_class,
	                       property, param_spec, dbus_type,
	                       NULL, NULL, NULL, NULL,
	                       to_dbus, from_dbus);
}

gboolean
_nm_setting_use_legacy_property (NMSetting *setting,
                                 GVariant *connection_dict,
                                 const char *legacy_property,
                                 const char *new_property)
{
	GVariant *setting_dict, *value;

	setting_dict = g_variant_lookup_value (connection_dict, nm_setting_get_name (NM_SETTING (setting)), NM_VARIANT_TYPE_SETTING);
	g_return_val_if_fail (setting_dict != NULL, FALSE);

	/* If the new property isn't set, we have to use the legacy property. */
	value = g_variant_lookup_value (setting_dict, new_property, NULL);
	if (!value) {
		g_variant_unref (setting_dict);
		return TRUE;
	}
	g_variant_unref (value);

	/* Otherwise, clients always prefer new properties sent from the daemon. */
	if (!_nm_utils_is_manager_process) {
		g_variant_unref (setting_dict);
		return FALSE;
	}

	/* The daemon prefers the legacy property if it exists. */
	value = g_variant_lookup_value (setting_dict, legacy_property, NULL);
	g_variant_unref (setting_dict);

	if (value) {
		g_variant_unref (value);
		return TRUE;
	} else
		return FALSE;
}

static GArray *
nm_setting_class_ensure_properties (NMSettingClass *setting_class)
{
	GType type = G_TYPE_FROM_CLASS (setting_class), otype;
	NMSettingProperty property, *override;
	GArray *overrides, *type_overrides, *properties;
	GParamSpec **property_specs;
	guint n_property_specs, i;

	properties = g_type_get_qdata (type, setting_properties_quark);
	if (properties)
		return properties;

	/* Build overrides array from @setting_class and its superclasses */
	overrides = g_array_new (FALSE, FALSE, sizeof (NMSettingProperty));
	for (otype = type; otype != G_TYPE_OBJECT; otype = g_type_parent (otype)) {
		type_overrides = g_type_get_qdata (otype, setting_property_overrides_quark);
		if (type_overrides)
			g_array_append_vals (overrides, (NMSettingProperty *)type_overrides->data, type_overrides->len);
	}

	/* Build the properties array from the GParamSpecs, obeying overrides */
	properties = g_array_new (FALSE, FALSE, sizeof (NMSettingProperty));

	property_specs = g_object_class_list_properties (G_OBJECT_CLASS (setting_class),
	                                                 &n_property_specs);
	for (i = 0; i < n_property_specs; i++) {
		override = find_property (overrides, property_specs[i]->name);
		if (override)
			property = *override;
		else {
			memset (&property, 0, sizeof (property));
			property.name = property_specs[i]->name;
			property.param_spec = property_specs[i];
		}
		g_array_append_val (properties, property);
	}
	g_free (property_specs);

	/* Add any remaining overrides not corresponding to GObject properties */
	for (i = 0; i < overrides->len; i++) {
		override = &g_array_index (overrides, NMSettingProperty, i);
		if (!g_object_class_find_property (G_OBJECT_CLASS (setting_class), override->name))
			g_array_append_val (properties, *override);
	}
	g_array_unref (overrides);

	g_type_set_qdata (type, setting_properties_quark, properties);
	return properties;
}

static const NMSettingProperty *
nm_setting_class_get_properties (NMSettingClass *setting_class, guint *n_properties)
{
	GArray *properties;

	properties = nm_setting_class_ensure_properties (setting_class);

	*n_properties = properties->len;
	return (NMSettingProperty *) properties->data;
}

static const NMSettingProperty *
nm_setting_class_find_property (NMSettingClass *setting_class, const char *property_name)
{
	GArray *properties;

	properties = nm_setting_class_ensure_properties (setting_class);
	return find_property (properties, property_name);
}

/*************************************************************/

static const GVariantType *
variant_type_for_gtype (GType type)
{
	if (type == G_TYPE_BOOLEAN)
		return G_VARIANT_TYPE_BOOLEAN;
	else if (type == G_TYPE_UCHAR)
		return G_VARIANT_TYPE_BYTE;
	else if (type == G_TYPE_INT)
		return G_VARIANT_TYPE_INT32;
	else if (type == G_TYPE_UINT)
		return G_VARIANT_TYPE_UINT32;
	else if (type == G_TYPE_INT64)
		return G_VARIANT_TYPE_INT64;
	else if (type == G_TYPE_UINT64)
		return G_VARIANT_TYPE_UINT64;
	else if (type == G_TYPE_STRING)
		return G_VARIANT_TYPE_STRING;
	else if (type == G_TYPE_DOUBLE)
		return G_VARIANT_TYPE_DOUBLE;
	else if (type == G_TYPE_STRV)
		return G_VARIANT_TYPE_STRING_ARRAY;
	else if (type == G_TYPE_BYTES)
		return G_VARIANT_TYPE_BYTESTRING;
	else if (g_type_is_a (type, G_TYPE_ENUM))
		return G_VARIANT_TYPE_INT32;
	else if (g_type_is_a (type, G_TYPE_FLAGS))
		return G_VARIANT_TYPE_UINT32;
	else
		g_assert_not_reached ();
}

static GVariant *
get_property_for_dbus (NMSetting *setting,
                       const NMSettingProperty *property,
                       gboolean ignore_default)
{
	GValue prop_value = { 0, };
	GVariant *dbus_value;

	if (property->get_func)
		return property->get_func (setting, property->name);
	else
		g_return_val_if_fail (property->param_spec != NULL, NULL);

	g_value_init (&prop_value, property->param_spec->value_type);
	g_object_get_property (G_OBJECT (setting), property->param_spec->name, &prop_value);

	if (ignore_default && g_param_value_defaults (property->param_spec, &prop_value)) {
		g_value_unset (&prop_value);
		return NULL;
	}

	if (property->to_dbus)
		dbus_value = property->to_dbus (&prop_value);
	else if (property->dbus_type)
		dbus_value = g_dbus_gvalue_to_gvariant (&prop_value, property->dbus_type);
	else if (g_type_is_a (prop_value.g_type, G_TYPE_ENUM))
		dbus_value = g_variant_new_int32 (g_value_get_enum (&prop_value));
	else if (g_type_is_a (prop_value.g_type, G_TYPE_FLAGS))
		dbus_value = g_variant_new_uint32 (g_value_get_flags (&prop_value));
	else if (prop_value.g_type == G_TYPE_BYTES)
		dbus_value = _nm_utils_bytes_to_dbus (&prop_value);
	else
		dbus_value = g_dbus_gvalue_to_gvariant (&prop_value, variant_type_for_gtype (prop_value.g_type));
	g_value_unset (&prop_value);

	return dbus_value;
}

static gboolean
set_property_from_dbus (const NMSettingProperty *property,
                        GVariant *src_value,
                        GValue *dst_value)
{
	g_return_val_if_fail (property->param_spec != NULL, FALSE);

	if (property->from_dbus) {
		if (!g_variant_type_equal (g_variant_get_type (src_value), property->dbus_type))
			return FALSE;

		property->from_dbus (src_value, dst_value);
	} else if (dst_value->g_type == G_TYPE_BYTES) {
		if (!g_variant_is_of_type (src_value, G_VARIANT_TYPE_BYTESTRING))
			return FALSE;

		_nm_utils_bytes_from_dbus (src_value, dst_value);
	} else {
		GValue tmp = G_VALUE_INIT;

		g_dbus_gvariant_to_gvalue (src_value, &tmp);
		if (G_VALUE_TYPE (&tmp) == G_VALUE_TYPE (dst_value))
			*dst_value = tmp;
		else {
			gboolean success;

			success = g_value_transform (&tmp, dst_value);
			g_value_unset (&tmp);
			if (!success)
				return FALSE;
		}
	}

	return TRUE;
}


/**
 * _nm_setting_to_dbus:
 * @setting: the #NMSetting
 * @connection: the #NMConnection containing @setting
 * @flags: hash flags, e.g. %NM_CONNECTION_SERIALIZE_ALL
 *
 * Converts the #NMSetting into a #GVariant of type #NM_VARIANT_TYPE_SETTING
 * mapping each setting property name to a value describing that property,
 * suitable for marshalling over D-Bus or serializing.
 *
 * Returns: (transfer none): a new floating #GVariant describing the setting's
 * properties
 **/
GVariant *
_nm_setting_to_dbus (NMSetting *setting, NMConnection *connection, NMConnectionSerializationFlags flags)
{
	GVariantBuilder builder;
	GVariant *dbus_value;
	const NMSettingProperty *properties;
	guint n_properties, i;

	g_return_val_if_fail (NM_IS_SETTING (setting), NULL);

	properties = nm_setting_class_get_properties (NM_SETTING_GET_CLASS (setting), &n_properties);

	g_variant_builder_init (&builder, NM_VARIANT_TYPE_SETTING);

	for (i = 0; i < n_properties; i++) {
		const NMSettingProperty *property = &properties[i];
		GParamSpec *prop_spec = property->param_spec;

		if (!prop_spec && !property->synth_func) {
			/* D-Bus-only property with no synth_func, so we skip it. */
			continue;
		}

		if (prop_spec && !(prop_spec->flags & G_PARAM_WRITABLE))
			continue;

		if (   prop_spec && (prop_spec->flags & NM_SETTING_PARAM_LEGACY)
		    && !_nm_utils_is_manager_process)
			continue;

		if (   (flags & NM_CONNECTION_SERIALIZE_NO_SECRETS)
		    && (prop_spec && (prop_spec->flags & NM_SETTING_PARAM_SECRET)))
			continue;

		if (   (flags & NM_CONNECTION_SERIALIZE_ONLY_SECRETS)
		    && !(prop_spec && (prop_spec->flags & NM_SETTING_PARAM_SECRET)))
			continue;

		if (property->synth_func)
			dbus_value = property->synth_func (setting, connection, property->name);
		else
			dbus_value = get_property_for_dbus (setting, property, TRUE);
		if (dbus_value) {
			/* Allow dbus_value to be either floating or not. */
			g_variant_take_ref (dbus_value);

			g_variant_builder_add (&builder, "{sv}", property->name, dbus_value);
			g_variant_unref (dbus_value);
		}
	}

	return g_variant_builder_end (&builder);
}

/**
 * _nm_setting_new_from_dbus:
 * @setting_type: the #NMSetting type which the hash contains properties for
 * @setting_dict: the #GVariant containing an %NM_VARIANT_TYPE_SETTING dictionary
 *   mapping property names to values
 * @connection_dict: the #GVariant containing an %NM_VARIANT_TYPE_CONNECTION
 *   dictionary mapping setting names to dictionaries.
 * @error: location to store error, or %NULL
 *
 * Creates a new #NMSetting object and populates that object with the properties
 * contained in @setting_dict, using each key as the property to set, and each
 * value as the value to set that property to.  Setting properties are strongly
 * typed, thus the #GVariantType of the dict value must be correct.  See the
 * documentation on each #NMSetting object subclass for the correct property
 * names and value types.
 *
 * Returns: a new #NMSetting object populated with the properties from the
 * hash table, or %NULL if @setting_hash could not be deserialized.
 **/
NMSetting *
_nm_setting_new_from_dbus (GType setting_type,
                           GVariant *setting_dict,
                           GVariant *connection_dict,
                           GError **error)
{
	NMSetting *setting;
	const NMSettingProperty *properties;
	guint n_properties;
	guint i;

	g_return_val_if_fail (G_TYPE_IS_INSTANTIATABLE (setting_type), NULL);
	g_return_val_if_fail (g_variant_is_of_type (setting_dict, NM_VARIANT_TYPE_SETTING), NULL);

	/* connection_dict is not technically optional, but some tests in test-general
	 * don't bother with it in cases where they know it's not needed.
	 */
	if (connection_dict)
		g_return_val_if_fail (g_variant_is_of_type (connection_dict, NM_VARIANT_TYPE_CONNECTION), NULL);

	/* Build the setting object from the properties we know about; we assume
	 * that any propreties in @setting_dict that we don't know about can
	 * either be ignored or else has a backward-compatibility equivalent
	 * that we do know about.
	 */
	setting = (NMSetting *) g_object_new (setting_type, NULL);

	properties = nm_setting_class_get_properties (NM_SETTING_GET_CLASS (setting), &n_properties);
	for (i = 0; i < n_properties; i++) {
		const NMSettingProperty *property = &properties[i];
		GVariant *value;

		if (property->param_spec && !(property->param_spec->flags & G_PARAM_WRITABLE))
			continue;

		value = g_variant_lookup_value (setting_dict, property->name, NULL);

		if (value && property->set_func) {
			if (!g_variant_type_equal (g_variant_get_type (value), property->dbus_type)) {
			property_type_error:
				g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("can't set property of type '%s' from value of type '%s'"),
				             property->dbus_type ?
				                 g_variant_type_peek_string (property->dbus_type) :
				                 property->param_spec ?
				                     g_type_name (property->param_spec->value_type) : "(unknown)",
				             g_variant_get_type_string (value));
				g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), property->name);

				g_variant_unref (value);
				g_object_unref (setting);
				return NULL;
			}

			property->set_func (setting,
			                    connection_dict,
			                    property->name,
			                    value);
		} else if (!value && property->not_set_func) {
			property->not_set_func (setting,
			                        connection_dict,
			                        property->name);
		} else if (value && property->param_spec) {
			GValue object_value = { 0, };

			g_value_init (&object_value, property->param_spec->value_type);
			if (!set_property_from_dbus (property, value, &object_value))
				goto property_type_error;

			g_object_set_property (G_OBJECT (setting), property->param_spec->name, &object_value);
			g_value_unset (&object_value);
		}

		if (value)
			g_variant_unref (value);
	}

	return setting;
}

/**
 * nm_setting_get_dbus_property_type:
 * @setting: an #NMSetting
 * @property_name: the property of @setting to get the type of
 *
 * Gets the D-Bus marshalling type of a property. @property_name is a D-Bus
 * property name, which may not necessarily be a #GObject property.
 *
 * Returns: the D-Bus marshalling type of @property on @setting.
 */
const GVariantType *
nm_setting_get_dbus_property_type (NMSetting *setting,
                                   const char *property_name)
{
	const NMSettingProperty *property;

	g_return_val_if_fail (NM_IS_SETTING (setting), NULL);
	g_return_val_if_fail (property_name != NULL, NULL);

	property = nm_setting_class_find_property (NM_SETTING_GET_CLASS (setting), property_name);
	g_return_val_if_fail (property != NULL, NULL);

	if (property->dbus_type)
		return property->dbus_type;
	else
		return variant_type_for_gtype (property->param_spec->value_type);
}

gboolean
_nm_setting_get_property (NMSetting *setting, const char *property_name, GValue *value)
{
	GParamSpec *prop_spec;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	g_return_val_if_fail (property_name, FALSE);
	g_return_val_if_fail (value, FALSE);

	prop_spec = g_object_class_find_property (G_OBJECT_GET_CLASS (setting), property_name);

	if (!prop_spec) {
		g_value_unset (value);
		return FALSE;
	}

	g_value_init (value, prop_spec->value_type);
	g_object_get_property (G_OBJECT (setting), property_name, value);
	return TRUE;
}

static void
duplicate_setting (NMSetting *setting,
                   const char *name,
                   const GValue *value,
                   GParamFlags flags,
                   gpointer user_data)
{
	if ((flags & (G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY)) == G_PARAM_WRITABLE)
		g_object_set_property (G_OBJECT (user_data), name, value);
}

/**
 * nm_setting_duplicate:
 * @setting: the #NMSetting to duplicate
 *
 * Duplicates a #NMSetting.
 *
 * Returns: (transfer full): a new #NMSetting containing the same properties and values as the
 * source #NMSetting
 **/
NMSetting *
nm_setting_duplicate (NMSetting *setting)
{
	GObject *dup;

	g_return_val_if_fail (NM_IS_SETTING (setting), NULL);

	dup = g_object_new (G_OBJECT_TYPE (setting), NULL);

	g_object_freeze_notify (dup);
	nm_setting_enumerate_values (setting, duplicate_setting, dup);
	g_object_thaw_notify (dup);

	return NM_SETTING (dup);
}

/**
 * nm_setting_get_name:
 * @setting: the #NMSetting
 *
 * Returns the type name of the #NMSetting object
 *
 * Returns: a string containing the type name of the #NMSetting object,
 * like 'ppp' or 'wireless' or 'wired'.
 **/
const char *
nm_setting_get_name (NMSetting *setting)
{
	NMSettingPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING (setting), NULL);
	priv = NM_SETTING_GET_PRIVATE (setting);
	_ensure_setting_info (setting, priv);
	return priv->info->name;
}

/**
 * nm_setting_verify:
 * @setting: the #NMSetting to verify
 * @connection: (allow-none): the #NMConnection that @setting came from, or
 *   %NULL if @setting is being verified in isolation.
 * @error: location to store error, or %NULL
 *
 * Validates the setting.  Each setting's properties have allowed values, and
 * some are dependent on other values (hence the need for @connection).  The
 * returned #GError contains information about which property of the setting
 * failed validation, and in what way that property failed validation.
 *
 * Returns: %TRUE if the setting is valid, %FALSE if it is not
 **/
gboolean
nm_setting_verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingVerifyResult result = _nm_setting_verify (setting, connection, error);

	if (result == NM_SETTING_VERIFY_NORMALIZABLE)
		g_clear_error (error);

	return result == NM_SETTING_VERIFY_SUCCESS || result == NM_SETTING_VERIFY_NORMALIZABLE;
}

NMSettingVerifyResult
_nm_setting_verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	g_return_val_if_fail (NM_IS_SETTING (setting), NM_SETTING_VERIFY_ERROR);
	g_return_val_if_fail (!connection || NM_IS_CONNECTION (connection), NM_SETTING_VERIFY_ERROR);
	g_return_val_if_fail (!error || *error == NULL, NM_SETTING_VERIFY_ERROR);

	if (NM_SETTING_GET_CLASS (setting)->verify)
		return NM_SETTING_GET_CLASS (setting)->verify (setting, connection, error);

	return NM_SETTING_VERIFY_SUCCESS;
}

static gboolean
compare_property (NMSetting *setting,
                  NMSetting *other,
                  const GParamSpec *prop_spec,
                  NMSettingCompareFlags flags)
{
	const NMSettingProperty *property;
	GVariant *value1, *value2;
	int cmp;

	/* Handle compare flags */
	if (prop_spec->flags & NM_SETTING_PARAM_SECRET) {
		NMSettingSecretFlags a_secret_flags = NM_SETTING_SECRET_FLAG_NONE;
		NMSettingSecretFlags b_secret_flags = NM_SETTING_SECRET_FLAG_NONE;

		g_return_val_if_fail (!NM_IS_SETTING_VPN (setting), FALSE);

		if (!nm_setting_get_secret_flags (setting, prop_spec->name, &a_secret_flags, NULL))
			g_return_val_if_reached (FALSE);
		if (!nm_setting_get_secret_flags (other, prop_spec->name, &b_secret_flags, NULL))
			g_return_val_if_reached (FALSE);

		/* If the secret flags aren't the same the settings aren't the same */
		if (a_secret_flags != b_secret_flags)
			return FALSE;

		/* Check for various secret flags that might cause us to ignore comparing
		 * this property.
		 */
		if (   (flags & NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS)
		    && (a_secret_flags & NM_SETTING_SECRET_FLAG_AGENT_OWNED))
			return TRUE;

		if (   (flags & NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS)
		    && (a_secret_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))
			return TRUE;
	}

	property = nm_setting_class_find_property (NM_SETTING_GET_CLASS (setting), prop_spec->name);
	g_return_val_if_fail (property != NULL, FALSE);

	value1 = get_property_for_dbus (setting, property, FALSE);
	value2 = get_property_for_dbus (other, property, FALSE);

	cmp = nm_property_compare (value1, value2);

	g_variant_unref (value1);
	g_variant_unref (value2);

	return cmp == 0;
}

/**
 * nm_setting_compare:
 * @a: a #NMSetting
 * @b: a second #NMSetting to compare with the first
 * @flags: compare flags, e.g. %NM_SETTING_COMPARE_FLAG_EXACT
 *
 * Compares two #NMSetting objects for similarity, with comparison behavior
 * modified by a set of flags.  See the documentation for #NMSettingCompareFlags
 * for a description of each flag's behavior.
 *
 * Returns: %TRUE if the comparison succeeds, %FALSE if it does not
 **/
gboolean
nm_setting_compare (NMSetting *a,
                    NMSetting *b,
                    NMSettingCompareFlags flags)
{
	GParamSpec **property_specs;
	guint n_property_specs;
	gint same = TRUE;
	guint i;

	g_return_val_if_fail (NM_IS_SETTING (a), FALSE);
	g_return_val_if_fail (NM_IS_SETTING (b), FALSE);

	/* First check that both have the same type */
	if (G_OBJECT_TYPE (a) != G_OBJECT_TYPE (b))
		return FALSE;

	/* And now all properties */
	property_specs = g_object_class_list_properties (G_OBJECT_GET_CLASS (a), &n_property_specs);
	for (i = 0; i < n_property_specs && same; i++) {
		GParamSpec *prop_spec = property_specs[i];

		/* Fuzzy compare ignores secrets and properties defined with the FUZZY_IGNORE flag */
		if (   (flags & NM_SETTING_COMPARE_FLAG_FUZZY)
		    && (prop_spec->flags & (NM_SETTING_PARAM_FUZZY_IGNORE | NM_SETTING_PARAM_SECRET)))
			continue;

		if ((flags & NM_SETTING_COMPARE_FLAG_INFERRABLE) && !(prop_spec->flags & NM_SETTING_PARAM_INFERRABLE))
			continue;

		if (   (flags & NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS)
		    && (prop_spec->flags & NM_SETTING_PARAM_SECRET))
			continue;

		same = NM_SETTING_GET_CLASS (a)->compare_property (a, b, prop_spec, flags);
	}
	g_free (property_specs);

	return same;
}

static inline gboolean
should_compare_prop (NMSetting *setting,
                     const char *prop_name,
                     NMSettingCompareFlags comp_flags,
                     GParamFlags prop_flags)
{
	/* Fuzzy compare ignores secrets and properties defined with the FUZZY_IGNORE flag */
	if (   (comp_flags & NM_SETTING_COMPARE_FLAG_FUZZY)
	    && (prop_flags & (NM_SETTING_PARAM_FUZZY_IGNORE | NM_SETTING_PARAM_SECRET)))
		return FALSE;

	if ((comp_flags & NM_SETTING_COMPARE_FLAG_INFERRABLE) && !(prop_flags & NM_SETTING_PARAM_INFERRABLE))
		return FALSE;

	if (prop_flags & NM_SETTING_PARAM_SECRET) {
		NMSettingSecretFlags secret_flags = NM_SETTING_SECRET_FLAG_NONE;

		if (comp_flags & NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS)
			return FALSE;

		if (   NM_IS_SETTING_VPN (setting)
		    && g_strcmp0 (prop_name, NM_SETTING_VPN_SECRETS) == 0) {
			/* FIXME: NMSettingVPN:NM_SETTING_VPN_SECRETS has NM_SETTING_PARAM_SECRET.
			 * nm_setting_get_secret_flags() quite possibly fails, but it might succeed if the
			 * setting accidently uses a key "secrets". */
			return TRUE;
		}

		if (!nm_setting_get_secret_flags (setting, prop_name, &secret_flags, NULL))
			g_return_val_if_reached (FALSE);

		if (   (comp_flags & NM_SETTING_COMPARE_FLAG_IGNORE_AGENT_OWNED_SECRETS)
		    && (secret_flags & NM_SETTING_SECRET_FLAG_AGENT_OWNED))
			return FALSE;

		if (   (comp_flags & NM_SETTING_COMPARE_FLAG_IGNORE_NOT_SAVED_SECRETS)
		    && (secret_flags & NM_SETTING_SECRET_FLAG_NOT_SAVED))
			return FALSE;
	}

	if (   (comp_flags & NM_SETTING_COMPARE_FLAG_IGNORE_ID)
	    && NM_IS_SETTING_CONNECTION (setting)
	    && !strcmp (prop_name, NM_SETTING_CONNECTION_ID))
		return FALSE;

	if (   (comp_flags & NM_SETTING_COMPARE_FLAG_IGNORE_TIMESTAMP)
	    && NM_IS_SETTING_CONNECTION (setting)
	    && !strcmp (prop_name, NM_SETTING_CONNECTION_TIMESTAMP))
		return FALSE;

	return TRUE;
}

/**
 * nm_setting_diff:
 * @a: a #NMSetting
 * @b: a second #NMSetting to compare with the first
 * @flags: compare flags, e.g. %NM_SETTING_COMPARE_FLAG_EXACT
 * @invert_results: this parameter is used internally by libnm and should
 * be set to %FALSE.  If %TRUE inverts the meaning of the #NMSettingDiffResult.
 * @results: (inout) (transfer full) (element-type utf8 guint32): if the
 * settings differ, on return a hash table mapping the differing keys to one or
 * more %NMSettingDiffResult values OR-ed together.  If the settings do not
 * differ, any hash table passed in is unmodified.  If no hash table is passed
 * in and the settings differ, a new one is created and returned.
 *
 * Compares two #NMSetting objects for similarity, with comparison behavior
 * modified by a set of flags.  See the documentation for #NMSettingCompareFlags
 * for a description of each flag's behavior.  If the settings differ, the keys
 * of each setting that differ from the other are added to @results, mapped to
 * one or more #NMSettingDiffResult values.
 *
 * Returns: %TRUE if the settings contain the same values, %FALSE if they do not
 **/
gboolean
nm_setting_diff (NMSetting *a,
                 NMSetting *b,
                 NMSettingCompareFlags flags,
                 gboolean invert_results,
                 GHashTable **results)
{
	GParamSpec **property_specs;
	guint n_property_specs;
	guint i;
	NMSettingDiffResult a_result = NM_SETTING_DIFF_RESULT_IN_A;
	NMSettingDiffResult b_result = NM_SETTING_DIFF_RESULT_IN_B;
	NMSettingDiffResult a_result_default = NM_SETTING_DIFF_RESULT_IN_A_DEFAULT;
	NMSettingDiffResult b_result_default = NM_SETTING_DIFF_RESULT_IN_B_DEFAULT;
	gboolean results_created = FALSE;

	g_return_val_if_fail (results != NULL, FALSE);
	g_return_val_if_fail (NM_IS_SETTING (a), FALSE);
	if (b) {
		g_return_val_if_fail (NM_IS_SETTING (b), FALSE);
		g_return_val_if_fail (G_OBJECT_TYPE (a) == G_OBJECT_TYPE (b), FALSE);
	}

	if ((flags & (NM_SETTING_COMPARE_FLAG_DIFF_RESULT_WITH_DEFAULT | NM_SETTING_COMPARE_FLAG_DIFF_RESULT_NO_DEFAULT)) ==
	             (NM_SETTING_COMPARE_FLAG_DIFF_RESULT_WITH_DEFAULT | NM_SETTING_COMPARE_FLAG_DIFF_RESULT_NO_DEFAULT)) {
		/* conflicting flags: default to WITH_DEFAULT (clearing NO_DEFAULT). */
		flags &= ~NM_SETTING_COMPARE_FLAG_DIFF_RESULT_NO_DEFAULT;
	}

	/* If the caller is calling this function in a pattern like this to get
	 * complete diffs:
	 *
	 * nm_setting_diff (A, B, FALSE, &results);
	 * nm_setting_diff (B, A, TRUE, &results);
	 *
	 * and wants us to invert the results so that the second invocation comes
	 * out correctly, do that here.
	 */
	if (invert_results) {
		a_result = NM_SETTING_DIFF_RESULT_IN_B;
		b_result = NM_SETTING_DIFF_RESULT_IN_A;
		a_result_default = NM_SETTING_DIFF_RESULT_IN_B_DEFAULT;
		b_result_default = NM_SETTING_DIFF_RESULT_IN_A_DEFAULT;
	}

	if (*results == NULL) {
		*results = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
		results_created = TRUE;
	}

	/* And now all properties */
	property_specs = g_object_class_list_properties (G_OBJECT_GET_CLASS (a), &n_property_specs);

	for (i = 0; i < n_property_specs; i++) {
		GParamSpec *prop_spec = property_specs[i];
		NMSettingDiffResult r = NM_SETTING_DIFF_RESULT_UNKNOWN;

		/* Handle compare flags */
		if (!should_compare_prop (a, prop_spec->name, flags, prop_spec->flags))
			continue;
		if (strcmp (prop_spec->name, NM_SETTING_NAME) == 0)
			continue;

		if (b) {
			gboolean different;

			different = !NM_SETTING_GET_CLASS (a)->compare_property (a, b, prop_spec, flags);
			if (different) {
				gboolean a_is_default, b_is_default;
				GValue value = G_VALUE_INIT;

				g_value_init (&value, prop_spec->value_type);
				g_object_get_property (G_OBJECT (a), prop_spec->name, &value);
				a_is_default = g_param_value_defaults (prop_spec, &value);

				g_value_reset (&value);
				g_object_get_property (G_OBJECT (b), prop_spec->name, &value);
				b_is_default = g_param_value_defaults (prop_spec, &value);

				g_value_unset (&value);
				if ((flags & NM_SETTING_COMPARE_FLAG_DIFF_RESULT_WITH_DEFAULT) == 0) {
					if (!a_is_default)
						r |= a_result;
					if (!b_is_default)
						r |= b_result;
				} else {
					r |= a_result | b_result;
					if (a_is_default)
						r |= a_result_default;
					if (b_is_default)
						r |= b_result_default;
				}
			}
		} else if ((flags & (NM_SETTING_COMPARE_FLAG_DIFF_RESULT_WITH_DEFAULT | NM_SETTING_COMPARE_FLAG_DIFF_RESULT_NO_DEFAULT)) == 0)
			r = a_result;  /* only in A */
		else {
			GValue value = G_VALUE_INIT;

			g_value_init (&value, prop_spec->value_type);
			g_object_get_property (G_OBJECT (a), prop_spec->name, &value);
			if (!g_param_value_defaults (prop_spec, &value))
				r |= a_result;
			else if (flags & NM_SETTING_COMPARE_FLAG_DIFF_RESULT_WITH_DEFAULT)
				r |= a_result | a_result_default;

			g_value_unset (&value);
		}

		if (r != NM_SETTING_DIFF_RESULT_UNKNOWN) {
			void *p;

			if (g_hash_table_lookup_extended (*results, prop_spec->name, NULL, &p)) {
				if ((r & GPOINTER_TO_UINT (p)) != r)
					g_hash_table_insert (*results, g_strdup (prop_spec->name), GUINT_TO_POINTER (r | GPOINTER_TO_UINT (p)));
			} else
				g_hash_table_insert (*results, g_strdup (prop_spec->name), GUINT_TO_POINTER (r));
		}
	}
	g_free (property_specs);

	/* Don't return an empty hash table */
	if (results_created && !g_hash_table_size (*results)) {
		g_hash_table_destroy (*results);
		*results = NULL;
	}

	return !(*results);
}

#define CMP_AND_RETURN(n_a, n_b, name) \
	G_STMT_START { \
		gboolean _is = (strcmp (n_a, ""name) == 0); \
		\
		if (_is || (strcmp (n_b, ""name) == 0)) \
			return _is ? -1 : 1; \
	} G_STMT_END

static int
_enumerate_values_sort (GParamSpec **p_a, GParamSpec **p_b, GType *p_type)
{
	const char *n_a = (*p_a)->name;
	const char *n_b = (*p_b)->name;
	int c = strcmp (n_a, n_b);

	if (c) {
		if (*p_type == NM_TYPE_SETTING_CONNECTION) {
			/* for [connection], report first id, uuid, type in that order. */
			CMP_AND_RETURN (n_a, n_b, NM_SETTING_CONNECTION_ID);
			CMP_AND_RETURN (n_a, n_b, NM_SETTING_CONNECTION_UUID);
			CMP_AND_RETURN (n_a, n_b, NM_SETTING_CONNECTION_TYPE);
		}
	}
	return c;
}
#undef CMP_AND_RETURN

/**
 * nm_setting_enumerate_values:
 * @setting: the #NMSetting
 * @func: (scope call): user-supplied function called for each property of the setting
 * @user_data: user data passed to @func at each invocation
 *
 * Iterates over each property of the #NMSetting object, calling the supplied
 * user function for each property.
 **/
void
nm_setting_enumerate_values (NMSetting *setting,
                             NMSettingValueIterFn func,
                             gpointer user_data)
{
	GParamSpec **property_specs;
	guint n_property_specs;
	int i;
	GType type;

	g_return_if_fail (NM_IS_SETTING (setting));
	g_return_if_fail (func != NULL);

	property_specs = g_object_class_list_properties (G_OBJECT_GET_CLASS (setting), &n_property_specs);

	/* sort the properties. This has an effect on the order in which keyfile
	 * prints them. */
	type = G_OBJECT_TYPE (setting);
	g_qsort_with_data (property_specs, n_property_specs, sizeof (gpointer),
	                   (GCompareDataFunc) _enumerate_values_sort, &type);

	for (i = 0; i < n_property_specs; i++) {
		GParamSpec *prop_spec = property_specs[i];
		GValue value = G_VALUE_INIT;

		g_value_init (&value, G_PARAM_SPEC_VALUE_TYPE (prop_spec));
		g_object_get_property (G_OBJECT (setting), prop_spec->name, &value);
		func (setting, prop_spec->name, &value, prop_spec->flags, user_data);
		g_value_unset (&value);
	}

	g_free (property_specs);
}

/**
 * _nm_setting_clear_secrets:
 * @setting: the #NMSetting
 *
 * Resets and clears any secrets in the setting.  Secrets should be added to the
 * setting only when needed, and cleared immediately after use to prevent
 * leakage of information.
 *
 * Returns: %TRUE if the setting changed at all
 **/
gboolean
_nm_setting_clear_secrets (NMSetting *setting)
{
	GParamSpec **property_specs;
	guint n_property_specs;
	guint i;
	gboolean changed = FALSE;

	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);

	property_specs = g_object_class_list_properties (G_OBJECT_GET_CLASS (setting), &n_property_specs);

	for (i = 0; i < n_property_specs; i++) {
		GParamSpec *prop_spec = property_specs[i];

		if (prop_spec->flags & NM_SETTING_PARAM_SECRET) {
			GValue value = G_VALUE_INIT;

			g_value_init (&value, prop_spec->value_type);
			g_object_get_property (G_OBJECT (setting), prop_spec->name, &value);
			if (!g_param_value_defaults (prop_spec, &value)) {
				g_param_value_set_default (prop_spec, &value);
				g_object_set_property (G_OBJECT (setting), prop_spec->name, &value);
				changed = TRUE;
			}
			g_value_unset (&value);
		}
	}

	g_free (property_specs);

	return changed;
}

static gboolean
clear_secrets_with_flags (NMSetting *setting,
                          GParamSpec *pspec,
                          NMSettingClearSecretsWithFlagsFn func,
                          gpointer user_data)
{
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;
	gboolean changed = FALSE;

	g_return_val_if_fail (!NM_IS_SETTING_VPN (setting), FALSE);

	/* Clear the secret if the user function says to do so */
	if (!nm_setting_get_secret_flags (setting, pspec->name, &flags, NULL))
		g_return_val_if_reached (FALSE);

	if (func (setting, pspec->name, flags, user_data) == TRUE) {
		GValue value = G_VALUE_INIT;

		g_value_init (&value, pspec->value_type);
		g_object_get_property (G_OBJECT (setting), pspec->name, &value);
		if (!g_param_value_defaults (pspec, &value)) {
			g_param_value_set_default (pspec, &value);
			g_object_set_property (G_OBJECT (setting), pspec->name, &value);
			changed = TRUE;
		}
		g_value_unset (&value);
	}

	return changed;
}

/**
 * _nm_setting_clear_secrets_with_flags:
 * @setting: the #NMSetting
 * @func: (scope call): function to be called to determine whether a
 *     specific secret should be cleared or not
 * @user_data: caller-supplied data passed to @func
 *
 * Clears and frees secrets determined by @func.
 *
 * Returns: %TRUE if the setting changed at all
 **/
gboolean
_nm_setting_clear_secrets_with_flags (NMSetting *setting,
                                      NMSettingClearSecretsWithFlagsFn func,
                                      gpointer user_data)
{
	GParamSpec **property_specs;
	guint n_property_specs;
	guint i;
	gboolean changed = FALSE;

	g_return_val_if_fail (setting, FALSE);
	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	g_return_val_if_fail (func != NULL, FALSE);

	property_specs = g_object_class_list_properties (G_OBJECT_GET_CLASS (setting), &n_property_specs);
	for (i = 0; i < n_property_specs; i++) {
		if (property_specs[i]->flags & NM_SETTING_PARAM_SECRET) {
			changed |= NM_SETTING_GET_CLASS (setting)->clear_secrets_with_flags (setting,
			                                                                     property_specs[i],
			                                                                     func,
			                                                                     user_data);
		}
	}

	g_free (property_specs);
	return changed;
}

/**
 * _nm_setting_need_secrets:
 * @setting: the #NMSetting
 *
 * Returns an array of property names for each secret which may be required
 * to make a successful connection.  The returned hints are only intended as a
 * guide to what secrets may be required, because in some circumstances, there
 * is no way to conclusively determine exactly which secrets are needed.
 *
 * Returns: (transfer container) (element-type utf8): a #GPtrArray containing
 * the property names of secrets of the #NMSetting which may be required; the
 * caller owns the array and must free it with g_ptr_array_free(), but must not
 * free the elements.
 **/
GPtrArray *
_nm_setting_need_secrets (NMSetting *setting)
{
	GPtrArray *secrets = NULL;

	g_return_val_if_fail (NM_IS_SETTING (setting), NULL);

	if (NM_SETTING_GET_CLASS (setting)->need_secrets)
		secrets = NM_SETTING_GET_CLASS (setting)->need_secrets (setting);

	return secrets;
}

static int
update_one_secret (NMSetting *setting, const char *key, GVariant *value, GError **error)
{
	const NMSettingProperty *property;
	GParamSpec *prop_spec;
	GValue prop_value = { 0, };

	property = nm_setting_class_find_property (NM_SETTING_GET_CLASS (setting), key);
	if (!property) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_PROPERTY_NOT_FOUND,
		                     _("secret not found"));
		g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), key);
		return NM_SETTING_UPDATE_SECRET_ERROR;
	}

	/* Silently ignore non-secrets */
	prop_spec = property->param_spec;
	if (!prop_spec || !(prop_spec->flags & NM_SETTING_PARAM_SECRET))
		return NM_SETTING_UPDATE_SECRET_SUCCESS_UNCHANGED;

	if (   g_variant_is_of_type (value, G_VARIANT_TYPE_STRING)
	    && G_IS_PARAM_SPEC_STRING (prop_spec)) {
		/* String is expected to be a common case. Handle it specially and check
		 * whether the value is already set. Otherwise, we just reset the
		 * property and assume the value got modified.
		 */
		char *v;

		g_object_get (G_OBJECT (setting), prop_spec->name, &v, NULL);
		if (g_strcmp0 (v, g_variant_get_string (value, NULL)) == 0) {
			g_free (v);
			return NM_SETTING_UPDATE_SECRET_SUCCESS_UNCHANGED;
		}
		g_free (v);
	}

	g_value_init (&prop_value, prop_spec->value_type);
	set_property_from_dbus (property, value, &prop_value);
	g_object_set_property (G_OBJECT (setting), prop_spec->name, &prop_value);
	g_value_unset (&prop_value);

	return NM_SETTING_UPDATE_SECRET_SUCCESS_MODIFIED;
}

/**
 * _nm_setting_update_secrets:
 * @setting: the #NMSetting
 * @secrets: a #GVariant of type #NM_VARIANT_TYPE_SETTING, mapping property
 *   names to secrets.
 * @error: location to store error, or %NULL
 *
 * Update the setting's secrets, given a dictionary of secrets intended for that
 * setting (deserialized from D-Bus for example).
 *
 * Returns: an #NMSettingUpdateSecretResult
 **/
NMSettingUpdateSecretResult
_nm_setting_update_secrets (NMSetting *setting, GVariant *secrets, GError **error)
{
	GVariantIter iter;
	const char *secret_key;
	GVariant *secret_value;
	GError *tmp_error = NULL;
	NMSettingUpdateSecretResult result = NM_SETTING_UPDATE_SECRET_SUCCESS_UNCHANGED;

	g_return_val_if_fail (NM_IS_SETTING (setting), NM_SETTING_UPDATE_SECRET_ERROR);
	g_return_val_if_fail (g_variant_is_of_type (secrets, NM_VARIANT_TYPE_SETTING), NM_SETTING_UPDATE_SECRET_ERROR);
	if (error)
		g_return_val_if_fail (*error == NULL, NM_SETTING_UPDATE_SECRET_ERROR);

	g_variant_iter_init (&iter, secrets);
	while (g_variant_iter_next (&iter, "{&sv}", &secret_key, &secret_value)) {
		int success;

		success = NM_SETTING_GET_CLASS (setting)->update_one_secret (setting, secret_key, secret_value, &tmp_error);
		g_assert (!((success == NM_SETTING_UPDATE_SECRET_ERROR) ^ (!!tmp_error)));

		g_variant_unref (secret_value);

		if (success == NM_SETTING_UPDATE_SECRET_ERROR) {
			g_propagate_error (error, tmp_error);
			return NM_SETTING_UPDATE_SECRET_ERROR;
		}

		if (success == NM_SETTING_UPDATE_SECRET_SUCCESS_MODIFIED)
			result = NM_SETTING_UPDATE_SECRET_SUCCESS_MODIFIED;
	}

	return result;
}

static gboolean
is_secret_prop (NMSetting *setting, const char *secret_name, GError **error)
{
	const NMSettingProperty *property;
	GParamSpec *pspec;

	property = nm_setting_class_find_property (NM_SETTING_GET_CLASS (setting), secret_name);
	if (!property) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_PROPERTY_NOT_FOUND,
		                     _("secret is not set"));
		g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), secret_name);
		return FALSE;
	}

	pspec = property->param_spec;
	if (!pspec || !(pspec->flags & NM_SETTING_PARAM_SECRET)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_PROPERTY_NOT_SECRET,
		                     _("not a secret property"));
		g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), secret_name);
		return FALSE;
	}

	return TRUE;
}

static gboolean
get_secret_flags (NMSetting *setting,
                  const char *secret_name,
                  gboolean verify_secret,
                  NMSettingSecretFlags *out_flags,
                  GError **error)
{
	char *flags_prop;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	if (verify_secret && !is_secret_prop (setting, secret_name, error)) {
		if (out_flags)
			*out_flags = NM_SETTING_SECRET_FLAG_NONE;
		return FALSE;
	}

	flags_prop = g_strdup_printf ("%s-flags", secret_name);
	g_object_get (G_OBJECT (setting), flags_prop, &flags, NULL);
	g_free (flags_prop);

	if (out_flags)
		*out_flags = flags;
	return TRUE;
}

/**
 * nm_setting_get_secret_flags:
 * @setting: the #NMSetting
 * @secret_name: the secret key name to get flags for
 * @out_flags: on success, the #NMSettingSecretFlags for the secret
 * @error: location to store error, or %NULL
 *
 * For a given secret, retrieves the #NMSettingSecretFlags describing how to
 * handle that secret.
 *
 * Returns: %TRUE on success (if the given secret name was a valid property of
 * this setting, and if that property is secret), %FALSE if not
 **/
gboolean
nm_setting_get_secret_flags (NMSetting *setting,
                             const char *secret_name,
                             NMSettingSecretFlags *out_flags,
                             GError **error)
{
	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	g_return_val_if_fail (secret_name != NULL, FALSE);

	return NM_SETTING_GET_CLASS (setting)->get_secret_flags (setting, secret_name, TRUE, out_flags, error);
}

static gboolean
set_secret_flags (NMSetting *setting,
                  const char *secret_name,
                  gboolean verify_secret,
                  NMSettingSecretFlags flags,
                  GError **error)
{
	char *flags_prop;

	if (verify_secret)
		g_return_val_if_fail (is_secret_prop (setting, secret_name, error), FALSE);

	flags_prop = g_strdup_printf ("%s-flags", secret_name);
	g_object_set (G_OBJECT (setting), flags_prop, flags, NULL);
	g_free (flags_prop);
	return TRUE;
}

/**
 * nm_setting_set_secret_flags:
 * @setting: the #NMSetting
 * @secret_name: the secret key name to set flags for
 * @flags: the #NMSettingSecretFlags for the secret
 * @error: location to store error, or %NULL
 *
 * For a given secret, stores the #NMSettingSecretFlags describing how to
 * handle that secret.
 *
 * Returns: %TRUE on success (if the given secret name was a valid property of
 * this setting, and if that property is secret), %FALSE if not
 **/
gboolean
nm_setting_set_secret_flags (NMSetting *setting,
                             const char *secret_name,
                             NMSettingSecretFlags flags,
                             GError **error)
{
	g_return_val_if_fail (NM_IS_SETTING (setting), FALSE);
	g_return_val_if_fail (secret_name != NULL, FALSE);
	g_return_val_if_fail (flags <= NM_SETTING_SECRET_FLAGS_ALL, FALSE);

	return NM_SETTING_GET_CLASS (setting)->set_secret_flags (setting, secret_name, TRUE, flags, error);
}

/**
 * nm_setting_to_string:
 * @setting: the #NMSetting
 *
 * Convert the setting into a string.  For debugging purposes ONLY, should NOT
 * be used for serialization of the setting, or machine-parsed in any way. The
 * output format is not guaranteed to be stable and may change at any time.
 *
 * Returns: an allocated string containing a textual representation of the
 * setting's properties and values (including secrets!), which the caller should
 * free with g_free()
 **/
char *
nm_setting_to_string (NMSetting *setting)
{
	GString *string;
	GParamSpec **property_specs;
	guint n_property_specs;
	guint i;

	g_return_val_if_fail (NM_IS_SETTING (setting), NULL);

	property_specs = g_object_class_list_properties (G_OBJECT_GET_CLASS (setting), &n_property_specs);

	string = g_string_new (nm_setting_get_name (setting));
	g_string_append_c (string, '\n');

	for (i = 0; i < n_property_specs; i++) {
		GParamSpec *prop_spec = property_specs[i];
		GValue value = G_VALUE_INIT;
		char *value_str;
		gboolean is_default;

		if (strcmp (prop_spec->name, NM_SETTING_NAME) == 0)
			continue;

		g_value_init (&value, prop_spec->value_type);
		g_object_get_property (G_OBJECT (setting), prop_spec->name, &value);

		value_str = g_strdup_value_contents (&value);
		g_string_append_printf (string, "\t%s : %s", prop_spec->name, value_str);
		g_free (value_str);

		is_default = g_param_value_defaults (prop_spec, &value);
		g_value_unset (&value);

		g_string_append (string, " (");
		g_string_append_c (string, 's');
		if (is_default)
			g_string_append_c (string, 'd');
		g_string_append_c (string, ')');
		g_string_append_c (string, '\n');
	}

	g_free (property_specs);
	g_string_append_c (string, '\n');

	return g_string_free (string, FALSE);
}

GVariant *
_nm_setting_get_deprecated_virtual_interface_name (NMSetting *setting,
                                                   NMConnection *connection,
                                                   const char *property)
{
	NMSettingConnection *s_con;

	s_con = nm_connection_get_setting_connection (connection);
	g_return_val_if_fail (s_con != NULL, NULL);

	if (nm_setting_connection_get_interface_name (s_con))
		return g_variant_new_string (nm_setting_connection_get_interface_name (s_con));
	else
		return NULL;
}

/*****************************************************************************/

static void
nm_setting_init (NMSetting *setting)
{
}

static void
constructed (GObject *object)
{
	_ensure_setting_info (object, NM_SETTING_GET_PRIVATE (object));

	G_OBJECT_CLASS (nm_setting_parent_class)->constructed (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSetting *setting = NM_SETTING (object);

	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, nm_setting_get_name (setting));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_class_init (NMSettingClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);

	if (!setting_property_overrides_quark)
		setting_property_overrides_quark = g_quark_from_static_string ("nm-setting-property-overrides");
	if (!setting_properties_quark)
		setting_properties_quark = g_quark_from_static_string ("nm-setting-properties");

	g_type_class_add_private (setting_class, sizeof (NMSettingPrivate));

	/* virtual methods */
	object_class->constructed  = constructed;
	object_class->get_property = get_property;

	setting_class->update_one_secret = update_one_secret;
	setting_class->get_secret_flags = get_secret_flags;
	setting_class->set_secret_flags = set_secret_flags;
	setting_class->compare_property = compare_property;
	setting_class->clear_secrets_with_flags = clear_secrets_with_flags;

	/* Properties */

	/**
	 * NMSetting:name:
	 *
	 * The setting's name, which uniquely identifies the setting within the
	 * connection.  Each setting type has a name unique to that type, for
	 * example "ppp" or "wireless" or "wired".
	 **/
	g_object_class_install_property
		(object_class, PROP_NAME,
		 g_param_spec_string (NM_SETTING_NAME, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));
}
