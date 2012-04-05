/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Weiping Pan <wpan@redhat.com>
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
 * (C) Copyright 2011 Red Hat, Inc.
 */

#include <dbus/dbus-glib.h>
#include "nm-setting-vlan.h"
#include "nm-param-spec-specialized.h"
#include "nm-utils.h"
#include "nm-dbus-glib-types.h"
#include "nm-setting-connection.h"

/**
 * SECTION:nm-setting-vlan
 * @short_description: Describes connection properties for VLAN interfaces
 * @include: nm-setting-vlan.h
 *
 * The #NMSettingVlan object is a #NMSetting subclass that describes properties
 * necessary for connection to VLAN interfaces.
 **/

/**
 * nm_setting_vlan_error_quark:
 *
 * Registers an error quark for #NMSettingVlan if necessary.
 *
 * Returns: the error quark used for #NMSettingVlan errors.
 **/
GQuark
nm_setting_vlan_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-vlan-error-quark");
	return quark;
}

G_DEFINE_TYPE (NMSettingVlan, nm_setting_vlan, NM_TYPE_SETTING)

#define NM_SETTING_VLAN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_VLAN, NMSettingVlanPrivate))

typedef struct {
	char *iface_name;
	char *parent;
	guint32 id;
	guint32 flags;
	GSList *ingress_priority_map;
	GSList *egress_priority_map;
} NMSettingVlanPrivate;

enum {
	PROP_0,
	PROP_IFACE_NAME,
	PROP_PARENT,
	PROP_ID,
	PROP_FLAGS,
	PROP_INGRESS_PRIORITY_MAP,
	PROP_EGRESS_PRIORITY_MAP,
	LAST_PROP
};

#define MAX_SKB_PRIO   G_MAXUINT32
#define MAX_8021P_PRIO 7  /* Max 802.1p priority */

typedef struct {
	guint32 from;
	guint32 to;
} PriorityMap;

/**
 * nm_setting_vlan_new:
 * Creates a new #NMSettingVlan object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingVlan object
 **/
NMSetting *
nm_setting_vlan_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_VLAN, NULL);
}

/**
 * nm_setting_vlan_get_interface_name:
 * @setting: the #NMSettingVlan
 *
 * Returns: the #NMSettingVlan:interface_name property of the setting
 **/
const char *
nm_setting_vlan_get_interface_name (NMSettingVlan *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_VLAN (setting), NULL);
	return NM_SETTING_VLAN_GET_PRIVATE (setting)->iface_name;
}

/**
 * nm_setting_vlan_get_parent:
 * @setting: the #NMSettingVlan
 *
 * Returns: the #NMSettingVlan:parent property of the setting
 **/
const char *
nm_setting_vlan_get_parent (NMSettingVlan *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_VLAN (setting), NULL);
	return NM_SETTING_VLAN_GET_PRIVATE (setting)->parent;
}

/**
 * nm_setting_vlan_get_id:
 * @setting: the #NMSettingVlan
 *
 * Returns: the #NMSettingVlan:id property of the setting
 **/
guint32
nm_setting_vlan_get_id (NMSettingVlan *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_VLAN (setting), 0);
	return NM_SETTING_VLAN_GET_PRIVATE (setting)->id;
}

/**
 * nm_setting_vlan_get_flags:
 * @setting: the #NMSettingVlan
 *
 * Returns: the #NMSettingVlan:flags property of the setting
 **/
guint32
nm_setting_vlan_get_flags (NMSettingVlan *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_VLAN (setting), 0);
	return NM_SETTING_VLAN_GET_PRIVATE (setting)->flags;
}

static guint32
get_max_prio (NMVlanPriorityMap map, gboolean from)
{
	if (map == NM_VLAN_INGRESS_MAP)
		return from ? MAX_8021P_PRIO : MAX_SKB_PRIO;
	else if (map == NM_VLAN_EGRESS_MAP)
		return from ? MAX_SKB_PRIO : MAX_8021P_PRIO;
	g_assert_not_reached ();
}

static PriorityMap *
priority_map_new_from_str (NMVlanPriorityMap map, const char *str)
{
	PriorityMap *p = NULL;
	gchar **t = NULL;
	guint32 len;
	guint64 from, to;

	g_return_val_if_fail (str && str[0], NULL);

	t = g_strsplit (str, ":", 0);
	len = g_strv_length (t);
	if (len == 2) {
		from = g_ascii_strtoull (t[0], NULL, 10);
		to = g_ascii_strtoull (t[1], NULL, 10);

		if ((from <= get_max_prio (map, TRUE)) && (to <= get_max_prio (map, FALSE))) {
			p = g_malloc0 (sizeof (PriorityMap));
			p->from = from;
			p->to = to;
		}
	} else {
		/* Warn */
		g_warn_if_fail (len == 2);
	}

	g_strfreev (t);
	return p;
}

static void
priority_map_free (PriorityMap *map)
{
	g_return_if_fail (map != NULL);
	g_free (map);
}

static GSList *
get_map (NMSettingVlan *self, NMVlanPriorityMap map)
{
	if (map == NM_VLAN_INGRESS_MAP)
		return NM_SETTING_VLAN_GET_PRIVATE (self)->ingress_priority_map;
	else if (map == NM_VLAN_EGRESS_MAP)
		return NM_SETTING_VLAN_GET_PRIVATE (self)->egress_priority_map;
	g_assert_not_reached ();
	return NULL;
}

static void
set_map (NMSettingVlan *self, NMVlanPriorityMap map, GSList *list)
{
	if (map == NM_VLAN_INGRESS_MAP)
		NM_SETTING_VLAN_GET_PRIVATE (self)->ingress_priority_map = list;
	else if (map == NM_VLAN_EGRESS_MAP)
		NM_SETTING_VLAN_GET_PRIVATE (self)->egress_priority_map = list;
	else
		g_assert_not_reached ();
}

/**
 * nm_setting_vlan_add_priority_str
 * @setting: the #NMSettingVlan
 * @map: the type of priority map
 * @str: the string which contains a priority map, like "3:7"
 *
 * Adds a priority map entry into either the #NMSettingVlan:ingress_priority_map
 * or the #NMSettingVlan:egress_priority_map properties.  The priority map maps
 * the Linux SKB priorities to 802.1p priorities.
 *
 * Returns: TRUE if the entry was successfully added to the list, or it
 * overwrote the old value, FALSE if error
 */
gboolean
nm_setting_vlan_add_priority_str (NMSettingVlan *setting,
                                  NMVlanPriorityMap map,
                                  const char *str)
{
	NMSettingVlanPrivate *priv = NULL;
	GSList *list = NULL, *iter = NULL;
	PriorityMap *item = NULL;

	g_return_val_if_fail (NM_IS_SETTING_VLAN (setting), FALSE);
	g_return_val_if_fail (map == NM_VLAN_INGRESS_MAP || map == NM_VLAN_EGRESS_MAP, FALSE);
	g_return_val_if_fail (str && str[0], FALSE);

	priv = NM_SETTING_VLAN_GET_PRIVATE (setting);
	list = get_map (setting, map);

	item = priority_map_new_from_str (map, str);
	g_return_val_if_fail (item != NULL, FALSE);

	/* Duplicates get replaced */
	for (iter = list; iter; iter = g_slist_next (iter)) {
		PriorityMap *p = iter->data;

		if (p->from == item->from) {
			p->to = item->to;
			g_free (item);
			return TRUE;
		}
	}

	set_map (setting, map, g_slist_append (list, item));
	return TRUE;
}

/**
 * nm_setting_vlan_get_num_priorities:
 * @map: the type of priority map
 * @setting: the #NMSettingVlan
 *
 * Returns the number of entires in the
 * #NMSettingVlan:ingress_priority_map or #NMSettingVlan:egress_priority_map
 * properties of this setting.
 *
 * Returns: return the number of ingress/egress priority entries, -1 if error
 **/
gint32
nm_setting_vlan_get_num_priorities (NMSettingVlan *setting, NMVlanPriorityMap map)
{
	g_return_val_if_fail (NM_IS_SETTING_VLAN (setting), -1);
	g_return_val_if_fail (map == NM_VLAN_INGRESS_MAP || map == NM_VLAN_EGRESS_MAP, -1);

	return g_slist_length (get_map (setting, map));
}

/**
 * nm_setting_vlan_get_priority:
 * @map: the type of priority map
 * @setting: the #NMSettingVlan
 * @idx: the zero-based index of the ingress/egress priority map entry
 * @out_from: (out): on return the value of the priority map's 'from' item
 * @out_to: (out): on return the value of priority map's 'to' item
 *
 * Retrieve one of the entries of the #NMSettingVlan:ingress_priority_map
 * or #NMSettingVlan:egress_priority_map properties of this setting.
 *
 * Returns: %TRUE if a priority map was returned, %FALSE if error
 **/
gboolean
nm_setting_vlan_get_priority (NMSettingVlan *setting,
                              NMVlanPriorityMap map,
                              guint32 idx,
                              guint32 *out_from,
                              guint32 *out_to)
{
	GSList *list = NULL;
	PriorityMap *item = NULL;

	g_return_val_if_fail (NM_IS_SETTING_VLAN (setting), FALSE);
	g_return_val_if_fail (map == NM_VLAN_INGRESS_MAP || map == NM_VLAN_EGRESS_MAP, FALSE);
	g_return_val_if_fail (out_from != NULL, FALSE);
	g_return_val_if_fail (out_to != NULL, FALSE);

	list = get_map (setting, map);
	g_return_val_if_fail (idx < g_slist_length (list), FALSE);

	item = g_slist_nth_data (list, idx);
	g_assert (item);
	*out_from = item->from;
	*out_to = item->to;
	return TRUE;
}

/**
 * nm_setting_vlan_add_priority:
 * @map: the type of priority map
 * @setting: the #NMSettingVlan
 * @from: the priority to map to @to
 * @to: the priority to map @from to
 *
 * Adds a priority mapping to the #NMSettingVlan:ingress_priority_map or
 * #NMSettingVlan:egress_priority_map properties of the setting. If @from is
 * already in the given priority map, this function will overwrite the
 * existing entry with the new @to.
 *
 * If @map is #NM_VLAN_INGRESS_MAP then @from is the incoming 802.1q VLAN
 * Priority Code Point (PCP) value, and @to is the Linux SKB priority value.
 *
 * If @map is #NM_VLAN_EGRESS_MAP then @from is the Linux SKB priority value and
 * @to is the outgoing 802.1q VLAN Priority Code Point (PCP) value.
 *
 * Returns: TRUE if the new priority mapping was successfully added to the
 * list, FALSE if error
 */
gboolean
nm_setting_vlan_add_priority (NMSettingVlan *setting,
                              NMVlanPriorityMap map,
                              guint32 from,
                              guint32 to)
{
	GSList *list = NULL, *iter = NULL;
	PriorityMap *item;

	g_return_val_if_fail (NM_IS_SETTING_VLAN (setting), FALSE);
	g_return_val_if_fail (map == NM_VLAN_INGRESS_MAP || map == NM_VLAN_EGRESS_MAP, FALSE);

	list = get_map (setting, map);
	for (iter = list; iter; iter = g_slist_next (iter)) {
		item = iter->data;
		if (item->from == from) {
			item->to = to;
			return TRUE;
		}
	}

	item = g_malloc0 (sizeof (PriorityMap));
	item->from = from;
	item->to = to;
	set_map (setting, map, g_slist_append (list, item));

	return TRUE;
}

/**
 * nm_setting_vlan_remove_priority:
 * @map: the type of priority map
 * @setting: the #NMSettingVlan
 * @idx: the zero-based index of the priority map to remove
 *
 * Removes the priority map at index @idx from the
 * #NMSettingVlan:ingress_priority_map or #NMSettingVlan:egress_priority_map
 * properties.
 */
void
nm_setting_vlan_remove_priority (NMSettingVlan *setting,
                                 NMVlanPriorityMap map,
                                 guint32 idx)
{
	GSList *list = NULL, *item = NULL;

	g_return_if_fail (NM_IS_SETTING_VLAN (setting));
	g_return_if_fail (map == NM_VLAN_INGRESS_MAP || map == NM_VLAN_EGRESS_MAP);

	list = get_map (setting, map);
	g_return_if_fail (idx < g_slist_length (list));

	item = g_slist_nth_data (list, idx);
	priority_map_free ((PriorityMap *) item);
	set_map (setting, map, g_slist_delete_link (list, item));
}

/**
 * nm_setting_vlan_clear_priorities:
 * @map: the type of priority map
 * @setting: the #NMSettingVlan
 *
 * Clear all the entires from #NMSettingVlan:ingress_priority_map or
 * #NMSettingVlan:egress_priority_map properties.
 */
void
nm_setting_vlan_clear_priorities (NMSettingVlan *setting, NMVlanPriorityMap map)
{
	GSList *list = NULL;

	g_return_if_fail (NM_IS_SETTING_VLAN (setting));
	g_return_if_fail (map == NM_VLAN_INGRESS_MAP || map == NM_VLAN_EGRESS_MAP);

	list = get_map (setting, map);
	nm_utils_slist_free (list, g_free);
	set_map (setting, map, NULL);
}

/*********************************************************************/

static void
nm_setting_vlan_init (NMSettingVlan *setting)
{
	g_object_set (setting, NM_SETTING_NAME, NM_SETTING_VLAN_SETTING_NAME, NULL);
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingVlanPrivate *priv = NM_SETTING_VLAN_GET_PRIVATE (setting);

	if (priv->iface_name && !priv->iface_name[0]) {
		g_set_error (error,
		             NM_SETTING_VLAN_ERROR,
		             NM_SETTING_VLAN_ERROR_INVALID_PROPERTY,
		             NM_SETTING_VLAN_INTERFACE_NAME);
		return FALSE;
	}

	if (priv->parent && !priv->parent[0]) {
		g_set_error (error,
		             NM_SETTING_VLAN_ERROR,
		             NM_SETTING_VLAN_ERROR_INVALID_PROPERTY,
		             NM_SETTING_VLAN_PARENT);
		return FALSE;
	}

	if (priv->id > 4095) {
		g_set_error (error,
		             NM_SETTING_VLAN_ERROR,
		             NM_SETTING_VLAN_ERROR_INVALID_PROPERTY,
		             NM_SETTING_VLAN_ID);
		return FALSE;
	}

	if (priv->flags & ~(NM_VLAN_FLAG_REORDER_HEADERS |
	                    NM_VLAN_FLAG_GVRP |
	                    NM_VLAN_FLAG_LOOSE_BINDING)) {
		g_set_error (error,
		             NM_SETTING_VLAN_ERROR,
		             NM_SETTING_VLAN_ERROR_INVALID_PROPERTY,
		             NM_SETTING_VLAN_FLAGS);
		return FALSE;
	}

	return TRUE;
}

static const char *
get_virtual_iface_name (NMSetting *setting)
{
	return nm_setting_vlan_get_interface_name (NM_SETTING_VLAN (setting));
}

static GSList *
priority_stringlist_to_maplist (NMVlanPriorityMap map, GSList *strlist)
{
	GSList *list = NULL, *iter;

	for (iter = strlist; iter; iter = g_slist_next (iter)) {
		PriorityMap *item;

		item = priority_map_new_from_str (map, (const char *) iter->data);
		if (item)
			list = g_slist_prepend (list, item);
	}
	return g_slist_reverse (list);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingVlan *setting = NM_SETTING_VLAN (object);
	NMSettingVlanPrivate *priv = NM_SETTING_VLAN_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_IFACE_NAME:
		g_free (priv->iface_name);
		priv->iface_name = g_value_dup_string (value);
		break;
	case PROP_PARENT:
		g_free (priv->parent);
		priv->parent = g_value_dup_string (value);
		break;
	case PROP_ID:
		priv->id = g_value_get_uint (value);
		break;
	case PROP_FLAGS:
		priv->flags = g_value_get_uint (value);
		break;
	case PROP_INGRESS_PRIORITY_MAP:
		nm_utils_slist_free (priv->ingress_priority_map, g_free);
		priv->ingress_priority_map =
			priority_stringlist_to_maplist (NM_VLAN_INGRESS_MAP, g_value_get_boxed (value));
		break;
	case PROP_EGRESS_PRIORITY_MAP:
		nm_utils_slist_free (priv->egress_priority_map, g_free);
		priv->egress_priority_map =
			priority_stringlist_to_maplist (NM_VLAN_EGRESS_MAP, g_value_get_boxed (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static GSList *
priority_maplist_to_stringlist (GSList *list)
{
	GSList *strlist = NULL, *iter;

	for (iter = list; iter; iter = g_slist_next (iter)) {
		PriorityMap *item = iter->data;

		strlist = g_slist_prepend (strlist, g_strdup_printf ("%d:%d", item->from, item->to));
	}
	return g_slist_reverse (strlist);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingVlan *setting = NM_SETTING_VLAN (object);
	NMSettingVlanPrivate *priv = NM_SETTING_VLAN_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_IFACE_NAME:
		g_value_set_string (value, priv->iface_name);
		break;
	case PROP_PARENT:
		g_value_set_string (value, priv->parent);
		break;
	case PROP_ID:
		g_value_set_uint (value, priv->id);
		break;
	case PROP_FLAGS:
		g_value_set_uint (value, priv->flags);
		break;
	case PROP_INGRESS_PRIORITY_MAP:
		g_value_take_boxed (value, priority_maplist_to_stringlist (priv->ingress_priority_map));
		break;
	case PROP_EGRESS_PRIORITY_MAP:
		g_value_take_boxed (value, priority_maplist_to_stringlist (priv->egress_priority_map));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
finalize (GObject *object)
{
	NMSettingVlan *setting = NM_SETTING_VLAN (object);
	NMSettingVlanPrivate *priv = NM_SETTING_VLAN_GET_PRIVATE (setting);

	g_free (priv->iface_name);
	g_free (priv->parent);
	nm_utils_slist_free (priv->ingress_priority_map, g_free);
	nm_utils_slist_free (priv->egress_priority_map, g_free);
}

static void
nm_setting_vlan_class_init (NMSettingVlanClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingVlanPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;
	parent_class->get_virtual_iface_name = get_virtual_iface_name;

	/* Properties */

	/**
	 * NMSettingVlan:interface-name:
	 *
	 * If given, specifies the kernel name of the VLAN interface. If not given,
	 * a default name will be constructed from the interface described by the
	 * parent interface and the #NMSettingVlan:id , ex 'eth2.1'. The parent
	 * interface may be given by the #NMSettingVlan:parent property or by a
	 * hardware address property, eg #NMSettingWired:mac-address or
	 * #NMSettingInfiniband:mac-address.
	 **/
	g_object_class_install_property
		(object_class, PROP_IFACE_NAME,
		g_param_spec_string (NM_SETTING_VLAN_INTERFACE_NAME,
		                     "InterfaceName",
		                     "If given, specifies the kernel name of the VLAN "
		                     "interface. If not given, a default name will be "
		                     "constructed from the interface described by the "
		                     "parent interface and the 'id' property, ex "
		                     "'eth2.1'. The parent interface may be given by "
		                     "the 'parent' property or by a hardware address "
		                     "property, eg the 'wired' or 'infiniband' "
		                     "settings' 'mac-address' property.",
		                     NULL,
		                     G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingVlan:parent:
	 *
	 * If given, specifies the parent interface name or parent connection UUID
	 * from which this VLAN interface should be created.  If this property is
	 * not specified, the connection must contain a hardware address in a
	 * hardware-specific setting, like #NMSettingWired:mac-address or
	 * #NMSettingInfiniband:mac-address.
	 **/
	g_object_class_install_property
		(object_class, PROP_PARENT,
		g_param_spec_string (NM_SETTING_VLAN_PARENT,
		                     "Parent",
		                     "If given, specifies the parent interface name or "
		                     "parent connection UUID from which this VLAN "
		                     "interface should be created.  If this property is "
		                     "not specified, the connection must contain a "
		                     "hardware address in a hardware-specific setting, "
		                     "like the 'wired' or 'infiniband' settings' "
		                     "'mac-address' property.",
		                     NULL,
		                     G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingVlan:id:
	 *
	 * The VLAN identifier the interface created by this connection should be
	 * assigned.
	 **/
	g_object_class_install_property
		(object_class, PROP_ID,
		 g_param_spec_uint (NM_SETTING_VLAN_ID,
		                    "VLAN ID",
		                    "The VLAN indentifier the interface created by "
		                    "this connection should be assigned.",
		                    0, 4095, 0,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingVlan:flags:
	 *
	 * One or more of %NMVlanFlags which control the behavior and features of
	 * the VLAN interface.
	 **/
	g_object_class_install_property
		(object_class, PROP_FLAGS,
		 g_param_spec_uint (NM_SETTING_VLAN_FLAGS,
		                    "VLAN flags",
		                    "One or more flags which control the behavior and "
		                    "features of the VLAN interface.  Flags include "
		                    "reordering of output packet headers (0x01), use "
		                    "of the GVRP protocol (0x02), and loose binding "
		                    "of the interface to its master device's operating "
		                    "state (0x04).",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingVlan:ingress-priority-map:
	 *
	 * For incoming packets, a list of mappings from 802.1p priorities to Linux
	 * SKB priorities.  The mapping is given in the format 'from:to' where both
	 * 'from' and 'to' are unsigned integers, ie '7:3'.
	 **/
	g_object_class_install_property
		(object_class, PROP_INGRESS_PRIORITY_MAP,
		_nm_param_spec_specialized (NM_SETTING_VLAN_INGRESS_PRIORITY_MAP,
		                            "VLAN ingress priority mapping",
		                            "For incoming packets, a list of mappings "
		                            "from 802.1p priorities to Linux SKB "
		                            "priorities.  The mapping is given in the "
		                            "format 'from:to' where both 'from' and "
		                            "'to' are unsigned integers, ie '7:3'.",
		                            DBUS_TYPE_G_LIST_OF_STRING,
		                            G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingVlan:egress-priority-map:
	 *
	 * For outgoing packets, a list of mappings from Linux SKB priorities to
	 * 802.1p priorities.  The mapping is given in the format 'from:to'
	 * where both 'from' and 'to' are unsigned integers, ie '7:3'.
	 **/
	g_object_class_install_property
		(object_class, PROP_EGRESS_PRIORITY_MAP,
		_nm_param_spec_specialized (NM_SETTING_VLAN_EGRESS_PRIORITY_MAP,
		                            "VLAN egress priority mapping",
		                            "For outgoing packets, a list of mappings "
		                            "from Linux SKB priorities to 802.1p "
		                            "priorities.  The mapping is given in the "
		                            "format 'from:to' where both 'from' and "
		                            "'to' are unsigned integers, ie '7:3'.",
		                            DBUS_TYPE_G_LIST_OF_STRING,
		                            G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));
}
