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
 * Copyright 2011 - 2014 Red Hat, Inc.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "nm-setting-vlan.h"
#include "nm-utils.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"
#include "nm-setting-wired.h"
#include "nm-connection-private.h"

/**
 * SECTION:nm-setting-vlan
 * @short_description: Describes connection properties for VLAN interfaces
 *
 * The #NMSettingVlan object is a #NMSetting subclass that describes properties
 * necessary for connection to VLAN interfaces.
 **/

G_DEFINE_TYPE_WITH_CODE (NMSettingVlan, nm_setting_vlan, NM_TYPE_SETTING,
                         _nm_register_setting (VLAN, 1))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_VLAN)

#define NM_SETTING_VLAN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_VLAN, NMSettingVlanPrivate))

typedef struct {
	char *parent;
	guint32 id;
	guint32 flags;
	GSList *ingress_priority_map;
	GSList *egress_priority_map;
} NMSettingVlanPrivate;

enum {
	PROP_0,
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
 *
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
	if (map == NM_VLAN_INGRESS_MAP) {
		NM_SETTING_VLAN_GET_PRIVATE (self)->ingress_priority_map = list;
		g_object_notify (G_OBJECT (self), NM_SETTING_VLAN_INGRESS_PRIORITY_MAP);
	} else if (map == NM_VLAN_EGRESS_MAP) {
		NM_SETTING_VLAN_GET_PRIVATE (self)->egress_priority_map = list;
		g_object_notify (G_OBJECT (self), NM_SETTING_VLAN_EGRESS_PRIORITY_MAP);
	} else
		g_assert_not_reached ();
}

/**
 * nm_setting_vlan_add_priority_str:
 * @setting: the #NMSettingVlan
 * @map: the type of priority map
 * @str: the string which contains a priority map, like "3:7"
 *
 * Adds a priority map entry into either the #NMSettingVlan:ingress_priority_map
 * or the #NMSettingVlan:egress_priority_map properties.  The priority map maps
 * the Linux SKB priorities to 802.1p priorities.
 *
 * Returns: %TRUE if the entry was successfully added to the list, or it
 * overwrote the old value, %FALSE if error
 */
gboolean
nm_setting_vlan_add_priority_str (NMSettingVlan *setting,
                                  NMVlanPriorityMap map,
                                  const char *str)
{
	GSList *list = NULL, *iter = NULL;
	PriorityMap *item = NULL;

	g_return_val_if_fail (NM_IS_SETTING_VLAN (setting), FALSE);
	g_return_val_if_fail (map == NM_VLAN_INGRESS_MAP || map == NM_VLAN_EGRESS_MAP, FALSE);
	g_return_val_if_fail (str && str[0], FALSE);

	list = get_map (setting, map);

	item = priority_map_new_from_str (map, str);
	if (!item)
		g_return_val_if_reached (FALSE);

	/* Duplicates get replaced */
	for (iter = list; iter; iter = g_slist_next (iter)) {
		PriorityMap *p = iter->data;

		if (p->from == item->from) {
			p->to = item->to;
			g_free (item);
			if (map == NM_VLAN_INGRESS_MAP)
				g_object_notify (G_OBJECT (setting), NM_SETTING_VLAN_INGRESS_PRIORITY_MAP);
			else
				g_object_notify (G_OBJECT (setting), NM_SETTING_VLAN_EGRESS_PRIORITY_MAP);
			return TRUE;
		}
	}

	set_map (setting, map, g_slist_append (list, item));
	return TRUE;
}

/**
 * nm_setting_vlan_get_num_priorities:
 * @setting: the #NMSettingVlan
 * @map: the type of priority map
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
 * @setting: the #NMSettingVlan
 * @map: the type of priority map
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
 * @setting: the #NMSettingVlan
 * @map: the type of priority map
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
 * Returns: %TRUE if the new priority mapping was successfully added to the
 * list, %FALSE if error
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
			if (map == NM_VLAN_INGRESS_MAP)
				g_object_notify (G_OBJECT (setting), NM_SETTING_VLAN_INGRESS_PRIORITY_MAP);
			else
				g_object_notify (G_OBJECT (setting), NM_SETTING_VLAN_EGRESS_PRIORITY_MAP);
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
 * @setting: the #NMSettingVlan
 * @map: the type of priority map
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

	item = g_slist_nth (list, idx);
	priority_map_free ((PriorityMap *) (item->data));
	set_map (setting, map, g_slist_delete_link (list, item));
}

/**
 * nm_setting_vlan_remove_priority_by_value:
 * @setting: the #NMSettingVlan
 * @map: the type of priority map
 * @from: the priority to map to @to
 * @to: the priority to map @from to
 *
 * Removes the priority map @form:@to from the #NMSettingVlan:ingress_priority_map
 * or #NMSettingVlan:egress_priority_map (according to @map argument)
 * properties.
 *
 * Returns: %TRUE if the priority mapping was found and removed; %FALSE if it was not.
 */
gboolean
nm_setting_vlan_remove_priority_by_value (NMSettingVlan *setting,
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
		if (item->from == from && item->to == to) {
			priority_map_free ((PriorityMap *) (iter->data));
			set_map (setting, map, g_slist_delete_link (list, iter));
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_vlan_remove_priority_str_by_value:
 * @setting: the #NMSettingVlan
 * @map: the type of priority map
 * @str: the string which contains a priority map, like "3:7"
 *
 * Removes the priority map @str from the #NMSettingVlan:ingress_priority_map
 * or #NMSettingVlan:egress_priority_map (according to @map argument)
 * properties.
 *
 * Returns: %TRUE if the priority mapping was found and removed; %FALSE if it was not.
 */
gboolean
nm_setting_vlan_remove_priority_str_by_value (NMSettingVlan *setting,
                                              NMVlanPriorityMap map,
                                              const char *str)
{
	PriorityMap *item;
	gboolean found;

	g_return_val_if_fail (NM_IS_SETTING_VLAN (setting), FALSE);
	g_return_val_if_fail (map == NM_VLAN_INGRESS_MAP || map == NM_VLAN_EGRESS_MAP, FALSE);

	item = priority_map_new_from_str (map, str);
	if (!item)
		return FALSE;

	found = nm_setting_vlan_remove_priority_by_value (setting, map, item->from, item->to);
	g_free (item);
	return found;
}

/**
 * nm_setting_vlan_clear_priorities:
 * @setting: the #NMSettingVlan
 * @map: the type of priority map
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
	g_slist_free_full (list, g_free);
	set_map (setting, map, NULL);
}

/*********************************************************************/

static void
nm_setting_vlan_init (NMSettingVlan *setting)
{
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingVlanPrivate *priv = NM_SETTING_VLAN_GET_PRIVATE (setting);
	NMSettingConnection *s_con;
	NMSettingWired *s_wired;

	if (connection) {
		s_con = nm_connection_get_setting_connection (connection);
		s_wired = nm_connection_get_setting_wired (connection);
	} else {
		s_con = NULL;
		s_wired = NULL;
	}

	if (priv->parent) {
		if (nm_utils_is_uuid (priv->parent)) {
			/* If we have an NMSettingConnection:master with slave-type="vlan",
			 * then it must be the same UUID.
			 */
			if (s_con) {
				const char *master = NULL, *slave_type = NULL;

				slave_type = nm_setting_connection_get_slave_type (s_con);
				if (!g_strcmp0 (slave_type, NM_SETTING_VLAN_SETTING_NAME))
					master = nm_setting_connection_get_master (s_con);

				if (master && g_strcmp0 (priv->parent, master) != 0) {
					g_set_error (error,
					             NM_CONNECTION_ERROR,
					             NM_CONNECTION_ERROR_INVALID_PROPERTY,
					             _("'%s' value doesn't match '%s=%s'"),
					             priv->parent, NM_SETTING_CONNECTION_MASTER, master);
					g_prefix_error (error, "%s.%s: ", NM_SETTING_VLAN_SETTING_NAME, NM_SETTING_VLAN_PARENT);
					return FALSE;
				}
			}
		} else if (!nm_utils_iface_valid_name (priv->parent)) {
			/* parent must be either a UUID or an interface name */
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("'%s' is neither an UUID nor an interface name"),
			             priv->parent);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_VLAN_SETTING_NAME, NM_SETTING_VLAN_PARENT);
			return FALSE;
		}
	} else {
		/* If parent is NULL, the parent must be specified via
		 * NMSettingWired:mac-address.
		 */
		if (   connection
		    && (!s_wired || !nm_setting_wired_get_mac_address (s_wired))) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_MISSING_PROPERTY,
			             _("property is not specified and neither is '%s:%s'"),
			             NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_MAC_ADDRESS);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_VLAN_SETTING_NAME, NM_SETTING_VLAN_PARENT);
			return FALSE;
		}
	}

	if (priv->flags & ~(NM_VLAN_FLAG_REORDER_HEADERS |
	                    NM_VLAN_FLAG_GVRP |
	                    NM_VLAN_FLAG_LOOSE_BINDING)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("flags are invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_VLAN_SETTING_NAME, NM_SETTING_VLAN_FLAGS);
		return FALSE;
	}

	return TRUE;
}

static GVariant *
_override_flags_get (NMSetting *setting, const char *property)
{
	return g_variant_new_uint32 (nm_setting_vlan_get_flags ((NMSettingVlan *) setting));
}

static void
_override_flags_not_set (NMSetting *setting,
                          GVariant *connection_dict,
                          const char *property)
{
	/* we changed the default value for FLAGS. When an older client
	 * doesn't serialize the property, we assume it is the old default. */
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_VLAN_FLAGS, (NMVlanFlags) 0,
	              NULL);
}

static GSList *
priority_strv_to_maplist (NMVlanPriorityMap map, char **strv)
{
	GSList *list = NULL;
	int i;

	for (i = 0; strv && strv[i]; i++) {
		PriorityMap *item;

		item = priority_map_new_from_str (map, strv[i]);
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
	case PROP_PARENT:
		g_free (priv->parent);
		priv->parent = g_value_dup_string (value);
		break;
	case PROP_ID:
		priv->id = g_value_get_uint (value);
		break;
	case PROP_FLAGS:
		priv->flags = g_value_get_flags (value);
		break;
	case PROP_INGRESS_PRIORITY_MAP:
		g_slist_free_full (priv->ingress_priority_map, g_free);
		priv->ingress_priority_map =
			priority_strv_to_maplist (NM_VLAN_INGRESS_MAP, g_value_get_boxed (value));
		break;
	case PROP_EGRESS_PRIORITY_MAP:
		g_slist_free_full (priv->egress_priority_map, g_free);
		priv->egress_priority_map =
			priority_strv_to_maplist (NM_VLAN_EGRESS_MAP, g_value_get_boxed (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static char **
priority_maplist_to_strv (GSList *list)
{
	GSList *iter;
	GPtrArray *strv;

	strv = g_ptr_array_new ();

	for (iter = list; iter; iter = g_slist_next (iter)) {
		PriorityMap *item = iter->data;

		g_ptr_array_add (strv, g_strdup_printf ("%d:%d", item->from, item->to));
	}
	g_ptr_array_add (strv, NULL);

	return (char **) g_ptr_array_free (strv, FALSE);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingVlan *setting = NM_SETTING_VLAN (object);
	NMSettingVlanPrivate *priv = NM_SETTING_VLAN_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_PARENT:
		g_value_set_string (value, priv->parent);
		break;
	case PROP_ID:
		g_value_set_uint (value, priv->id);
		break;
	case PROP_FLAGS:
		g_value_set_flags (value, priv->flags);
		break;
	case PROP_INGRESS_PRIORITY_MAP:
		g_value_take_boxed (value, priority_maplist_to_strv (priv->ingress_priority_map));
		break;
	case PROP_EGRESS_PRIORITY_MAP:
		g_value_take_boxed (value, priority_maplist_to_strv (priv->egress_priority_map));
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

	g_free (priv->parent);
	g_slist_free_full (priv->ingress_priority_map, g_free);
	g_slist_free_full (priv->egress_priority_map, g_free);

	G_OBJECT_CLASS (nm_setting_vlan_parent_class)->finalize (object);
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

	/* Properties */

	/**
	 * NMSettingVlan:parent:
	 *
	 * If given, specifies the parent interface name or parent connection UUID
	 * from which this VLAN interface should be created.  If this property is
	 * not specified, the connection must contain an #NMSettingWired setting
	 * with a #NMSettingWired:mac-address property.
	 **/
	/* ---ifcfg-rh---
	 * property: parent
	 * variable: DEVICE or PHYSDEV
	 * description: Parent interface of the VLAN.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_PARENT,
		 g_param_spec_string (NM_SETTING_VLAN_PARENT, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT |
		                      NM_SETTING_PARAM_INFERRABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingVlan:id:
	 *
	 * The VLAN identifier that the interface created by this connection should
	 * be assigned.
	 **/
	/* ---ifcfg-rh---
	 * property: id
	 * variable: VLAN_ID or DEVICE
	 * description: VLAN identifier.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_ID,
		 g_param_spec_uint (NM_SETTING_VLAN_ID, "", "",
		                    0, 4095, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    NM_SETTING_PARAM_INFERRABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingVlan:flags:
	 *
	 * One or more flags which control the behavior and features of the VLAN
	 * interface.  Flags include %NM_VLAN_FLAG_REORDER_HEADERS (reordering of
	 * output packet headers), %NM_VLAN_FLAG_GVRP (use of the GVRP protocol),
	 * and %NM_VLAN_FLAG_LOOSE_BINDING (loose binding of the interface to its
	 * master device's operating state).
	 *
	 * The default value of this property is NM_VLAN_FLAG_REORDER_HEADERS,
	 * but it used to be 0. To preserve backward compatibility, the default-value
	 * in the D-Bus API continues to be 0 and a missing property on D-Bus
	 * is still considered as 0.
	 **/
	/* ---ifcfg-rh---
	 * property: flags
	 * variable: REORDER_HDR, GVRP, VLAN_FLAGS
	 * values: "yes or "no" for REORDER_HDR and GVRP; "LOOSE_BINDING" for VLAN_FLAGS
	 * description: VLAN flags.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_FLAGS,
		 g_param_spec_flags (NM_SETTING_VLAN_FLAGS, "", "",
		                     NM_TYPE_VLAN_FLAGS,
		                     NM_VLAN_FLAG_REORDER_HEADERS,
		                     G_PARAM_READWRITE |
		                     G_PARAM_CONSTRUCT |
		                     NM_SETTING_PARAM_INFERRABLE |
		                     G_PARAM_STATIC_STRINGS));
	_nm_setting_class_override_property (parent_class, NM_SETTING_VLAN_FLAGS,
	                                     NULL,
	                                     _override_flags_get,
	                                     NULL,
	                                     _override_flags_not_set);

	/**
	 * NMSettingVlan:ingress-priority-map:
	 *
	 * For incoming packets, a list of mappings from 802.1p priorities to Linux
	 * SKB priorities.  The mapping is given in the format "from:to" where both
	 * "from" and "to" are unsigned integers, ie "7:3".
	 **/
	/* ---ifcfg-rh---
	 * property: ingress-priority-map
	 * variable: VLAN_INGRESS_PRIORITY_MAP
	 * description: Ingress priority mapping.
	 * example: VLAN_INGRESS_PRIORITY_MAP=4:2,3:5
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_INGRESS_PRIORITY_MAP,
		 g_param_spec_boxed (NM_SETTING_VLAN_INGRESS_PRIORITY_MAP, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READWRITE |
		                     NM_SETTING_PARAM_INFERRABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingVlan:egress-priority-map:
	 *
	 * For outgoing packets, a list of mappings from Linux SKB priorities to
	 * 802.1p priorities.  The mapping is given in the format "from:to" where
	 * both "from" and "to" are unsigned integers, ie "7:3".
	 **/
	/* ---ifcfg-rh---
	 * property: egress-priority-map
	 * variable: VLAN_EGRESS_PRIORITY_MAP
	 * description: Egress priority mapping.
	 * example: VLAN_EGRESS_PRIORITY_MAP=5:4,4:1,3:7
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_EGRESS_PRIORITY_MAP,
		 g_param_spec_boxed (NM_SETTING_VLAN_EGRESS_PRIORITY_MAP, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READWRITE |
		                     NM_SETTING_PARAM_INFERRABLE |
		                     G_PARAM_STATIC_STRINGS));

	/* ---ifcfg-rh---
	 * property: interface-name
	 * variable: PHYSDEV and VLAN_ID, or DEVICE
	 * description: VLAN interface name.
	 *   If all variables are set, parent device from PHYSDEV takes precedence over DEVICE,
	 *   but VLAN id from DEVICE takes precedence over VLAN_ID.
	 * example: PHYSDEV=eth0, VLAN_ID=12; or DEVICE=eth0.12
	 * ---end---
	 * ---dbus---
	 * property: interface-name
	 * format: string
	 * description: Deprecated in favor of connection.interface-name, but can
	 *   be used for backward-compatibility with older daemons, to set the
	 *   vlan's interface name.
	 * ---end---
	 */
	_nm_setting_class_add_dbus_only_property (parent_class, "interface-name",
	                                          G_VARIANT_TYPE_STRING,
	                                          _nm_setting_get_deprecated_virtual_interface_name,
	                                          NULL);
}
