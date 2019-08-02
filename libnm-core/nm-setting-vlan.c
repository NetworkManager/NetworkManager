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

#include "nm-default.h"

#include "nm-setting-vlan.h"

#include <stdlib.h>

#include "nm-libnm-core-intern/nm-libnm-core-utils.h"
#include "nm-utils.h"
#include "nm-core-types-internal.h"
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

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMSettingVlan,
	PROP_PARENT,
	PROP_ID,
	PROP_FLAGS,
	PROP_INGRESS_PRIORITY_MAP,
	PROP_EGRESS_PRIORITY_MAP,
);

typedef struct {
	char *parent;
	guint32 id;
	guint32 flags;
	GSList *ingress_priority_map;
	GSList *egress_priority_map;
} NMSettingVlanPrivate;

G_DEFINE_TYPE (NMSettingVlan, nm_setting_vlan, NM_TYPE_SETTING)

#define NM_SETTING_VLAN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_VLAN, NMSettingVlanPrivate))

/*****************************************************************************/

#define MAX_SKB_PRIO   G_MAXUINT32
#define MAX_8021P_PRIO 7  /* Max 802.1p priority */

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

static NMVlanQosMapping *
priority_map_new (guint32 from, guint32 to)
{
	NMVlanQosMapping *mapping;

	mapping = g_new (NMVlanQosMapping, 1);
	*mapping = (NMVlanQosMapping) {
		.from = from,
		.to   = to,
	};
	return mapping;
}

static NMVlanQosMapping *
priority_map_new_from_str (NMVlanPriorityMap map, const char *str)
{
	guint32 from, to;

	if (!nm_utils_vlan_priority_map_parse_str (map, str, FALSE, &from, &to, NULL))
		return NULL;
	return priority_map_new (from, to);
}

static void
priority_map_free (NMVlanQosMapping *map)
{
	nm_assert (map);
	g_free (map);
}

static GSList *
get_map (NMSettingVlan *self, NMVlanPriorityMap map)
{
	if (map == NM_VLAN_INGRESS_MAP)
		return NM_SETTING_VLAN_GET_PRIVATE (self)->ingress_priority_map;
	else if (map == NM_VLAN_EGRESS_MAP)
		return NM_SETTING_VLAN_GET_PRIVATE (self)->egress_priority_map;
	nm_assert_not_reached ();
	return NULL;
}

static int
prio_map_compare (gconstpointer p_a, gconstpointer p_b)
{
	const NMVlanQosMapping *a = p_a;
	const NMVlanQosMapping *b = p_b;

	return a->from < b->from
	       ? -1
	       : (a->from > b->from
	          ? 1
	          : (a->to < b->to ? -1 : (a->to > b->to ? 1 : 0)));
}

static void
set_map (NMSettingVlan *self, NMVlanPriorityMap map, GSList *list)
{
	/* Assert that the list is sorted */
#if NM_MORE_ASSERTS >= 2
	{
		GSList *iter, *last;

		last = list;
		iter = list ? list->next : NULL;
		while (iter) {
			const NMVlanQosMapping *l = last->data;
			const NMVlanQosMapping *m = iter->data;

			nm_assert (prio_map_compare (last->data, iter->data) < 0);

			/* Also reject duplicates (based on "from") */
			nm_assert (l->from < m->from);

			last = iter;
			iter = iter->next;
		}
	}
#endif

	if (map == NM_VLAN_INGRESS_MAP) {
		NM_SETTING_VLAN_GET_PRIVATE (self)->ingress_priority_map = list;
		_notify (self, PROP_INGRESS_PRIORITY_MAP);
	} else if (map == NM_VLAN_EGRESS_MAP) {
		NM_SETTING_VLAN_GET_PRIVATE (self)->egress_priority_map = list;
		_notify (self, PROP_EGRESS_PRIORITY_MAP);
	} else
		nm_assert_not_reached ();
}

static gboolean
check_replace_duplicate_priority (GSList *list, guint32 from, guint32 to)
{
	GSList *iter;
	NMVlanQosMapping *p;

	for (iter = list; iter; iter = g_slist_next (iter)) {
		p = iter->data;
		if (p->from == from) {
			p->to = to;
			return TRUE;
		}
	}
	return FALSE;
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
 * overwrote the old value, %FALSE if @str is not a valid mapping.
 */
gboolean
nm_setting_vlan_add_priority_str (NMSettingVlan *setting,
                                  NMVlanPriorityMap map,
                                  const char *str)
{
	GSList *list = NULL;
	NMVlanQosMapping *item = NULL;

	g_return_val_if_fail (NM_IS_SETTING_VLAN (setting), FALSE);
	g_return_val_if_fail (map == NM_VLAN_INGRESS_MAP || map == NM_VLAN_EGRESS_MAP, FALSE);
	g_return_val_if_fail (str && str[0], FALSE);

	item = priority_map_new_from_str (map, str);
	if (!item)
		return FALSE;

	list = get_map (setting, map);

	/* Duplicates get replaced */
	if (check_replace_duplicate_priority (list, item->from, item->to)) {
		g_free (item);
		if (map == NM_VLAN_INGRESS_MAP)
			_notify (setting, PROP_INGRESS_PRIORITY_MAP);
		else
			_notify (setting, PROP_EGRESS_PRIORITY_MAP);
		return TRUE;
	}

	set_map (setting, map, g_slist_insert_sorted (list, item, prio_map_compare));
	return TRUE;
}

/**
 * nm_setting_vlan_get_num_priorities:
 * @setting: the #NMSettingVlan
 * @map: the type of priority map
 *
 * Returns the number of entries in the
 * #NMSettingVlan:ingress_priority_map or #NMSettingVlan:egress_priority_map
 * properties of this setting.
 *
 * Returns: return the number of ingress/egress priority entries.
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
 * @out_from: (out) (allow-none): on return the value of the priority map's 'from' item
 * @out_to: (out) (allow-none): on return the value of priority map's 'to' item
 *
 * Retrieve one of the entries of the #NMSettingVlan:ingress_priority_map
 * or #NMSettingVlan:egress_priority_map properties of this setting.
 *
 * Returns: returns %TRUE if @idx is in range. Otherwise %FALSE.
 **/
gboolean
nm_setting_vlan_get_priority (NMSettingVlan *setting,
                              NMVlanPriorityMap map,
                              guint32 idx,
                              guint32 *out_from,
                              guint32 *out_to)
{
	NMVlanQosMapping *item;
	GSList *list;

	g_return_val_if_fail (NM_IS_SETTING_VLAN (setting), FALSE);
	g_return_val_if_fail (NM_IN_SET (map, NM_VLAN_INGRESS_MAP, NM_VLAN_EGRESS_MAP), FALSE);

	list = get_map (setting, map);
	item = g_slist_nth_data (list, idx);

	if (!item) {
		NM_SET_OUT (out_from, 0);
		NM_SET_OUT (out_to, 0);
		return FALSE;
	}

	NM_SET_OUT (out_from, item->from);
	NM_SET_OUT (out_to, item->to);
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
 * Returns: %TRUE.
 */
gboolean
nm_setting_vlan_add_priority (NMSettingVlan *setting,
                              NMVlanPriorityMap map,
                              guint32 from,
                              guint32 to)
{
	GSList *list = NULL;
	NMVlanQosMapping *item;

	g_return_val_if_fail (NM_IS_SETTING_VLAN (setting), FALSE);
	g_return_val_if_fail (map == NM_VLAN_INGRESS_MAP || map == NM_VLAN_EGRESS_MAP, FALSE);

	list = get_map (setting, map);
	if (check_replace_duplicate_priority (list, from, to)) {
		if (map == NM_VLAN_INGRESS_MAP)
			_notify (setting, PROP_INGRESS_PRIORITY_MAP);
		else
			_notify (setting, PROP_EGRESS_PRIORITY_MAP);
		return TRUE;
	}

	item = g_malloc0 (sizeof (NMVlanQosMapping));
	item->from = from;
	item->to = to;
	set_map (setting, map, g_slist_insert_sorted (list, item, prio_map_compare));

	return TRUE;
}

gboolean
_nm_setting_vlan_set_priorities (NMSettingVlan *setting,
                                 NMVlanPriorityMap map,
                                 const NMVlanQosMapping *qos_map,
                                 guint n_qos_map)
{
	gboolean has_changes = FALSE;
	GSList *map_prev, *map_new;
	guint i;
	gint64 from_last;

	map_prev = get_map (setting, map);

	if (n_qos_map != g_slist_length (map_prev))
		has_changes = TRUE;
	else {
		const GSList *iter;

		iter = map_prev;
		for (i = 0; i < n_qos_map; i++, iter = iter->next) {
			const NMVlanQosMapping *m = iter->data;

			if (   m->from != qos_map[i].from
			    || m->to != qos_map[i].to) {
				has_changes = TRUE;
				break;
			}
		}
	}

	if (!has_changes)
		return FALSE;

	map_new = NULL;
	from_last = G_MAXINT64;
	for (i = n_qos_map; i > 0;) {
		const NMVlanQosMapping *m = &qos_map[--i];
		NMVlanQosMapping *item;

		/* We require the array to be presorted. */
		if (m->from >= from_last)
			g_return_val_if_reached (FALSE);
		from_last = m->from;

		item = g_malloc0 (sizeof (NMVlanQosMapping));
		item->from = m->from;
		item->to = m->to;
		map_new = g_slist_prepend (map_new, item);
	}

	g_slist_free_full (map_prev, g_free);
	set_map (setting, map, map_new);

	return TRUE;
}

void
_nm_setting_vlan_get_priorities (NMSettingVlan *setting,
                                 NMVlanPriorityMap map,
                                 NMVlanQosMapping **out_qos_map,
                                 guint *out_n_qos_map)
{
	GSList *list;
	NMVlanQosMapping *qos_map = NULL;
	guint n_qos_map, i;

	list = get_map (setting, map);

	n_qos_map = g_slist_length (list);

	if (n_qos_map > 0) {
		qos_map = g_new (NMVlanQosMapping, n_qos_map);

		for (i = 0; list; i++, list = list->next) {
			nm_assert (i < n_qos_map);
			qos_map[i] = *((const NMVlanQosMapping *) list->data);
		}
	}
	*out_qos_map = qos_map;
	*out_n_qos_map = n_qos_map;
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
	priority_map_free ((NMVlanQosMapping *) (item->data));
	set_map (setting, map, g_slist_delete_link (list, item));
}

static gboolean
priority_map_remove_by_value (NMSettingVlan *setting,
                              NMVlanPriorityMap map,
                              guint32 from,
                              guint32 to,
                              gboolean wildcard_to)
{
	GSList *list = NULL, *iter = NULL;
	NMVlanQosMapping *item;

	nm_assert (NM_IS_SETTING_VLAN (setting));
	nm_assert (NM_IN_SET (map, NM_VLAN_INGRESS_MAP, NM_VLAN_EGRESS_MAP));

	list = get_map (setting, map);
	for (iter = list; iter; iter = g_slist_next (iter)) {
		item = iter->data;

		if (item->from != from)
			continue;
		if (   !wildcard_to
		    && item->to != to)
			continue;

		priority_map_free ((NMVlanQosMapping *) (iter->data));
		set_map (setting, map, g_slist_delete_link (list, iter));
		return TRUE;
	}
	return FALSE;
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
	g_return_val_if_fail (NM_IS_SETTING_VLAN (setting), FALSE);
	g_return_val_if_fail (map == NM_VLAN_INGRESS_MAP || map == NM_VLAN_EGRESS_MAP, FALSE);

	return priority_map_remove_by_value (setting, map, from, to, FALSE);
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
	gboolean is_wildcard_to;
	guint32 from, to;

	g_return_val_if_fail (NM_IS_SETTING_VLAN (setting), FALSE);
	g_return_val_if_fail (map == NM_VLAN_INGRESS_MAP || map == NM_VLAN_EGRESS_MAP, FALSE);

	if (!nm_utils_vlan_priority_map_parse_str (map, str, TRUE, &from, &to, &is_wildcard_to))
		return FALSE;
	return priority_map_remove_by_value (setting, map, from, to, is_wildcard_to);
}

/**
 * nm_setting_vlan_clear_priorities:
 * @setting: the #NMSettingVlan
 * @map: the type of priority map
 *
 * Clear all the entries from #NMSettingVlan:ingress_priority_map or
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

/*****************************************************************************/

static int
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
		} else if (!nm_utils_is_valid_iface_name (priv->parent, NULL)) {
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

	if (priv->id >= 4095) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("the vlan id must be in range 0-4094 but is %u"),
		             priv->id);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_VLAN_SETTING_NAME, NM_SETTING_VLAN_ID);
		return FALSE;
	}

	if (priv->flags & ~NM_VLAN_FLAGS_ALL) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("flags are invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_VLAN_SETTING_NAME, NM_SETTING_VLAN_FLAGS);
		return FALSE;
	}

	if (connection && !s_wired) {
		/* technically, a VLAN setting does not require an ethernet setting. However,
		 * the ifcfg-rh reader always adds a ethernet setting when reading a vlan setting.
		 * Thus, in order to be consistent, always add one via normalization. */
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_SETTING_NOT_FOUND,
		                     _("vlan setting should have a ethernet setting as well"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_VLAN_SETTING_NAME, NM_SETTING_VLAN_FLAGS);
		return NM_SETTING_VERIFY_NORMALIZABLE;
	}

	return TRUE;
}

static GVariant *
_override_flags_get (const NMSettInfoSetting *sett_info,
                     guint property_idx,
                     NMConnection *connection,
                     NMSetting *setting,
                     NMConnectionSerializationFlags flags,
                     const NMConnectionSerializationOptions *options)
{
	return g_variant_new_uint32 (nm_setting_vlan_get_flags ((NMSettingVlan *) setting));
}

static gboolean
_override_flags_not_set (NMSetting *setting,
                         GVariant *connection_dict,
                         const char *property,
                         NMSettingParseFlags parse_flags,
                         GError **error)
{
	/* we changed the default value for FLAGS. When an older client
	 * doesn't serialize the property, we assume it is the old default. */
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_VLAN_FLAGS, (NMVlanFlags) 0,
	              NULL);
	return TRUE;
}

static GSList *
priority_strv_to_maplist (NMVlanPriorityMap map, char **strv)
{
	GSList *list = NULL;
	gsize i;

	for (i = 0; strv && strv[i]; i++) {
		guint32 from, to;

		if (!nm_utils_vlan_priority_map_parse_str (map, strv[i], FALSE, &from, &to, NULL))
			continue;
		if (check_replace_duplicate_priority (list, from, to))
			continue;
		list = g_slist_prepend (list, priority_map_new (from, to));
	}
	return g_slist_sort (list, prio_map_compare);
}

static char **
priority_maplist_to_strv (GSList *list)
{
	GSList *iter;
	GPtrArray *strv;

	strv = g_ptr_array_new ();

	for (iter = list; iter; iter = g_slist_next (iter)) {
		NMVlanQosMapping *item = iter->data;

		g_ptr_array_add (strv, g_strdup_printf ("%d:%d", item->from, item->to));
	}
	g_ptr_array_add (strv, NULL);

	return (char **) g_ptr_array_free (strv, FALSE);
}

/*****************************************************************************/

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
		priv->ingress_priority_map = priority_strv_to_maplist (NM_VLAN_INGRESS_MAP, g_value_get_boxed (value));
		break;
	case PROP_EGRESS_PRIORITY_MAP:
		g_slist_free_full (priv->egress_priority_map, g_free);
		priv->egress_priority_map = priority_strv_to_maplist (NM_VLAN_EGRESS_MAP, g_value_get_boxed (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_vlan_init (NMSettingVlan *setting)
{
}

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
nm_setting_vlan_class_init (NMSettingVlanClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);
	GArray *properties_override = _nm_sett_info_property_override_create_array ();

	g_type_class_add_private (klass, sizeof (NMSettingVlanPrivate));

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize     = finalize;

	setting_class->verify = verify;

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
	obj_properties[PROP_PARENT] =
	    g_param_spec_string (NM_SETTING_VLAN_PARENT, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_CONSTRUCT |
	                         NM_SETTING_PARAM_INFERRABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingVlan:id:
	 *
	 * The VLAN identifier that the interface created by this connection should
	 * be assigned. The valid range is from 0 to 4094, without the reserved id 4095.
	 **/
	/* ---ifcfg-rh---
	 * property: id
	 * variable: VLAN_ID or DEVICE
	 * description: VLAN identifier.
	 * ---end---
	 */
	obj_properties[PROP_ID] =
	    g_param_spec_uint (NM_SETTING_VLAN_ID, "", "",
	                       0, 4095, 0,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_INFERRABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingVlan:flags:
	 *
	 * One or more flags which control the behavior and features of the VLAN
	 * interface.  Flags include %NM_VLAN_FLAG_REORDER_HEADERS (reordering of
	 * output packet headers), %NM_VLAN_FLAG_GVRP (use of the GVRP protocol),
	 * and %NM_VLAN_FLAG_LOOSE_BINDING (loose binding of the interface to its
	 * master device's operating state). %NM_VLAN_FLAG_MVRP (use of the MVRP
	 * protocol).
	 *
	 * The default value of this property is NM_VLAN_FLAG_REORDER_HEADERS,
	 * but it used to be 0. To preserve backward compatibility, the default-value
	 * in the D-Bus API continues to be 0 and a missing property on D-Bus
	 * is still considered as 0.
	 **/
	/* ---ifcfg-rh---
	 * property: flags
	 * variable: GVRP, MVRP, VLAN_FLAGS
	 * values: "yes or "no" for GVRP and MVRP; "LOOSE_BINDING" and "NO_REORDER_HDR" for VLAN_FLAGS
	 * description: VLAN flags.
	 * ---end---
	 */
	obj_properties[PROP_FLAGS] =
	    g_param_spec_flags (NM_SETTING_VLAN_FLAGS, "", "",
	                        NM_TYPE_VLAN_FLAGS,
	                        NM_VLAN_FLAG_REORDER_HEADERS,
	                        G_PARAM_READWRITE |
	                        G_PARAM_CONSTRUCT |
	                        NM_SETTING_PARAM_INFERRABLE |
	                        G_PARAM_STATIC_STRINGS);

	_properties_override_add_override (properties_override,
	                                   obj_properties[PROP_FLAGS],
	                                   G_VARIANT_TYPE_UINT32,
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
	obj_properties[PROP_INGRESS_PRIORITY_MAP] =
	    g_param_spec_boxed (NM_SETTING_VLAN_INGRESS_PRIORITY_MAP, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READWRITE |
	                        NM_SETTING_PARAM_INFERRABLE |
	                        G_PARAM_STATIC_STRINGS);

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
	obj_properties[PROP_EGRESS_PRIORITY_MAP] =
	    g_param_spec_boxed (NM_SETTING_VLAN_EGRESS_PRIORITY_MAP, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READWRITE |
	                        NM_SETTING_PARAM_INFERRABLE |
	                        G_PARAM_STATIC_STRINGS);

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
	_properties_override_add_dbus_only (properties_override,
	                                    "interface-name",
	                                    G_VARIANT_TYPE_STRING,
	                                    _nm_setting_get_deprecated_virtual_interface_name,
	                                    NULL);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit_full (setting_class, NM_META_SETTING_TYPE_VLAN,
	                               NULL, properties_override);
}
