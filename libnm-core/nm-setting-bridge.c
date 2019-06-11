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
 * Copyright 2011 - 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-setting-bridge.h"

#include <ctype.h>
#include <stdlib.h>

#include "nm-connection-private.h"
#include "nm-utils.h"
#include "nm-utils-private.h"

/**
 * SECTION:nm-setting-bridge
 * @short_description: Describes connection properties for bridges
 *
 * The #NMSettingBridge object is a #NMSetting subclass that describes properties
 * necessary for bridging connections.
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMSettingBridge,
	PROP_MAC_ADDRESS,
	PROP_STP,
	PROP_PRIORITY,
	PROP_FORWARD_DELAY,
	PROP_HELLO_TIME,
	PROP_MAX_AGE,
	PROP_AGEING_TIME,
	PROP_GROUP_FORWARD_MASK,
	PROP_MULTICAST_SNOOPING,
	PROP_VLAN_FILTERING,
	PROP_VLAN_DEFAULT_PVID,
	PROP_VLANS,
);

typedef struct {
	char *   mac_address;
	gboolean stp;
	guint16  priority;
	guint16  forward_delay;
	guint16  hello_time;
	guint16  max_age;
	guint32  ageing_time;
	guint16  group_forward_mask;
	gboolean multicast_snooping;
	gboolean vlan_filtering;
	guint16  vlan_default_pvid;
	GPtrArray *vlans;
} NMSettingBridgePrivate;

G_DEFINE_TYPE (NMSettingBridge, nm_setting_bridge, NM_TYPE_SETTING)

#define NM_SETTING_BRIDGE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_BRIDGE, NMSettingBridgePrivate))

/*****************************************************************************/

G_DEFINE_BOXED_TYPE (NMBridgeVlan, nm_bridge_vlan, _nm_bridge_vlan_dup, nm_bridge_vlan_unref)

struct _NMBridgeVlan {
	guint refcount;
	guint16 vid_start;
	guint16 vid_end;
	bool untagged:1;
	bool pvid:1;
	bool sealed:1;
};

static gboolean
NM_IS_BRIDGE_VLAN (const NMBridgeVlan *self, gboolean also_sealed)
{
	return    self
	       && self->refcount > 0
	       && (also_sealed || !self->sealed);
}

/**
 * nm_bridge_vlan_new:
 * @vid_start: the start VLAN id, must be between 1 and 4094.
 * @vid_end: the end VLAN id, must be 0 or between @vid_start and 4094.
 *
 * Creates a new #NMBridgeVlan object for the given VLAN id range.
 * Setting @vid_end to 0 is equivalent to setting it to @vid_start
 * and creates a single-id VLAN.
 *
 * Returns: (transfer full): the new #NMBridgeVlan object.
 *
 * Since: 1.18
 **/
NMBridgeVlan *
nm_bridge_vlan_new (guint16 vid_start, guint16 vid_end)
{
	NMBridgeVlan *vlan;

	if (vid_end == 0)
		vid_end = vid_start;

	g_return_val_if_fail (vid_start >= NM_BRIDGE_VLAN_VID_MIN, NULL);
	g_return_val_if_fail (vid_end <= NM_BRIDGE_VLAN_VID_MAX, NULL);
	g_return_val_if_fail (vid_start <= vid_end, NULL);

	vlan = g_slice_new0 (NMBridgeVlan);
	vlan->refcount = 1;
	vlan->vid_start = vid_start;
	vlan->vid_end = vid_end;

	return vlan;
}

/**
 * nm_bridge_vlan_ref:
 * @vlan: the #NMBridgeVlan
 *
 * Increases the reference count of the object.
 *
 * Returns: the input argument @vlan object.
 *
 * Since: 1.18
 **/
NMBridgeVlan *
nm_bridge_vlan_ref (NMBridgeVlan *vlan)
{
	g_return_val_if_fail (NM_IS_BRIDGE_VLAN (vlan, TRUE), NULL);

	nm_assert (vlan->refcount < G_MAXUINT);

	vlan->refcount++;
	return vlan;
}

/**
 * nm_bridge_vlan_unref:
 * @vlan: the #NMBridgeVlan
 *
 * Decreases the reference count of the object.  If the reference count
 * reaches zero the object will be destroyed.
 *
 * Since: 1.18
 **/
void
nm_bridge_vlan_unref (NMBridgeVlan *vlan)
{
	g_return_if_fail (NM_IS_BRIDGE_VLAN (vlan, TRUE));

	if (--vlan->refcount == 0)
		g_slice_free (NMBridgeVlan, vlan);
}

/**
 * nm_bridge_vlan_cmp:
 * @a: a #NMBridgeVlan
 * @b: another #NMBridgeVlan
 *
 * Compare two bridge VLAN objects.
 *
 * Returns: zero of the two instances are equivalent or
 *   a non-zero integer otherwise. This defines a total ordering
 *   over the VLANs. Whether a VLAN is sealed or not does not
 *   affect the comparison.
 *
 * Since: 1.18
 **/
int
nm_bridge_vlan_cmp (const NMBridgeVlan *a, const NMBridgeVlan *b)
{
	g_return_val_if_fail (NM_IS_BRIDGE_VLAN (a, TRUE), 0);
	g_return_val_if_fail (NM_IS_BRIDGE_VLAN (b, TRUE), 0);

	NM_CMP_SELF (a, b);
	NM_CMP_FIELD (a, b, vid_start);
	NM_CMP_FIELD (a, b, vid_end);
	NM_CMP_FIELD_BOOL (a, b, untagged);
	NM_CMP_FIELD_BOOL (a, b, pvid);

	return 0;
}

NMBridgeVlan *
_nm_bridge_vlan_dup (const NMBridgeVlan *vlan)
{
	g_return_val_if_fail (NM_IS_BRIDGE_VLAN (vlan, TRUE), NULL);

	if (vlan->sealed) {
		nm_bridge_vlan_ref ((NMBridgeVlan *) vlan);
		return (NMBridgeVlan *) vlan;
	}

	return nm_bridge_vlan_new_clone (vlan);
}

NMBridgeVlan *
_nm_bridge_vlan_dup_and_seal (const NMBridgeVlan *vlan)
{
	NMBridgeVlan *new;

	g_return_val_if_fail (NM_IS_BRIDGE_VLAN (vlan, TRUE), NULL);

	new = _nm_bridge_vlan_dup (vlan);
	nm_bridge_vlan_seal (new);

	return new;
}

/**
 * nm_bridge_vlan_get_vid_range:
 * @vlan: the #NMBridgeVlan
 * @vid_start: location to store the VLAN id range start.
 * @vid_end: location to store the VLAN id range end
 *
 * Gets the VLAN id range.
 *
 * Returns: %TRUE is the VLAN specifies a range, %FALSE if it is
 * a single-id VLAN.
 *
 * Since: 1.18
 **/
gboolean
nm_bridge_vlan_get_vid_range (const NMBridgeVlan *vlan,
                              guint16 *vid_start,
                              guint16 *vid_end)
{
	g_return_val_if_fail (NM_IS_BRIDGE_VLAN (vlan, TRUE), 0);

	NM_SET_OUT (vid_start, vlan->vid_start);
	NM_SET_OUT (vid_end, vlan->vid_end);

	return vlan->vid_start != vlan->vid_end;
}

/**
 * nm_bridge_vlan_is_untagged:
 * @vlan: the #NMBridgeVlan
 *
 * Returns whether the VLAN is untagged.
 *
 * Returns: %TRUE if the VLAN is untagged, %FALSE otherwise
 *
 * Since: 1.18
 **/
gboolean
nm_bridge_vlan_is_untagged (const NMBridgeVlan *vlan)
{
	g_return_val_if_fail (NM_IS_BRIDGE_VLAN (vlan, TRUE), FALSE);

	return vlan->untagged;
}

/**
 * nm_bridge_vlan_is_pvid:
 * @vlan: the #NMBridgeVlan
 *
 * Returns whether the VLAN is the PVID for the port.
 *
 * Returns: %TRUE if the VLAN is the PVID
 *
 * Since: 1.18
 **/
gboolean
nm_bridge_vlan_is_pvid (const NMBridgeVlan *vlan)
{
	g_return_val_if_fail (NM_IS_BRIDGE_VLAN (vlan, TRUE), FALSE);

	return vlan->pvid;
}

/**
 * nm_bridge_vlan_set_untagged:
 * @vlan: the #NMBridgeVlan
 * @value: the new value
 *
 * Change the value of the untagged property of the VLAN.
 *
 * Since: 1.18
 **/
void
nm_bridge_vlan_set_untagged (NMBridgeVlan *vlan, gboolean value)
{
	g_return_if_fail (NM_IS_BRIDGE_VLAN (vlan, FALSE));

	vlan->untagged = value;
}

/**
 * nm_bridge_vlan_set_pvid:
 * @vlan: the #NMBridgeVlan
 * @value: the new value
 *
 * Change the value of the PVID property of the VLAN. It
 * is invalid to set the value to %TRUE for non-single-id
 * VLANs.
 *
 * Since: 1.18
 **/
void
nm_bridge_vlan_set_pvid (NMBridgeVlan *vlan, gboolean value)
{
	g_return_if_fail (NM_IS_BRIDGE_VLAN (vlan, FALSE));
	g_return_if_fail (!value || vlan->vid_start == vlan->vid_end);

	vlan->pvid = value;
}

/**
 * nm_bridge_vlan_is_sealed:
 * @vlan: the #NMBridgeVlan instance
 *
 * Returns: whether @self is sealed or not.
 *
 * Since: 1.18
 */
gboolean
nm_bridge_vlan_is_sealed (const NMBridgeVlan *vlan)
{
	g_return_val_if_fail (NM_IS_BRIDGE_VLAN (vlan, TRUE), FALSE);

	return vlan->sealed;
}

/**
 * nm_bridge_vlan_seal:
 * @vlan: the #NMBridgeVlan instance
 *
 * Seal the #NMBridgeVlan instance. Afterwards, it is a bug
 * to call all functions that modify the instance (except ref/unref).
 * A sealed instance cannot be unsealed again, but you can create
 * an unsealed copy with nm_bridge_vlan_new_clone().
 *
 * Since: 1.18
 */
void
nm_bridge_vlan_seal (NMBridgeVlan *vlan)
{
	g_return_if_fail (NM_IS_BRIDGE_VLAN (vlan, TRUE));

	vlan->sealed = TRUE;
}

/**
 * nm_bridge_vlan_new_clone:
 * @vlan: the #NMBridgeVlan instance to copy
 *
 * Returns: (transfer full): a clone of @vlan. This instance
 *   is always unsealed.
 *
 * Since: 1.18
 */
NMBridgeVlan *
nm_bridge_vlan_new_clone (const NMBridgeVlan *vlan)
{
	NMBridgeVlan *copy;

	g_return_val_if_fail (NM_IS_BRIDGE_VLAN (vlan, TRUE), NULL);

	copy = nm_bridge_vlan_new (vlan->vid_start, vlan->vid_end);
	copy->untagged = vlan->untagged;
	copy->pvid = vlan->pvid;

	return copy;
}

void
_nm_bridge_vlan_str_append_rest (const NMBridgeVlan *vlan,
                                 GString *string,
                                 gboolean leading_space)
{
	if (nm_bridge_vlan_is_pvid (vlan)) {
		if (leading_space)
			g_string_append_c (string, ' ');
		g_string_append (string, "pvid");
		leading_space = TRUE;
	}
	if (nm_bridge_vlan_is_untagged (vlan)) {
		if (leading_space)
			g_string_append_c (string, ' ');
		g_string_append (string, "untagged");
		leading_space = TRUE;
	}
}

/**
 * nm_bridge_vlan_to_str:
 * @vlan: the %NMBridgeVlan
 * @error: location of the error
 *
 * Convert a %NMBridgeVlan to a string.
 *
 * Returns: formatted string or %NULL
 *
 * Since: 1.18
 */
char *
nm_bridge_vlan_to_str (const NMBridgeVlan *vlan, GError **error)
{
	GString *string;

	g_return_val_if_fail (vlan, NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	/* The function never fails at the moment, but it might in the
	 * future if more parameters are added to the object that could
	 * make it invalid. */

	string = g_string_sized_new (28);

	if (vlan->vid_start == vlan->vid_end)
		g_string_append_printf (string, "%u", vlan->vid_start);
	else
		g_string_append_printf (string, "%u-%u", vlan->vid_start, vlan->vid_end);

	_nm_bridge_vlan_str_append_rest (vlan, string, TRUE);

	return g_string_free (string, FALSE);
}

/**
 * nm_bridge_vlan_from_str:
 * @str: the string representation of a bridge VLAN
 * @error: location of the error
 *
 * Parses the string representation of the queueing
 * discipline to a %NMBridgeVlan instance.
 *
 * Returns: the %NMBridgeVlan or %NULL
 *
 * Since: 1.18
 */
NMBridgeVlan *
nm_bridge_vlan_from_str (const char *str, GError **error)
{
	NMBridgeVlan *vlan = NULL;
	gs_free const char **tokens = NULL;
	guint i, vid_start, vid_end = 0;
	gboolean pvid = FALSE;
	gboolean untagged = FALSE;
	char *c;

	g_return_val_if_fail (str, NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	tokens = nm_utils_escaped_tokens_split (str, NM_ASCII_SPACES);
	if (!tokens || !tokens[0]) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_FAILED,
		                     "missing VLAN id");
		return NULL;
	}

	c = strchr (tokens[0], '-');
	if (c)
		*c = '\0';

	vid_start = _nm_utils_ascii_str_to_uint64 (tokens[0],
	                                           10,
	                                           NM_BRIDGE_VLAN_VID_MIN,
	                                           NM_BRIDGE_VLAN_VID_MAX,
	                                           G_MAXUINT);
	if (vid_start == G_MAXUINT) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_FAILED,
		             "invalid VLAN id range start '%s', must be in [1,4094]", tokens[0]);
		return NULL;
	}

	if (c) {
		vid_end = _nm_utils_ascii_str_to_uint64 (c + 1,
		                                         10,
		                                         NM_BRIDGE_VLAN_VID_MIN,
		                                         NM_BRIDGE_VLAN_VID_MAX,
		                                         G_MAXUINT);
		if (vid_end == G_MAXUINT) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_FAILED,
			             "invalid VLAN id range end '%s', must be in [1,4094]", c + 1);
			return NULL;
		}
		if (vid_end < vid_start) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_FAILED,
			             "invalid VLAN id range %u-%u, start VLAN id must be less than end VLAN id",
			             vid_start, vid_end);
			return NULL;
		}
	} else
		vid_end = vid_start;

	for (i = 1; tokens[i]; i++) {
		if (nm_streq (tokens[i], "pvid")) {
			if (vid_start != vid_end) {
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_FAILED,
				                     "a VLAN range can't be a PVID");
				return NULL;
			}
			pvid = TRUE;
		} else if (nm_streq (tokens[i], "untagged"))
			untagged = TRUE;
		else {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_FAILED,
			             "invalid option '%s'", tokens[i]);
			return NULL;
		}
	}

	vlan = nm_bridge_vlan_new (vid_start, vid_end);
	nm_bridge_vlan_set_pvid (vlan, pvid);
	nm_bridge_vlan_set_untagged (vlan, untagged);

	return vlan;
}

/*****************************************************************************/

static int
vlan_ptr_cmp (gconstpointer a, gconstpointer b)
{
	const NMBridgeVlan *vlan_a = *(const NMBridgeVlan **) a;
	const NMBridgeVlan *vlan_b = *(const NMBridgeVlan **) b;

	return nm_bridge_vlan_cmp (vlan_a, vlan_b);
}

gboolean
_nm_setting_bridge_sort_vlans (NMSettingBridge *setting)
{
	NMSettingBridgePrivate *priv;
	gboolean need_sort = FALSE;
	guint i;

	priv = NM_SETTING_BRIDGE_GET_PRIVATE (setting);

	for (i = 1; i < priv->vlans->len; i++) {
		NMBridgeVlan *vlan_prev = priv->vlans->pdata[i - 1];
		NMBridgeVlan *vlan = priv->vlans->pdata[i];

		if (nm_bridge_vlan_cmp (vlan_prev, vlan) > 0) {
			need_sort = TRUE;
			break;
		}
	}

	if (need_sort) {
		g_ptr_array_sort (priv->vlans, vlan_ptr_cmp);
		_notify (setting, PROP_VLANS);
	}

	return need_sort;
}

/*****************************************************************************/

/**
 * nm_setting_bridge_get_mac_address:
 * @setting: the #NMSettingBridge
 *
 * Returns: the #NMSettingBridge:mac-address property of the setting
 **/
const char *
nm_setting_bridge_get_mac_address (NMSettingBridge *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), NULL);

	return NM_SETTING_BRIDGE_GET_PRIVATE (setting)->mac_address;
}

/**
 * nm_setting_bridge_get_stp:
 * @setting: the #NMSettingBridge
 *
 * Returns: the #NMSettingBridge:stp property of the setting
 **/
gboolean
nm_setting_bridge_get_stp (NMSettingBridge *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), FALSE);

	return NM_SETTING_BRIDGE_GET_PRIVATE (setting)->stp;
}

/**
 * nm_setting_bridge_get_priority:
 * @setting: the #NMSettingBridge
 *
 * Returns: the #NMSettingBridge:priority property of the setting
 **/
guint16
nm_setting_bridge_get_priority (NMSettingBridge *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), 0);

	return NM_SETTING_BRIDGE_GET_PRIVATE (setting)->priority;
}

/**
 * nm_setting_bridge_get_forward_delay:
 * @setting: the #NMSettingBridge
 *
 * Returns: the #NMSettingBridge:forward-delay property of the setting
 **/
guint16
nm_setting_bridge_get_forward_delay (NMSettingBridge *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), 0);

	return NM_SETTING_BRIDGE_GET_PRIVATE (setting)->forward_delay;
}

/**
 * nm_setting_bridge_get_hello_time:
 * @setting: the #NMSettingBridge
 *
 * Returns: the #NMSettingBridge:hello-time property of the setting
 **/
guint16
nm_setting_bridge_get_hello_time (NMSettingBridge *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), 0);

	return NM_SETTING_BRIDGE_GET_PRIVATE (setting)->hello_time;
}

/**
 * nm_setting_bridge_get_max_age:
 * @setting: the #NMSettingBridge
 *
 * Returns: the #NMSettingBridge:max-age property of the setting
 **/
guint16
nm_setting_bridge_get_max_age (NMSettingBridge *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), 0);

	return NM_SETTING_BRIDGE_GET_PRIVATE (setting)->max_age;
}

/**
 * nm_setting_bridge_get_ageing_time:
 * @setting: the #NMSettingBridge
 *
 * Returns: the #NMSettingBridge:ageing-time property of the setting
 **/
guint
nm_setting_bridge_get_ageing_time (NMSettingBridge *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), 0);

	return NM_SETTING_BRIDGE_GET_PRIVATE (setting)->ageing_time;
}

/**
 * nm_setting_bridge_get_group_forward_mask:
 * @setting: the #NMSettingBridge
 *
 * Returns: the #NMSettingBridge:group-forward-mask property of the setting
 *
 * Since: 1.10
 **/
guint16
nm_setting_bridge_get_group_forward_mask (NMSettingBridge *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), 0);

	return NM_SETTING_BRIDGE_GET_PRIVATE (setting)->group_forward_mask;
}

/**
 * nm_setting_bridge_get_multicast_snooping:
 * @setting: the #NMSettingBridge
 *
 * Returns: the #NMSettingBridge:multicast-snooping property of the setting
 *
 * Since: 1.2
 **/
gboolean
nm_setting_bridge_get_multicast_snooping (NMSettingBridge *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), FALSE);

	return NM_SETTING_BRIDGE_GET_PRIVATE (setting)->multicast_snooping;
}

/**
 * nm_setting_bridge_get_vlan_filtering:
 * @setting: the #NMSettingBridge
 *
 * Returns: the #NMSettingBridge:vlan-filtering property of the setting
 *
 * Since: 1.18
 **/
gboolean
nm_setting_bridge_get_vlan_filtering (NMSettingBridge *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), FALSE);

	return NM_SETTING_BRIDGE_GET_PRIVATE (setting)->vlan_filtering;
}

/**
 * nm_setting_bridge_get_vlan_default_pvid:
 * @setting: the #NMSettingBridge
 *
 * Returns: the #NMSettingBridge:vlan-default-pvid property of the setting
 *
 * Since: 1.18
 **/
guint16
nm_setting_bridge_get_vlan_default_pvid (NMSettingBridge *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), 1);

	return NM_SETTING_BRIDGE_GET_PRIVATE (setting)->vlan_default_pvid;
}

/**
 * nm_setting_bridge_add_vlan:
 * @setting: the #NMSettingBridge
 * @vlan: the vlan to add
 *
 * Appends a new vlan and associated information to the setting.  The
 * given vlan gets sealed and a reference to it is added.
 *
 * Since: 1.18
 **/
void
nm_setting_bridge_add_vlan (NMSettingBridge *setting,
                            NMBridgeVlan *vlan)
{
	NMSettingBridgePrivate *priv;

	g_return_if_fail (NM_IS_SETTING_BRIDGE (setting));
	g_return_if_fail (vlan);

	priv = NM_SETTING_BRIDGE_GET_PRIVATE (setting);

	nm_bridge_vlan_seal (vlan);
	nm_bridge_vlan_ref (vlan);

	g_ptr_array_add (priv->vlans, vlan);
	_notify (setting, PROP_VLANS);
}

/**
 * nm_setting_bridge_get_num_vlans:
 * @setting: the #NMSettingBridge
 *
 * Returns: the number of VLANs
 *
 * Since: 1.18
 **/
guint
nm_setting_bridge_get_num_vlans (NMSettingBridge *setting)
{
	NMSettingBridgePrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), 0);
	priv = NM_SETTING_BRIDGE_GET_PRIVATE (setting);

	return priv->vlans->len;
}

/**
 * nm_setting_bridge_get_vlan:
 * @setting: the #NMSettingBridge
 * @idx: index number of the VLAN to return
 *
 * Returns: (transfer none): the VLAN at index @idx
 *
 * Since: 1.18
 **/
NMBridgeVlan *
nm_setting_bridge_get_vlan (NMSettingBridge *setting, guint idx)
{
	NMSettingBridgePrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), NULL);
	priv = NM_SETTING_BRIDGE_GET_PRIVATE (setting);

	g_return_val_if_fail (idx < priv->vlans->len, NULL);

	return priv->vlans->pdata[idx];
}

/**
 * nm_setting_bridge_remove_vlan:
 * @setting: the #NMSettingBridge
 * @idx: index number of the VLAN.
 *
 * Removes the vlan at index @idx.
 *
 * Since: 1.18
 **/
void
nm_setting_bridge_remove_vlan (NMSettingBridge *setting, guint idx)
{
	NMSettingBridgePrivate *priv;

	g_return_if_fail (NM_IS_SETTING_BRIDGE (setting));
	priv = NM_SETTING_BRIDGE_GET_PRIVATE (setting);

	g_return_if_fail (idx < priv->vlans->len);

	g_ptr_array_remove_index (priv->vlans, idx);
	_notify (setting, PROP_VLANS);
}

/**
 * nm_setting_bridge_remove_vlan_by_vid:
 * @setting: the #NMSettingBridge
 * @vid_start: the vlan start index
 * @vid_end: the vlan end index
 *
 * Remove the VLAN with range @vid_start to @vid_end.
 * If @vid_end is zero, it is assumed to be equal to @vid_start
 * and so the single-id VLAN with id @vid_start is removed.
 *
 * Returns: %TRUE if the vlan was found and removed; %FALSE otherwise
 *
 * Since: 1.18
 **/
gboolean
nm_setting_bridge_remove_vlan_by_vid (NMSettingBridge *setting,
                                      guint16 vid_start,
                                      guint16 vid_end)
{
	NMSettingBridgePrivate *priv;
	NMBridgeVlan *vlan;
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_BRIDGE (setting), FALSE);
	priv = NM_SETTING_BRIDGE_GET_PRIVATE (setting);

	if (vid_end == 0)
		vid_end = vid_start;

	for (i = 0; i < priv->vlans->len; i++) {
		vlan = (NMBridgeVlan *) priv->vlans->pdata[i];
		if (vlan->vid_start == vid_start && vlan->vid_end == vid_end) {
			g_ptr_array_remove_index (priv->vlans, i);
			_notify (setting, PROP_VLANS);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_bridge_clear_vlans:
 * @setting: the #NMSettingBridge
 *
 * Removes all configured VLANs.
 *
 * Since: 1.18
 **/
void
nm_setting_bridge_clear_vlans (NMSettingBridge *setting)
{
	NMSettingBridgePrivate *priv;

	g_return_if_fail (NM_IS_SETTING_BRIDGE (setting));
	priv = NM_SETTING_BRIDGE_GET_PRIVATE (setting);

	if (priv->vlans->len != 0) {
		g_ptr_array_set_size (priv->vlans, 0);
		_notify (setting, PROP_VLANS);
	}
}

/*****************************************************************************/

static gboolean
check_range (guint32 val,
             guint32 min,
             guint32 max,
             gboolean zero,
             const char *prop,
             GError **error)
{
	if (zero && val == 0)
		return TRUE;

	if (val < min || val > max) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("value '%d' is out of range <%d-%d>"),
		             val, min, max);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BRIDGE_SETTING_NAME, prop);
		return FALSE;
	}
	return TRUE;
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingBridgePrivate *priv = NM_SETTING_BRIDGE_GET_PRIVATE (setting);

	if (priv->mac_address && !nm_utils_hwaddr_valid (priv->mac_address, ETH_ALEN)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("is not a valid MAC address"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BRIDGE_SETTING_NAME, NM_SETTING_BRIDGE_MAC_ADDRESS);
		return FALSE;
	}

	if (!check_range (priv->forward_delay,
	                  NM_BR_MIN_FORWARD_DELAY,
	                  NM_BR_MAX_FORWARD_DELAY,
	                  !priv->stp,
	                  NM_SETTING_BRIDGE_FORWARD_DELAY,
	                  error))
		return FALSE;

	if (!check_range (priv->hello_time,
	                  NM_BR_MIN_HELLO_TIME,
	                  NM_BR_MAX_HELLO_TIME,
	                  !priv->stp,
	                  NM_SETTING_BRIDGE_HELLO_TIME,
	                  error))
		return FALSE;

	if (!check_range (priv->max_age,
	                  NM_BR_MIN_MAX_AGE,
	                  NM_BR_MAX_MAX_AGE,
	                  !priv->stp,
	                  NM_SETTING_BRIDGE_MAX_AGE,
	                  error))
		return FALSE;

	if (!check_range (priv->ageing_time,
	                  NM_BR_MIN_AGEING_TIME,
	                  NM_BR_MAX_AGEING_TIME,
	                  !priv->stp,
	                  NM_SETTING_BRIDGE_AGEING_TIME,
	                  error))
		return FALSE;

	if (priv->group_forward_mask & 7) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("the mask can't contain bits 0 (STP), 1 (MAC) or 2 (LACP)"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_BRIDGE_SETTING_NAME, NM_SETTING_BRIDGE_GROUP_FORWARD_MASK);
		return FALSE;
	}

	if (!_nm_connection_verify_required_interface_name (connection, error))
		return FALSE;

	if (!_nm_utils_bridge_vlan_verify_list (priv->vlans,
	                                        FALSE,
	                                        error,
	                                        NM_SETTING_BRIDGE_SETTING_NAME,
	                                        NM_SETTING_BRIDGE_VLANS))
		return FALSE;

	/* Failures from here on are NORMALIZABLE... */

	if (!_nm_utils_bridge_vlan_verify_list (priv->vlans,
	                                        TRUE,
	                                        error,
	                                        NM_SETTING_BRIDGE_SETTING_NAME,
	                                        NM_SETTING_BRIDGE_VLANS))
		return NM_SETTING_VERIFY_NORMALIZABLE;

	return TRUE;
}

static NMTernary
compare_property (const NMSettInfoSetting *sett_info,
                  guint property_idx,
                  NMConnection *con_a,
                  NMSetting *set_a,
                  NMConnection *con_b,
                  NMSetting *set_b,
                  NMSettingCompareFlags flags)
{
	NMSettingBridgePrivate *priv_a;
	NMSettingBridgePrivate *priv_b;
	guint i;

	if (nm_streq (sett_info->property_infos[property_idx].name, NM_SETTING_BRIDGE_VLANS)) {
		if (set_b) {
			priv_a = NM_SETTING_BRIDGE_GET_PRIVATE (set_a);
			priv_b = NM_SETTING_BRIDGE_GET_PRIVATE (set_b);

			if (priv_a->vlans->len != priv_b->vlans->len)
				return FALSE;
			for (i = 0; i < priv_a->vlans->len; i++) {
				if (nm_bridge_vlan_cmp (priv_a->vlans->pdata[i], priv_b->vlans->pdata[i]))
					return FALSE;
			}
		}
		return TRUE;
	}

	return NM_SETTING_CLASS (nm_setting_bridge_parent_class)->compare_property (sett_info,
	                                                                            property_idx,
	                                                                            con_a,
	                                                                            set_a,
	                                                                            con_b,
	                                                                            set_b,
	                                                                            flags);
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingBridgePrivate *priv = NM_SETTING_BRIDGE_GET_PRIVATE (object);
	NMSettingBridge *setting = NM_SETTING_BRIDGE (object);

	switch (prop_id) {
	case PROP_MAC_ADDRESS:
		g_value_set_string (value, nm_setting_bridge_get_mac_address (setting));
		break;
	case PROP_STP:
		g_value_set_boolean (value, priv->stp);
		break;
	case PROP_PRIORITY:
		g_value_set_uint (value, priv->priority);
		break;
	case PROP_FORWARD_DELAY:
		g_value_set_uint (value, priv->forward_delay);
		break;
	case PROP_HELLO_TIME:
		g_value_set_uint (value, priv->hello_time);
		break;
	case PROP_MAX_AGE:
		g_value_set_uint (value, priv->max_age);
		break;
	case PROP_AGEING_TIME:
		g_value_set_uint (value, priv->ageing_time);
		break;
	case PROP_GROUP_FORWARD_MASK:
		g_value_set_uint (value, priv->group_forward_mask);
		break;
	case PROP_MULTICAST_SNOOPING:
		g_value_set_boolean (value, priv->multicast_snooping);
		break;
	case PROP_VLAN_FILTERING:
		g_value_set_boolean (value, priv->vlan_filtering);
		break;
	case PROP_VLAN_DEFAULT_PVID:
		g_value_set_uint (value, priv->vlan_default_pvid);
		break;
	case PROP_VLANS:
		g_value_take_boxed (value, _nm_utils_copy_array (priv->vlans,
		                                                 (NMUtilsCopyFunc) nm_bridge_vlan_ref,
		                                                 (GDestroyNotify) nm_bridge_vlan_unref));
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
	NMSettingBridgePrivate *priv = NM_SETTING_BRIDGE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MAC_ADDRESS:
		g_free (priv->mac_address);
		priv->mac_address = _nm_utils_hwaddr_canonical_or_invalid (g_value_get_string (value),
		                                                           ETH_ALEN);
		break;
	case PROP_STP:
		priv->stp = g_value_get_boolean (value);
		break;
	case PROP_PRIORITY:
		priv->priority = (guint16) g_value_get_uint (value);
		break;
	case PROP_FORWARD_DELAY:
		priv->forward_delay = (guint16) g_value_get_uint (value);
		break;
	case PROP_HELLO_TIME:
		priv->hello_time = (guint16) g_value_get_uint (value);
		break;
	case PROP_MAX_AGE:
		priv->max_age = (guint16) g_value_get_uint (value);
		break;
	case PROP_AGEING_TIME:
		priv->ageing_time = g_value_get_uint (value);
		break;
	case PROP_GROUP_FORWARD_MASK:
		priv->group_forward_mask = (guint16) g_value_get_uint (value);
		break;
	case PROP_MULTICAST_SNOOPING:
		priv->multicast_snooping = g_value_get_boolean (value);
		break;
	case PROP_VLAN_FILTERING:
		priv->vlan_filtering = g_value_get_boolean (value);
		break;
	case PROP_VLAN_DEFAULT_PVID:
		priv->vlan_default_pvid = g_value_get_uint (value);
		break;
	case PROP_VLANS:
		g_ptr_array_unref (priv->vlans);
		priv->vlans = _nm_utils_copy_array (g_value_get_boxed (value),
		                                    (NMUtilsCopyFunc) _nm_bridge_vlan_dup_and_seal,
		                                    (GDestroyNotify) nm_bridge_vlan_unref);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_bridge_init (NMSettingBridge *setting)
{
	NMSettingBridgePrivate *priv = NM_SETTING_BRIDGE_GET_PRIVATE (setting);

	priv->vlans = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_bridge_vlan_unref);
}

/**
 * nm_setting_bridge_new:
 *
 * Creates a new #NMSettingBridge object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingBridge object
 **/
NMSetting *
nm_setting_bridge_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_BRIDGE, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingBridgePrivate *priv = NM_SETTING_BRIDGE_GET_PRIVATE (object);

	g_free (priv->mac_address);
	g_ptr_array_unref (priv->vlans);

	G_OBJECT_CLASS (nm_setting_bridge_parent_class)->finalize (object);
}

static void
nm_setting_bridge_class_init (NMSettingBridgeClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);
	GArray *properties_override = _nm_sett_info_property_override_create_array ();

	g_type_class_add_private (klass, sizeof (NMSettingBridgePrivate));

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize     = finalize;

	setting_class->compare_property = compare_property;
	setting_class->verify = verify;

	/**
	 * NMSettingBridge:mac-address:
	 *
	 * If specified, the MAC address of bridge. When creating a new bridge, this
	 * MAC address will be set.
	 *
	 * If this field is left unspecified, the "ethernet.cloned-mac-address" is
	 * referred instead to generate the initial MAC address. Note that setting
	 * "ethernet.cloned-mac-address" anyway overwrites the MAC address of
	 * the bridge later while activating the bridge. Hence, this property
	 * is deprecated.
	 *
	 * Deprecated: 1.12: Use the ethernet.cloned-mac-address property instead.
	 **/
	/* ---keyfile---
	 * property: mac-address
	 * format: usual hex-digits-and-colons notation
	 * description: MAC address in traditional hex-digits-and-colons notation,
	 *   or semicolon separated list of 6 decimal bytes (obsolete)
	 * example: mac-address=00:22:68:12:79:A2
	 *  mac-address=0;34;104;18;121;162;
	 * ---end---
	 * ---ifcfg-rh---
	 * property: mac-address
	 * variable: BRIDGE_MACADDR(+)
	 * description: MAC address of the bridge. Note that this requires a recent
	 *   kernel support, originally introduced in 3.15 upstream kernel)
	 *   BRIDGE_MACADDR for bridges is an NM extension.
	 * ---end---
	 */
	obj_properties[PROP_MAC_ADDRESS] =
	    g_param_spec_string (NM_SETTING_BRIDGE_MAC_ADDRESS, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_INFERRABLE |
	                         G_PARAM_STATIC_STRINGS);

	_properties_override_add_transform (properties_override,
	                                    obj_properties[PROP_MAC_ADDRESS],
	                                    G_VARIANT_TYPE_BYTESTRING,
	                                    _nm_utils_hwaddr_to_dbus,
	                                    _nm_utils_hwaddr_from_dbus);

	/**
	 * NMSettingBridge:stp:
	 *
	 * Controls whether Spanning Tree Protocol (STP) is enabled for this bridge.
	 **/
	/* ---ifcfg-rh---
	 * property: stp
	 * variable: STP
	 * default: no
	 * description: Span tree protocol participation.
	 * ---end---
	 */
	obj_properties[PROP_STP] =
	    g_param_spec_boolean (NM_SETTING_BRIDGE_STP, "", "",
	                          TRUE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT |
	                          NM_SETTING_PARAM_INFERRABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingBridge:priority:
	 *
	 * Sets the Spanning Tree Protocol (STP) priority for this bridge.  Lower
	 * values are "better"; the lowest priority bridge will be elected the root
	 * bridge.
	 **/
	/* ---ifcfg-rh---
	 * property: priority
	 * variable: BRIDGING_OPTS: priority=
	 * values: 0 - 32768
	 * default: 32768
	 * description: STP priority.
	 * ---end---
	 */
	obj_properties[PROP_PRIORITY] =
	    g_param_spec_uint (NM_SETTING_BRIDGE_PRIORITY, "", "",
	                       0, G_MAXUINT16, 0x8000,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_INFERRABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingBridge:forward-delay:
	 *
	 * The Spanning Tree Protocol (STP) forwarding delay, in seconds.
	 **/
	/* ---ifcfg-rh---
	 * property: forward-delay
	 * variable: DELAY
	 * values: 2 - 30
	 * default: 15
	 * description: STP forwarding delay.
	 * ---end---
	 */
	obj_properties[PROP_FORWARD_DELAY] =
	    g_param_spec_uint (NM_SETTING_BRIDGE_FORWARD_DELAY, "", "",
	                       0, NM_BR_MAX_FORWARD_DELAY, 15,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_INFERRABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingBridge:hello-time:
	 *
	 * The Spanning Tree Protocol (STP) hello time, in seconds.
	 **/
	/* ---ifcfg-rh---
	 * property: hello-time
	 * variable: BRIDGING_OPTS: hello_time=
	 * values: 1 - 10
	 * default: 2
	 * description: STP hello time.
	 * ---end---
	 */
	obj_properties[PROP_HELLO_TIME] =
	    g_param_spec_uint (NM_SETTING_BRIDGE_HELLO_TIME, "", "",
	                       0, NM_BR_MAX_HELLO_TIME, 2,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_INFERRABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingBridge:max-age:
	 *
	 * The Spanning Tree Protocol (STP) maximum message age, in seconds.
	 **/
	/* ---ifcfg-rh---
	 * property: max-age
	 * variable: BRIDGING_OPTS: max_age=
	 * values: 6 - 40
	 * default: 20
	 * description: STP maximum message age.
	 * ---end---
	 */
	obj_properties[PROP_MAX_AGE] =
	    g_param_spec_uint (NM_SETTING_BRIDGE_MAX_AGE, "", "",
	                       0, NM_BR_MAX_MAX_AGE, 20,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_INFERRABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingBridge:ageing-time:
	 *
	 * The Ethernet MAC address aging time, in seconds.
	 **/
	/* ---ifcfg-rh---
	 * property: ageing-time
	 * variable: BRIDGING_OPTS: ageing_time=
	 * values: 0 - 1000000
	 * default: 300
	 * description: Ethernet MAC ageing time.
	 * ---end---
	 */
	obj_properties[PROP_AGEING_TIME] =
	    g_param_spec_uint (NM_SETTING_BRIDGE_AGEING_TIME, "", "",
	                       NM_BR_MIN_AGEING_TIME, NM_BR_MAX_AGEING_TIME, 300,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_INFERRABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingBridge:group-forward-mask:
	 *
	 * A mask of group addresses to forward. Usually, group addresses in
	 * the range from 01:80:C2:00:00:00 to 01:80:C2:00:00:0F are not
	 * forwarded according to standards. This property is a mask of 16 bits,
	 * each corresponding to a group address in that range that must be
	 * forwarded. The mask can't have bits 0, 1 or 2 set because they are
	 * used for STP, MAC pause frames and LACP.
	 *
	 * Since: 1.10
	 **/
	obj_properties[PROP_GROUP_FORWARD_MASK] =
	    g_param_spec_uint (NM_SETTING_BRIDGE_GROUP_FORWARD_MASK, "", "",
	                       0, 0xFFFF, 0,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_INFERRABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingBridge:multicast-snooping:
	 *
	 * Controls whether IGMP snooping is enabled for this bridge.
	 * Note that if snooping was automatically disabled due to hash collisions,
	 * the system may refuse to enable the feature until the collisions are
	 * resolved.
	 *
	 * Since: 1.2
	 **/
	/* ---ifcfg-rh---
	 * property: multicast-snooping
	 * variable: BRIDGING_OPTS: multicast_snooping=
	 * values: 0 or 1
	 * default: 1
	 * description: IGMP snooping support.
	 * ---end---
	 */
	obj_properties[PROP_MULTICAST_SNOOPING] =
	    g_param_spec_boolean (NM_SETTING_BRIDGE_MULTICAST_SNOOPING, "", "",
	                          TRUE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT |
	                          NM_SETTING_PARAM_INFERRABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingBridge:vlan-filtering:
	 *
	 * Control whether VLAN filtering is enabled on the bridge.
	 *
	 * Since: 1.18
	 **/
	/* ---ifcfg-rh---
	 * property: vlan-filtering
	 * variable: BRIDGING_OPTS: vlan_filtering=
	 * values: 0 or 1
	 * default: 0
	 * description: VLAN filtering support.
	 * ---end---
	 */
	obj_properties[PROP_VLAN_FILTERING] =
	    g_param_spec_boolean (NM_SETTING_BRIDGE_VLAN_FILTERING, "", "",
	                          FALSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT |
	                          NM_SETTING_PARAM_INFERRABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingBridge:vlan-default-pvid:
	 *
	 * The default PVID for the ports of the bridge, that is the VLAN id
	 * assigned to incoming untagged frames.
	 *
	 * Since: 1.18
	 **/
	/* ---ifcfg-rh---
	 * property: vlan-default-pvid
	 * variable: BRIDGING_OPTS: default_pvid=
	 * values: 0 - 4094
	 * default: 1
	 * description: default VLAN PVID.
	 * ---end---
	 */
	obj_properties[PROP_VLAN_DEFAULT_PVID] =
	    g_param_spec_uint (NM_SETTING_BRIDGE_VLAN_DEFAULT_PVID, "", "",
	                       0, NM_BRIDGE_VLAN_VID_MAX, 1,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_INFERRABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingBridge:vlans: (type GPtrArray(NMBridgeVlan))
	 *
	 * Array of bridge VLAN objects. In addition to the VLANs
	 * specified here, the bridge will also have the default-pvid
	 * VLAN configured  by the bridge.vlan-default-pvid property.
	 *
	 * In nmcli the VLAN list can be specified with the following
	 * syntax:
	 *
	 *  $vid [pvid] [untagged] [, $vid [pvid] [untagged]]...
	 *
	 * where $vid is either a single id between 1 and 4094 or a
	 * range, represented as a couple of ids separated by a dash.
	 *
	 * Since: 1.18
	 **/
	/* ---ifcfg-rh---
	 * property: vlans
	 * variable: BRIDGE_VLANS
	 * description: List of VLANs on the bridge
	 * example: BRIDGE_VLANS="1 pvid untagged,20,300-400 untagged"
	 * ---end---
	 */
	obj_properties[PROP_VLANS] =
	    g_param_spec_boxed (NM_SETTING_BRIDGE_VLANS, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READWRITE |
	                        NM_SETTING_PARAM_INFERRABLE |
	                        G_PARAM_STATIC_STRINGS);

	_properties_override_add_override (properties_override,
	                                   obj_properties[PROP_VLANS],
	                                   G_VARIANT_TYPE ("aa{sv}"),
	                                   _nm_utils_bridge_vlans_to_dbus,
	                                   _nm_utils_bridge_vlans_from_dbus,
	                                   NULL);

	/* ---dbus---
	 * property: interface-name
	 * format: string
	 * description: Deprecated in favor of connection.interface-name, but can
	 *   be used for backward-compatibility with older daemons, to set the
	 *   bridge's interface name.
	 * ---end---
	 */
	_properties_override_add_dbus_only (properties_override,
	                                    "interface-name",
	                                    G_VARIANT_TYPE_STRING,
	                                    _nm_setting_get_deprecated_virtual_interface_name,
	                                    NULL);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit_full (setting_class, NM_META_SETTING_TYPE_BRIDGE,
	                               NULL, properties_override);
}
