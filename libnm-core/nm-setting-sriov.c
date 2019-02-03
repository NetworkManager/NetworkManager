/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program. If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Copyright 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-setting-sriov.h"

#include "nm-setting-private.h"
#include "nm-utils-private.h"

/**
 * SECTION:nm-setting-sriov
 * @short_description: Describes SR-IOV connection properties
 * @include: nm-setting-sriov.h
 **/

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMSettingSriov,
	PROP_TOTAL_VFS,
	PROP_VFS,
	PROP_AUTOPROBE_DRIVERS,
);

/**
 * NMSettingSriov:
 *
 * SR-IOV settings.
 *
 * Since: 1.14
 */
struct _NMSettingSriov {
	NMSetting parent;
	GPtrArray *vfs;
	guint total_vfs;
	NMTernary autoprobe_drivers;
};

struct _NMSettingSriovClass {
	NMSettingClass parent;
};

G_DEFINE_TYPE (NMSettingSriov, nm_setting_sriov, NM_TYPE_SETTING)

/*****************************************************************************/

G_DEFINE_BOXED_TYPE (NMSriovVF, nm_sriov_vf, nm_sriov_vf_dup, nm_sriov_vf_unref)

struct _NMSriovVF {
	guint refcount;
	guint index;
	GHashTable *attributes;
	GHashTable *vlans;
	guint *vlan_ids;
};

typedef struct {
	guint id;
	guint qos;
	NMSriovVFVlanProtocol protocol;
} VFVlan;

static guint
_vf_vlan_hash (gconstpointer ptr)
{
	return nm_hash_val (1348254767u, *((guint *) ptr));
}

static gboolean
_vf_vlan_equal (gconstpointer a, gconstpointer b)
{
	return *((guint *) a) == *((guint *) b);
}

static GHashTable *
_vf_vlan_create_hash (void)
{
	G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (VFVlan, id) == 0);
	return g_hash_table_new_full (_vf_vlan_hash,
	                              _vf_vlan_equal,
	                              NULL,
	                              nm_g_slice_free_fcn (VFVlan));
}

/**
 * nm_srio_vf_new:
 * @index: the VF index
 *
 * Creates a new #NMSriovVF object.
 *
 * Returns: (transfer full): the new #NMSriovVF object.
 *
 * Since: 1.14
 **/
NMSriovVF *
nm_sriov_vf_new (guint index)
{
	NMSriovVF *vf;

	vf = g_slice_new0 (NMSriovVF);
	vf->refcount = 1;
	vf->index = index;
	vf->attributes = g_hash_table_new_full (nm_str_hash,
	                                        g_str_equal,
	                                        g_free,
	                                        (GDestroyNotify) g_variant_unref);
	return vf;
}

/**
 * nm_sriov_vf_ref:
 * @vf: the #NMSriovVF
 *
 * Increases the reference count of the object.
 *
 * Since: 1.14
 **/
void
nm_sriov_vf_ref (NMSriovVF *vf)
{
	g_return_if_fail (vf);
	g_return_if_fail (vf->refcount > 0);

	vf->refcount++;
}

/**
 * nm_sriov_vf_unref:
 * @vf: the #NMSriovVF
 *
 * Decreases the reference count of the object.  If the reference count
 * reaches zero, the object will be destroyed.
 *
 * Since: 1.14
 **/
void
nm_sriov_vf_unref (NMSriovVF *vf)
{
	g_return_if_fail (vf);
	g_return_if_fail (vf->refcount > 0);

	vf->refcount--;
	if (vf->refcount == 0) {
		g_hash_table_unref (vf->attributes);
		if (vf->vlans)
			g_hash_table_unref (vf->vlans);
		g_free (vf->vlan_ids);
		g_slice_free (NMSriovVF, vf);
	}
}

/**
 * nm_sriov_vf_equal:
 * @vf: the #NMSriovVF
 * @other: the #NMSriovVF to compare @vf to.
 *
 * Determines if two #NMSriovVF objects have the same index,
 * attributes and VLANs.
 *
 * Returns: %TRUE if the objects contain the same values, %FALSE
 *    if they do not.
 *
 * Since: 1.14
 **/
gboolean
nm_sriov_vf_equal (const NMSriovVF *vf, const NMSriovVF *other)
{
	GHashTableIter iter;
	const char *key;
	GVariant *value, *value2;
	VFVlan *vlan, *vlan2;
	guint n_vlans;

	g_return_val_if_fail (vf, FALSE);
	g_return_val_if_fail (vf->refcount > 0, FALSE);
	g_return_val_if_fail (other, FALSE);
	g_return_val_if_fail (other->refcount > 0, FALSE);

	if (vf == other)
		return TRUE;

	if (vf->index != other->index)
		return FALSE;

	if (g_hash_table_size (vf->attributes) != g_hash_table_size (other->attributes))
		return FALSE;
	g_hash_table_iter_init (&iter, vf->attributes);
	while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &value)) {
		value2 = g_hash_table_lookup (other->attributes, key);
		if (!value2)
			return FALSE;
		if (!g_variant_equal (value, value2))
			return FALSE;
	}

	n_vlans = vf->vlans ? g_hash_table_size (vf->vlans) : 0u;
	if (n_vlans != (other->vlans ? g_hash_table_size (other->vlans) : 0u))
		return FALSE;
	if (n_vlans > 0) {
		g_hash_table_iter_init (&iter, vf->vlans);
		while (g_hash_table_iter_next (&iter, (gpointer *) &vlan, NULL)) {
			vlan2 = g_hash_table_lookup (other->vlans, vlan);
			if (!vlan2)
				return FALSE;
			if (   vlan->qos != vlan2->qos
			    || vlan->protocol != vlan2->protocol)
				return FALSE;
		}
	}

	return TRUE;
}

static void
vf_add_vlan (NMSriovVF *vf,
             guint vlan_id,
             guint qos,
             NMSriovVFVlanProtocol protocol)
{
	VFVlan *vlan;

	vlan = g_slice_new0 (VFVlan);
	vlan->id = vlan_id;
	vlan->qos = qos;
	vlan->protocol = protocol;

	if (!vf->vlans)
		vf->vlans = _vf_vlan_create_hash ();

	g_hash_table_add (vf->vlans, vlan);
	g_clear_pointer (&vf->vlan_ids, g_free);
}

/**
 * nm_sriov_vf_dup:
 * @vf: the #NMSriovVF
 *
 * Creates a copy of @vf.
 *
 * Returns: (transfer full): a copy of @vf
 *
 * Since: 1.14
 **/
NMSriovVF *
nm_sriov_vf_dup (const NMSriovVF *vf)
{
	NMSriovVF *copy;
	GHashTableIter iter;
	const char *name;
	GVariant *variant;
	VFVlan *vlan;

	g_return_val_if_fail (vf, NULL);
	g_return_val_if_fail (vf->refcount > 0, NULL);

	copy = nm_sriov_vf_new (vf->index);

	g_hash_table_iter_init (&iter, vf->attributes);
	while (g_hash_table_iter_next (&iter, (gpointer *) &name, (gpointer *) &variant))
		nm_sriov_vf_set_attribute (copy, name, variant);

	if (vf->vlans) {
		g_hash_table_iter_init (&iter, vf->vlans);
		while (g_hash_table_iter_next (&iter, (gpointer *) &vlan, NULL))
			vf_add_vlan (copy, vlan->id, vlan->qos, vlan->protocol);
	}

	return copy;
}

/**
 * nm_sriov_vf_get_index:
 * @vf: the #NMSriovVF
 *
 * Gets the index property of this VF object.
 *
 * Returns: the VF index
 *
 * Since: 1.14
 **/
guint
nm_sriov_vf_get_index (const NMSriovVF *vf)
{
	g_return_val_if_fail (vf, 0);
	g_return_val_if_fail (vf->refcount > 0, 0);

	return vf->index;
}

/**
 * nm_sriov_vf_set_attribute:
 * @vf: the #NMSriovVF
 * @name: the name of a route attribute
 * @value: (transfer none) (allow-none): the value
 *
 * Sets the named attribute on @vf to the given value.
 *
 * Since: 1.14
 **/
void
nm_sriov_vf_set_attribute (NMSriovVF *vf, const char *name, GVariant *value)
{
	g_return_if_fail (vf);
	g_return_if_fail (vf->refcount > 0);
	g_return_if_fail (name && *name != '\0');
	g_return_if_fail (!nm_streq (name, "index"));

	if (value) {
		g_hash_table_insert (vf->attributes,
		                     g_strdup (name),
		                     g_variant_ref_sink (value));
	} else
		g_hash_table_remove (vf->attributes, name);
}

/**
 * nm_sriov_vf_get_attribute_names:
 * @vf: the #NMSriovVF
 *
 * Gets an array of attribute names defined on @vf.
 *
 * Returns: (transfer container): a %NULL-terminated array of attribute names
 *
 * Since: 1.14
 **/
const char **
nm_sriov_vf_get_attribute_names (const NMSriovVF *vf)
{
	g_return_val_if_fail (vf, NULL);
	g_return_val_if_fail (vf->refcount > 0, NULL);

	return nm_utils_strdict_get_keys (vf->attributes, TRUE, NULL);
}

/**
 * nm_sriov_vf_get_attribute:
 * @vf: the #NMSriovVF
 * @name: the name of a VF attribute
 *
 * Gets the value of the attribute with name @name on @vf
 *
 * Returns: (transfer none): the value of the attribute with name @name on
 *   @vf, or %NULL if @vf has no such attribute.
 *
 * Since: 1.14
 **/
GVariant *
nm_sriov_vf_get_attribute (const NMSriovVF *vf, const char *name)
{
	g_return_val_if_fail (vf, NULL);
	g_return_val_if_fail (vf->refcount > 0, NULL);
	g_return_val_if_fail (name && *name != '\0', NULL);

	return g_hash_table_lookup (vf->attributes, name);
}

#define SRIOV_ATTR_SPEC_PTR(name, type, str_type) \
	&(NMVariantAttributeSpec) { name, type, FALSE, FALSE, FALSE, FALSE, str_type }

const NMVariantAttributeSpec * const _nm_sriov_vf_attribute_spec[] = {
	SRIOV_ATTR_SPEC_PTR (NM_SRIOV_VF_ATTRIBUTE_MAC,          G_VARIANT_TYPE_STRING,  'm'),
	SRIOV_ATTR_SPEC_PTR (NM_SRIOV_VF_ATTRIBUTE_SPOOF_CHECK,  G_VARIANT_TYPE_BOOLEAN,  0),
	SRIOV_ATTR_SPEC_PTR (NM_SRIOV_VF_ATTRIBUTE_TRUST,        G_VARIANT_TYPE_BOOLEAN,  0),
	SRIOV_ATTR_SPEC_PTR (NM_SRIOV_VF_ATTRIBUTE_MIN_TX_RATE,  G_VARIANT_TYPE_UINT32,   0),
	SRIOV_ATTR_SPEC_PTR (NM_SRIOV_VF_ATTRIBUTE_MAX_TX_RATE,  G_VARIANT_TYPE_UINT32,   0),
	/* D-Bus only, synthetic attributes */
	SRIOV_ATTR_SPEC_PTR ("vlans",                            G_VARIANT_TYPE_STRING,  'd'),
	NULL,
};

/**
 * nm_sriov_vf_attribute_validate:
 * @name: the attribute name
 * @value: the attribute value
 * @known: (out): on return, whether the attribute name is a known one
 * @error: (allow-none): return location for a #GError, or %NULL
 *
 * Validates a VF attribute, i.e. checks that the attribute is a known one,
 * the value is of the correct type and well-formed.
 *
 * Returns: %TRUE if the attribute is valid, %FALSE otherwise
 *
 * Since: 1.14
 */
gboolean
nm_sriov_vf_attribute_validate  (const char *name,
                                 GVariant *value,
                                 gboolean *known,
                                 GError **error)
{
	const NMVariantAttributeSpec *const *iter;
	const NMVariantAttributeSpec *spec = NULL;

	g_return_val_if_fail (name, FALSE);
	g_return_val_if_fail (value, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	for (iter = _nm_sriov_vf_attribute_spec; *iter; iter++) {
		if (nm_streq (name, (*iter)->name)) {
			spec = *iter;
			break;
		}
	}

	if (!spec || spec->str_type == 'd') {
		NM_SET_OUT (known, FALSE);
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_FAILED,
		                     _("unknown attribute"));
		return FALSE;
	}

	NM_SET_OUT (known, TRUE);

	if (!g_variant_is_of_type (value, spec->type)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_FAILED,
		             _("invalid attribute type '%s'"),
		             g_variant_get_type_string (value));
		return FALSE;
	}

	if (g_variant_type_equal (spec->type, G_VARIANT_TYPE_STRING)) {
		const char *string;

		switch (spec->str_type) {
		case 'm': /* MAC address */
			string = g_variant_get_string (value, NULL);
			if (!nm_utils_hwaddr_valid (string, -1)) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_FAILED,
				             _("'%s' is not a valid MAC address"),
				             string);
				return FALSE;
			}
			break;
		default:
			break;
		}
	}

	return TRUE;
}

gboolean
_nm_sriov_vf_attribute_validate_all (const NMSriovVF *vf, GError **error)
{
	GHashTableIter iter;
	const char *name;
	GVariant *variant;
	GVariant *min, *max;

	g_return_val_if_fail (vf, FALSE);
	g_return_val_if_fail (vf->refcount > 0, FALSE);

	g_hash_table_iter_init (&iter, vf->attributes);
	while (g_hash_table_iter_next (&iter, (gpointer *) &name, (gpointer *) &variant)) {
		if (!nm_sriov_vf_attribute_validate (name, variant, NULL, error)) {
			g_prefix_error (error, "attribute '%s':", name);
			return FALSE;
		}
	}

	min = g_hash_table_lookup (vf->attributes, NM_SRIOV_VF_ATTRIBUTE_MIN_TX_RATE);
	max = g_hash_table_lookup (vf->attributes, NM_SRIOV_VF_ATTRIBUTE_MAX_TX_RATE);
	if (   min
	    && max
	    && g_variant_get_uint32 (min) > g_variant_get_uint32 (max)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_FAILED,
		             "min_tx_rate is greater than max_tx_rate");
		return FALSE;
	}

	return TRUE;
}

/**
 * nm_sriov_vf_add_vlan:
 * @vf: the #NMSriovVF
 * @vlan_id: the VLAN id
 *
 * Adds a VLAN to the VF.
 *
 * Returns: %TRUE if the VLAN was added; %FALSE if it already existed
 *
 * Since: 1.14
 **/
gboolean
nm_sriov_vf_add_vlan (NMSriovVF *vf, guint vlan_id)
{
	g_return_val_if_fail (vf, FALSE);
	g_return_val_if_fail (vf->refcount > 0, FALSE);

	if (   vf->vlans
	    && g_hash_table_contains (vf->vlans, &vlan_id))
		return FALSE;

	vf_add_vlan (vf, vlan_id, 0, NM_SRIOV_VF_VLAN_PROTOCOL_802_1Q);

	return TRUE;
}

/**
 * nm_sriov_vf_remove_vlan:
 * @vf: the #NMSriovVF
 * @vlan_id: the VLAN id
 *
 * Removes a VLAN from a VF.
 *
 * Returns: %TRUE if the VLAN was removed, %FALSE if the VLAN @vlan_id
 *     did not belong to the VF.
 *
 * Since: 1.14
 */
gboolean
nm_sriov_vf_remove_vlan (NMSriovVF *vf, guint vlan_id)
{
	g_return_val_if_fail (vf, FALSE);
	g_return_val_if_fail (vf->refcount > 0, FALSE);

	if (   !vf->vlans
	    || !g_hash_table_remove (vf->vlans, &vlan_id))
		return FALSE;

	g_clear_pointer (&vf->vlan_ids, g_free);
	return TRUE;
}

static int
vlan_id_compare (gconstpointer a, gconstpointer b, gpointer user_data)
{
	guint id_a  = *(guint *) a;
	guint id_b  = *(guint *) b;

	if (id_a < id_b)
		return -1;
	else if (id_a > id_b)
		return 1;
	else return 0;
}

/**
 * nm_sriov_vf_get_vlan_ids:
 * @vf: the #NMSriovVF
 * @length: (out) (allow-none): on return, the number of VLANs configured
 *
 * Returns the VLANs currently configured on the VF.
 *
 * Returns: (transfer none): a list of VLAN ids configured on the VF.
 *
 * Since: 1.14
 */
const guint *
nm_sriov_vf_get_vlan_ids (const NMSriovVF *vf, guint *length)
{
	GHashTableIter iter;
	VFVlan *vlan;
	guint num, i;

	g_return_val_if_fail (vf, NULL);
	g_return_val_if_fail (vf->refcount > 0, NULL);

	num = vf->vlans ? g_hash_table_size (vf->vlans) : 0u;
	NM_SET_OUT (length, num);

	if (vf->vlan_ids)
		return vf->vlan_ids;
	if (num == 0)
		return NULL;

	/* vf is const, however, vlan_ids is a mutable field caching the
	 * result ("mutable" in C++ terminology) */
	((NMSriovVF *) vf)->vlan_ids = g_new0 (guint, num);

	i = 0;
	g_hash_table_iter_init (&iter, vf->vlans);
	while (g_hash_table_iter_next (&iter, (gpointer *) &vlan, NULL))
		vf->vlan_ids[i++] = vlan->id;

	nm_assert (num == i);

	g_qsort_with_data (vf->vlan_ids, num, sizeof (guint), vlan_id_compare, NULL);

	return vf->vlan_ids;
}

/**
 * nm_sriov_vf_set_vlan_qos:
 * @vf: the #NMSriovVF
 * @vlan_id: the VLAN id
 * @qos: a QoS (priority) value
 *
 * Sets a QoS value for the given VLAN.
 *
 * Since: 1.14
 */
void
nm_sriov_vf_set_vlan_qos (NMSriovVF *vf, guint vlan_id, guint32 qos)
{
	VFVlan *vlan;

	g_return_if_fail (vf);
	g_return_if_fail (vf->refcount > 0);

	if (   !vf->vlans
	    || !(vlan = g_hash_table_lookup (vf->vlans, &vlan_id)))
		g_return_if_reached ();

	vlan->qos = qos;
}

/**
 * nm_sriov_vf_set_vlan_protocol:
 * @vf: the #NMSriovVF
 * @vlan_id: the VLAN id
 * @protocol: the VLAN protocol
 *
 * Sets the protocol for the given VLAN.
 *
 * Since: 1.14
 */
void
nm_sriov_vf_set_vlan_protocol (NMSriovVF *vf, guint vlan_id, NMSriovVFVlanProtocol protocol)
{
	VFVlan *vlan;

	g_return_if_fail (vf);
	g_return_if_fail (vf->refcount > 0);

	if (   !vf->vlans
	    || !(vlan = g_hash_table_lookup (vf->vlans, &vlan_id)))
		g_return_if_reached ();

	vlan->protocol = protocol;
}

/**
 * nm_sriov_vf_get_vlan_qos:
 * @vf: the #NMSriovVF
 * @vlan_id: the VLAN id
 *
 * Returns the QoS value for the given VLAN.
 *
 * Returns: the QoS value
 *
 * Since: 1.14
 */
guint32
nm_sriov_vf_get_vlan_qos (const NMSriovVF *vf, guint vlan_id)
{
	VFVlan *vlan;

	g_return_val_if_fail (vf, 0);
	g_return_val_if_fail (vf->refcount > 0, 0);

	if (   !vf->vlans
	    || !(vlan = g_hash_table_lookup (vf->vlans, &vlan_id)))
		g_return_val_if_reached (0);

	return vlan->qos;
}

/*
 * nm_sriov_vf_get_vlan_protocol:
 * @vf: the #NMSriovVF
 * @vlan_id: the VLAN id
 *
 * Returns the configured protocol for the given VLAN.
 *
 * Returns: the configured protocol
 *
 * Since: 1.14
 */
NMSriovVFVlanProtocol
nm_sriov_vf_get_vlan_protocol (const NMSriovVF *vf, guint vlan_id)
{
	VFVlan *vlan;

	g_return_val_if_fail (vf, NM_SRIOV_VF_VLAN_PROTOCOL_802_1Q);
	g_return_val_if_fail (vf->refcount > 0, NM_SRIOV_VF_VLAN_PROTOCOL_802_1Q);

	if (   !vf->vlans
	    || !(vlan = g_hash_table_lookup (vf->vlans, &vlan_id)))
		g_return_val_if_reached (NM_SRIOV_VF_VLAN_PROTOCOL_802_1Q);

	return vlan->protocol;
}

/*****************************************************************************/

/**
 * nm_setting_sriov_get_total_vfs:
 * @setting: the #NMSettingSriov
 *
 * Returns the value contained in the #NMSettingSriov:total-vfs
 * property.
 *
 * Returns: the total number of SR-IOV virtual functions to create
 *
 * Since: 1.14
 **/
guint
nm_setting_sriov_get_total_vfs (NMSettingSriov *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_SRIOV (setting), 0);

	return setting->total_vfs;
}

/**
 * nm_setting_sriov_get_num_vfs:
 * @setting: the #NMSettingSriov
 *
 * Returns: the number of configured VFs
 *
 * Since: 1.14
 **/
guint
nm_setting_sriov_get_num_vfs (NMSettingSriov *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_SRIOV (setting), 0);

	return setting->vfs->len;
}

/**
 * nm_setting_sriov_get_vf:
 * @setting: the #NMSettingSriov
 * @idx: index number of the VF to return
 *
 * Returns: (transfer none): the VF at index @idx
 *
 * Since: 1.14
 **/
NMSriovVF *
nm_setting_sriov_get_vf (NMSettingSriov *setting, guint idx)
{
	g_return_val_if_fail (NM_IS_SETTING_SRIOV (setting), NULL);
	g_return_val_if_fail (idx < setting->vfs->len, NULL);

	return setting->vfs->pdata[idx];
}

/**
 * nm_setting_sriov_add_vf:
 * @setting: the #NMSettingSriov
 * @vf: the VF to add
 *
 * Appends a new VF and associated information to the setting.  The
 * given VF is duplicated internally and is not changed by this function.
 *
 * Since: 1.14
 **/
void
nm_setting_sriov_add_vf (NMSettingSriov *setting, NMSriovVF *vf)
{
	g_return_if_fail (NM_IS_SETTING_SRIOV (setting));
	g_return_if_fail (vf);
	g_return_if_fail (vf->refcount > 0);

	g_ptr_array_add (setting->vfs, nm_sriov_vf_dup (vf));
	_notify (setting, PROP_VFS);
}

/**
 * nm_setting_sriov_remove_vf:
 * @setting: the #NMSettingSriov
 * @idx: index number of the VF
 *
 * Removes the VF at index @idx.
 *
 * Since: 1.14
 **/
void
nm_setting_sriov_remove_vf (NMSettingSriov *setting, guint idx)
{
	g_return_if_fail (NM_IS_SETTING_SRIOV (setting));
	g_return_if_fail (idx < setting->vfs->len);

	g_ptr_array_remove_index (setting->vfs, idx);
	_notify (setting, PROP_VFS);
}

/**
 * nm_setting_sriov_remove_vf_by_index:
 * @setting: the #NMSettingSriov
 * @index: the VF index of the VF to remove
 *
 * Removes the VF with VF index @index.
 *
 * Returns: %TRUE if the VF was found and removed; %FALSE if it was not
 *
 * Since: 1.14
 **/
gboolean
nm_setting_sriov_remove_vf_by_index (NMSettingSriov *setting,
                                     guint index)
{
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_SRIOV (setting), FALSE);

	for (i = 0; i < setting->vfs->len; i++) {
		if (nm_sriov_vf_get_index  (setting->vfs->pdata[i]) == index) {
			g_ptr_array_remove_index (setting->vfs, i);
			_notify (setting, PROP_VFS);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_sriov_clear_vfs:
 * @setting: the #NMSettingSriov
 *
 * Removes all configured VFs.
 *
 * Since: 1.14
 **/
void
nm_setting_sriov_clear_vfs (NMSettingSriov *setting)
{
	g_return_if_fail (NM_IS_SETTING_SRIOV (setting));

	if (setting->vfs->len != 0) {
		g_ptr_array_set_size (setting->vfs, 0);
		_notify (setting, PROP_VFS);
	}
}

/**
 * nm_setting_sriov_get_autoprobe_drivers:
 * @setting: the #NMSettingSriov
 *
 * Returns the value contained in the #NMSettingSriov:autoprobe-drivers
 * property.
 *
 * Returns: the autoprobe-drivers property value
 *
 * Since: 1.14
 **/
NMTernary
nm_setting_sriov_get_autoprobe_drivers (NMSettingSriov *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_SRIOV (setting), NM_TERNARY_DEFAULT);

	return setting->autoprobe_drivers;
}

static gint
vf_index_compare (gconstpointer a, gconstpointer b)
{
	NMSriovVF *vf_a = *(NMSriovVF **) a;
	NMSriovVF *vf_b = *(NMSriovVF **) b;

	if (vf_a->index < vf_b->index)
		return -1;
	else if (vf_a->index > vf_b->index)
		return 1;
	else
		return 0;
}

gboolean
_nm_setting_sriov_sort_vfs (NMSettingSriov *setting)
{
	gboolean need_sort = FALSE;
	guint i;

	for (i = 1; i < setting->vfs->len; i++) {
		NMSriovVF *vf_prev = setting->vfs->pdata[i - 1];
		NMSriovVF *vf = setting->vfs->pdata[i];

		if (vf->index <= vf_prev->index) {
			need_sort = TRUE;
			break;
		}
	}

	if (need_sort)
		g_ptr_array_sort (setting->vfs, vf_index_compare);

	return need_sort;
}

/*****************************************************************************/

static GVariant *
vfs_to_dbus (NMSetting *setting, const char *property)
{
	gs_unref_ptrarray GPtrArray *vfs = NULL;
	GVariantBuilder builder;
	guint i;

	g_object_get (setting, NM_SETTING_SRIOV_VFS, &vfs, NULL);
	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aa{sv}"));

	if (vfs) {
		for (i = 0; i < vfs->len; i++) {
			gs_free const char **attr_names = NULL;
			NMSriovVF *vf = vfs->pdata[i];
			GVariantBuilder vf_builder;
			const guint *vlan_ids;
			const char **name;
			guint num_vlans = 0;

			g_variant_builder_init (&vf_builder, G_VARIANT_TYPE_VARDICT);
			g_variant_builder_add (&vf_builder, "{sv}", "index",
			                       g_variant_new_uint32 (nm_sriov_vf_get_index (vf)));

			attr_names = nm_utils_strdict_get_keys (vf->attributes, TRUE, NULL);
			if (attr_names) {
				for (name = attr_names; *name; name++) {
					g_variant_builder_add (&vf_builder,
					                       "{sv}",
					                       *name,
					                       nm_sriov_vf_get_attribute (vf, *name));
				}
			}

			/* VLANs are translated into an array of maps, where each map has
			 * keys 'id', 'qos' and 'proto'. This guarantees enough flexibility
			 * to accommodate any future new option. */
			vlan_ids = nm_sriov_vf_get_vlan_ids (vf, &num_vlans);
			if (num_vlans) {
				GVariantBuilder vlans_builder;
				guint j;

				g_variant_builder_init (&vlans_builder, G_VARIANT_TYPE ("aa{sv}"));
				for (j = 0; j < num_vlans; j++) {
					GVariantBuilder vlan_builder;

					g_variant_builder_init (&vlan_builder, G_VARIANT_TYPE ("a{sv}"));
					g_variant_builder_add (&vlan_builder,
					                       "{sv}", "id",
					                       g_variant_new_uint32 (vlan_ids[j]));
					g_variant_builder_add (&vlan_builder,
					                       "{sv}", "qos",
					                       g_variant_new_uint32 (nm_sriov_vf_get_vlan_qos (vf,
					                                                                       vlan_ids[j])));
					g_variant_builder_add (&vlan_builder,
					                       "{sv}", "protocol",
					                       g_variant_new_uint32 (nm_sriov_vf_get_vlan_protocol (vf,
					                                                                            vlan_ids[j])));
					g_variant_builder_add (&vlans_builder,
					                       "a{sv}",
					                       &vlan_builder);
				}
				g_variant_builder_add (&vf_builder , "{sv}", "vlans", g_variant_builder_end (&vlans_builder));
			}
			g_variant_builder_add (&builder, "a{sv}", &vf_builder);
		}
	}

	return g_variant_builder_end (&builder);
}

static gboolean
vfs_from_dbus (NMSetting *setting,
               GVariant *connection_dict,
               const char *property,
               GVariant *value,
               NMSettingParseFlags parse_flags,
               GError **error)
{
	GPtrArray *vfs;
	GVariantIter vf_iter;
	GVariant *vf_var;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("aa{sv}")), FALSE);

	vfs = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_sriov_vf_unref);
	g_variant_iter_init (&vf_iter, value);
	while (g_variant_iter_next (&vf_iter, "@a{sv}", &vf_var)) {
		NMSriovVF *vf;
		guint32 index;
		GVariantIter attr_iter;
		const char *attr_name;
		GVariant *attr_var, *vlans_var;

		if (!g_variant_lookup (vf_var, "index", "u", &index))
			goto next;

		vf = nm_sriov_vf_new (index);

		g_variant_iter_init (&attr_iter, vf_var);
		while (g_variant_iter_next (&attr_iter, "{&sv}", &attr_name, &attr_var)) {
			if (!NM_IN_STRSET (attr_name, "index", "vlans"))
				nm_sriov_vf_set_attribute (vf, attr_name, attr_var);
			g_variant_unref (attr_var);
		}

		if (g_variant_lookup (vf_var, "vlans", "@aa{sv}", &vlans_var)) {
			GVariantIter vlan_iter;
			GVariant *vlan_var;

			g_variant_iter_init (&vlan_iter, vlans_var);
			while (g_variant_iter_next (&vlan_iter, "@a{sv}", &vlan_var)) {
				NMSriovVFVlanProtocol proto = NM_SRIOV_VF_VLAN_PROTOCOL_802_1Q;
				gint64 vlan_id = -1;
				guint qos = 0;

				g_variant_iter_init (&attr_iter, vlan_var);
				while (g_variant_iter_next (&attr_iter, "{&sv}", &attr_name, &attr_var)) {
					if (   nm_streq (attr_name, "id")
					    && g_variant_is_of_type (attr_var, G_VARIANT_TYPE_UINT32))
						vlan_id = g_variant_get_uint32 (attr_var);
					else if (   nm_streq (attr_name, "qos")
					         && g_variant_is_of_type (attr_var, G_VARIANT_TYPE_UINT32))
						qos = g_variant_get_uint32 (attr_var);
					else if (   nm_streq (attr_name, "protocol")
					         && g_variant_is_of_type (attr_var, G_VARIANT_TYPE_UINT32))
						proto = g_variant_get_uint32 (attr_var);
					g_variant_unref (attr_var);
				}
				if (vlan_id != -1)
					vf_add_vlan (vf, vlan_id, qos, proto);
				g_variant_unref (vlan_var);
			}
			g_variant_unref (vlans_var);
		}

		g_ptr_array_add (vfs, vf);
next:
		g_variant_unref (vf_var);
	}

	g_object_set (setting, NM_SETTING_SRIOV_VFS, vfs, NULL);
	g_ptr_array_unref (vfs);

	return TRUE;
}

/*****************************************************************************/

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingSriov *self = NM_SETTING_SRIOV (setting);
	guint i;

	if (self->vfs->len) {
		gs_unref_hashtable GHashTable *h = NULL;

		h = g_hash_table_new (nm_direct_hash, NULL);
		for (i = 0; i < self->vfs->len; i++) {
			NMSriovVF *vf = self->vfs->pdata[i];
			gs_free_error GError *local = NULL;

			if (vf->index >= self->total_vfs) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("VF with index %u, but the total number of VFs is %u"),
				             vf->index, self->total_vfs);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_SRIOV_SETTING_NAME,
				                NM_SETTING_SRIOV_VFS);
				return FALSE;
			}

			if (!_nm_sriov_vf_attribute_validate_all (vf, &local)) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("invalid VF %u: %s"),
				             vf->index,
				             local->message);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_SRIOV_SETTING_NAME,
				                NM_SETTING_SRIOV_VFS);
				return FALSE;
			}

			if (g_hash_table_contains (h, GUINT_TO_POINTER (vf->index))) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("duplicate VF index %u"), vf->index);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_SRIOV_SETTING_NAME,
				                NM_SETTING_SRIOV_VFS);
				return FALSE;
			}

			g_hash_table_add (h, GUINT_TO_POINTER (vf->index));
		}
	}

	/* Failures from here on are NORMALIZABLE... */

	if (self->vfs->len) {
		for (i = 1; i < self->vfs->len; i++) {
			NMSriovVF *vf_prev = self->vfs->pdata[i - 1];
			NMSriovVF *vf = self->vfs->pdata[i];

			if (vf->index <= vf_prev->index) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("VFs %d and %d are not sorted by ascending index"),
				             vf_prev->index, vf->index);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_SRIOV_SETTING_NAME,
				                NM_SETTING_SRIOV_VFS);
				return NM_SETTING_VERIFY_NORMALIZABLE;
			}
		}
	}

	return TRUE;
}

static NMTernary
compare_property (const NMSettInfoSetting *sett_info,
                  guint property_idx,
                  NMSetting *setting,
                  NMSetting *other,
                  NMSettingCompareFlags flags)
{
	NMSettingSriov *a;
	NMSettingSriov *b;
	guint i;

	if (nm_streq (sett_info->property_infos[property_idx].name, NM_SETTING_SRIOV_VFS)) {
		if (other) {
			a = NM_SETTING_SRIOV (setting);
			b = NM_SETTING_SRIOV (other);

			if (a->vfs->len != b->vfs->len)
				return FALSE;
			for (i = 0; i < a->vfs->len; i++) {
				if (!nm_sriov_vf_equal (a->vfs->pdata[i], b->vfs->pdata[i]))
					return FALSE;
			}
		}
		return TRUE;
	}

	return NM_SETTING_CLASS (nm_setting_sriov_parent_class)->compare_property (sett_info,
	                                                                           property_idx,
	                                                                           setting,
	                                                                           other,
	                                                                           flags);
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingSriov *self = NM_SETTING_SRIOV (object);

	switch (prop_id) {
	case PROP_TOTAL_VFS:
		g_value_set_uint (value, self->total_vfs);
		break;
	case PROP_VFS:
		g_value_take_boxed (value, _nm_utils_copy_array (self->vfs,
		                                                 (NMUtilsCopyFunc) nm_sriov_vf_dup,
		                                                 (GDestroyNotify) nm_sriov_vf_unref));
		break;
	case PROP_AUTOPROBE_DRIVERS:
		g_value_set_enum (value, self->autoprobe_drivers);
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
	NMSettingSriov *self = NM_SETTING_SRIOV (object);

	switch (prop_id) {
	case PROP_TOTAL_VFS:
		self->total_vfs = g_value_get_uint (value);
		break;
	case PROP_VFS:
		g_ptr_array_unref (self->vfs);
		self->vfs = _nm_utils_copy_array (g_value_get_boxed (value),
		                                  (NMUtilsCopyFunc) nm_sriov_vf_dup,
		                                  (GDestroyNotify) nm_sriov_vf_unref);
		break;
	case PROP_AUTOPROBE_DRIVERS:
		self->autoprobe_drivers = g_value_get_enum (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_sriov_init (NMSettingSriov *setting)
{
	setting->vfs = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_sriov_vf_unref);
}

/**
 * nm_setting_sriov_new:
 *
 * Creates a new #NMSettingSriov object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingSriov object
 *
 * Since: 1.14
 **/
NMSetting *
nm_setting_sriov_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_SRIOV, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingSriov *self = NM_SETTING_SRIOV (object);

	g_ptr_array_unref (self->vfs);

	G_OBJECT_CLASS (nm_setting_sriov_parent_class)->finalize (object);
}

static void
nm_setting_sriov_class_init (NMSettingSriovClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);
	GArray *properties_override = _nm_sett_info_property_override_create_array ();

	object_class->get_property     = get_property;
	object_class->set_property     = set_property;
	object_class->finalize         = finalize;

	setting_class->compare_property = compare_property;
	setting_class->verify           = verify;

	/**
	 * NMSettingSriov:total-vfs
	 *
	 * The total number of virtual functions to create.
	 *
	 * Note that when the sriov setting is present NetworkManager
	 * enforces the number of virtual functions on the interface
	 * also when it is zero. To prevent any changes to SR-IOV
	 * parameters don't add a sriov setting to the connection.
	 *
	 * Since: 1.14
	 **/
	/* ---ifcfg-rh---
	 * property: total-vfs
	 * variable: SRIOV_TOTAL_VFS(+)
	 * description: The total number of virtual functions to create
	 * example: SRIOV_TOTAL_VFS=16
	 * ---end---
	 */
	obj_properties[PROP_TOTAL_VFS] =
	    g_param_spec_uint (NM_SETTING_SRIOV_TOTAL_VFS, "", "",
	                       0, G_MAXUINT32, 0,
	                       NM_SETTING_PARAM_FUZZY_IGNORE |
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingSriov:vfs: (type GPtrArray(NMSriovVF))
	 *
	 * Array of virtual function descriptors.
	 *
	 * Each VF descriptor is a dictionary mapping attribute names
	 * to GVariant values. The 'index' entry is mandatory for
	 * each VF.
	 *
	 * When represented as string a VF is in the form:
	 *
	 *   "INDEX [ATTR=VALUE[ ATTR=VALUE]...]".
	 *
	 * for example:
	 *
	 *   "2 mac=00:11:22:33:44:55 spoof-check=true".
	 *
	 * Multiple VFs can be specified using a comma as separator.
	 * Currently the following attributes are supported: mac,
	 * spoof-check, trust, min-tx-rate, max-tx-rate, vlans.
	 *
	 * The "vlans" attribute is represented as a semicolon-separated
	 * list of VLAN descriptors, where each descriptor has the form
	 *
	 *   "ID[.PRIORITY[.PROTO]]".
	 *
	 * PROTO can be either 'q' for 802.1Q (the default) or 'ad' for
	 * 802.1ad.
	 *

	 * Since: 1.14
	 **/
	/* ---ifcfg-rh---
	 * property: vfs
	 * variable: SRIOV_VF1(+), SRIOV_VF2(+), ...
	 * description: SR-IOV virtual function descriptors
	 * example: SRIOV_VF10="mac=00:11:22:33:44:55", ...
	 * ---end---
	 */
	obj_properties[PROP_VFS] =
	    g_param_spec_boxed (NM_SETTING_SRIOV_VFS, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READWRITE |
	                        NM_SETTING_PARAM_INFERRABLE |
	                        G_PARAM_STATIC_STRINGS);

	_properties_override_add_override (properties_override,
	                                   obj_properties[PROP_VFS],
	                                   G_VARIANT_TYPE ("aa{sv}"),
	                                   vfs_to_dbus,
	                                   vfs_from_dbus,
	                                   NULL);

	/**
	 * NMSettingSriov:autoprobe-drivers
	 *
	 * Whether to autoprobe virtual functions by a compatible driver.
	 *
	 * If set to %NM_TERNARY_TRUE, the kernel will try to bind VFs to
	 * a compatible driver and if this succeeds a new network
	 * interface will be instantiated for each VF.
	 *
	 * If set to %NM_TERNARY_FALSE, VFs will not be claimed and no
	 * network interfaces will be created for them.
	 *
	 * When set to %NM_TERNARY_DEFAULT, the global default is used; in
	 * case the global default is unspecified it is assumed to be
	 * %NM_TERNARY_TRUE.
	 *
	 * Since: 1.14
	 **/
	/* ---ifcfg-rh---
	 * property: autoprobe-drivers
	 * variable: SRIOV_AUTOPROBE_DRIVERS(+)
	 * default: missing variable means global default
	 * description: Whether to autoprobe virtual functions by a compatible driver
	 * example: SRIOV_AUTOPROBE_DRIVERS=0,1
	 * ---end---
	 */
	obj_properties[PROP_AUTOPROBE_DRIVERS] =
	    g_param_spec_enum (NM_SETTING_SRIOV_AUTOPROBE_DRIVERS, "", "",
	                       nm_ternary_get_type (),
	                       NM_TERNARY_DEFAULT,
	                       NM_SETTING_PARAM_FUZZY_IGNORE |
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit_full (setting_class, NM_META_SETTING_TYPE_SRIOV,
	                               NULL, properties_override);
}
