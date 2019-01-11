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
 * Copyright 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-setting-tc-config.h"

#include <linux/pkt_sched.h>

#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-tc-config
 * @short_description: Describes connection properties for the Linux Traffic Control
 * @include: nm-setting-tc-config.h
 **/

/*****************************************************************************/

G_DEFINE_BOXED_TYPE (NMTCQdisc, nm_tc_qdisc, nm_tc_qdisc_dup, nm_tc_qdisc_unref)

struct NMTCQdisc {
	guint refcount;

	char *kind;
	guint32 handle;
	guint32 parent;
};

/**
 * nm_tc_qdisc_new:
 * @kind: name of the queueing discipline
 * @parent: the parent queueing discipline
 * @error: location to store error, or %NULL
 *
 * Creates a new #NMTCQdisc object.
 *
 * Returns: (transfer full): the new #NMTCQdisc object, or %NULL on error
 *
 * Since: 1.12
 **/
NMTCQdisc *
nm_tc_qdisc_new (const char *kind,
                 guint32 parent,
                 GError **error)
{
	NMTCQdisc *qdisc;

	if (!kind || !*kind || strchr (kind, ' ') || strchr (kind, '\t')) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid kind"), kind);
		return NULL;
	}

	if (!parent) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("parent handle missing"));
		return NULL;
	}

	qdisc = g_slice_new0 (NMTCQdisc);
	qdisc->refcount = 1;

	qdisc->kind = g_strdup (kind);
	qdisc->parent = parent;

	return qdisc;
}

/**
 * nm_tc_qdisc_ref:
 * @qdisc: the #NMTCQdisc
 *
 * Increases the reference count of the object.
 *
 * Since: 1.12
 **/
void
nm_tc_qdisc_ref (NMTCQdisc *qdisc)
{
	g_return_if_fail (qdisc != NULL);
	g_return_if_fail (qdisc->refcount > 0);

	qdisc->refcount++;
}

/**
 * nm_tc_qdisc_unref:
 * @qdisc: the #NMTCQdisc
 *
 * Decreases the reference count of the object.  If the reference count
 * reaches zero, the object will be destroyed.
 *
 * Since: 1.12
 **/
void
nm_tc_qdisc_unref (NMTCQdisc *qdisc)
{
	g_return_if_fail (qdisc != NULL);
	g_return_if_fail (qdisc->refcount > 0);

	qdisc->refcount--;
	if (qdisc->refcount == 0) {
		g_free (qdisc->kind);
		g_slice_free (NMTCQdisc, qdisc);
	}
}

/**
 * nm_tc_qdisc_equal:
 * @qdisc: the #NMTCQdisc
 * @other: the #NMTCQdisc to compare @qdisc to.
 *
 * Determines if two #NMTCQdisc objects contain the same kind, * handle
 * and parent.
 *
 * Returns: %TRUE if the objects contain the same values, %FALSE if they do not.
 *
 * Since: 1.12
 **/
gboolean
nm_tc_qdisc_equal (NMTCQdisc *qdisc, NMTCQdisc *other)
{
	g_return_val_if_fail (qdisc != NULL, FALSE);
	g_return_val_if_fail (qdisc->refcount > 0, FALSE);

	g_return_val_if_fail (other != NULL, FALSE);
	g_return_val_if_fail (other->refcount > 0, FALSE);

	if (   qdisc->handle != other->handle
	    || qdisc->parent != other->parent
	    || g_strcmp0 (qdisc->kind, other->kind) != 0)
		return FALSE;

	return TRUE;
}

static guint
_nm_tc_qdisc_hash (NMTCQdisc *qdisc)
{
	NMHashState h;

	nm_hash_init (&h, 43869703);
	nm_hash_update_vals (&h,
	                     qdisc->handle,
	                     qdisc->parent);
	nm_hash_update_str0 (&h, qdisc->kind);
	return nm_hash_complete (&h);
}

/**
 * nm_tc_qdisc_dup:
 * @qdisc: the #NMTCQdisc
 *
 * Creates a copy of @qdisc
 *
 * Returns: (transfer full): a copy of @qdisc
 *
 * Since: 1.12
 **/
NMTCQdisc *
nm_tc_qdisc_dup (NMTCQdisc *qdisc)
{
	NMTCQdisc *copy;

	g_return_val_if_fail (qdisc != NULL, NULL);
	g_return_val_if_fail (qdisc->refcount > 0, NULL);

	copy = nm_tc_qdisc_new (qdisc->kind, qdisc->parent, NULL);
	nm_tc_qdisc_set_handle (copy, qdisc->handle);

	return copy;
}

/**
 * nm_tc_qdisc_get_kind:
 * @qdisc: the #NMTCQdisc
 *
 * Returns:
 *
 * Since: 1.12
 **/
const char *
nm_tc_qdisc_get_kind (NMTCQdisc *qdisc)
{
	g_return_val_if_fail (qdisc != NULL, NULL);
	g_return_val_if_fail (qdisc->refcount > 0, NULL);

	return qdisc->kind;
}

/**
 * nm_tc_qdisc_get_handle:
 * @qdisc: the #NMTCQdisc
 *
 * Returns: the queueing discipline handle
 *
 * Since: 1.12
 **/
guint32
nm_tc_qdisc_get_handle (NMTCQdisc *qdisc)
{
	g_return_val_if_fail (qdisc != NULL, TC_H_UNSPEC);
	g_return_val_if_fail (qdisc->refcount > 0, TC_H_UNSPEC);

	return qdisc->handle;
}

/**
 * nm_tc_qdisc_set_handle:
 * @qdisc: the #NMTCQdisc
 * @handle: the queueing discipline handle
 *
 * Sets the queueing discipline handle.
 *
 * Since: 1.12
 **/
void
nm_tc_qdisc_set_handle (NMTCQdisc *qdisc, guint32 handle)
{
	g_return_if_fail (qdisc != NULL);
	g_return_if_fail (qdisc->refcount > 0);

	qdisc->handle = handle;
}

/**
 * nm_tc_qdisc_get_parent:
 * @qdisc: the #NMTCQdisc
 *
 * Returns: the parent class
 *
 * Since: 1.12
 **/
guint32
nm_tc_qdisc_get_parent (NMTCQdisc *qdisc)
{
	g_return_val_if_fail (qdisc != NULL, TC_H_UNSPEC);
	g_return_val_if_fail (qdisc->refcount > 0, TC_H_UNSPEC);

	return qdisc->parent;
}

/*****************************************************************************/

G_DEFINE_BOXED_TYPE (NMTCAction, nm_tc_action, nm_tc_action_dup, nm_tc_action_unref)

struct NMTCAction {
	guint refcount;

	char *kind;

	GHashTable *attributes;
};

/**
 * nm_tc_action_new:
 * @kind: name of the queueing discipline
 * @error: location to store error, or %NULL
 *
 * Creates a new #NMTCAction object.
 *
 * Returns: (transfer full): the new #NMTCAction object, or %NULL on error
 *
 * Since: 1.12
 **/
NMTCAction *
nm_tc_action_new (const char *kind,
                  GError **error)
{
	NMTCAction *action;

	if (!kind || !*kind || strchr (kind, ' ') || strchr (kind, '\t')) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid kind"), kind);
		return NULL;
	}

	action = g_slice_new0 (NMTCAction);
	action->refcount = 1;

	action->kind = g_strdup (kind);

	return action;
}

/**
 * nm_tc_action_ref:
 * @action: the #NMTCAction
 *
 * Increases the reference count of the object.
 *
 * Since: 1.12
 **/
void
nm_tc_action_ref (NMTCAction *action)
{
	g_return_if_fail (action != NULL);
	g_return_if_fail (action->refcount > 0);

	action->refcount++;
}

/**
 * nm_tc_action_unref:
 * @action: the #NMTCAction
 *
 * Decreases the reference count of the object.  If the reference count
 * reaches zero, the object will be destroyed.
 *
 * Since: 1.12
 **/
void
nm_tc_action_unref (NMTCAction *action)
{
	g_return_if_fail (action != NULL);
	g_return_if_fail (action->refcount > 0);

	action->refcount--;
	if (action->refcount == 0) {
		g_free (action->kind);
		if (action->attributes)
			g_hash_table_unref (action->attributes);
		g_slice_free (NMTCAction, action);
	}
}

/**
 * nm_tc_action_equal:
 * @action: the #NMTCAction
 * @other: the #NMTCAction to compare @action to.
 *
 * Determines if two #NMTCAction objects contain the same kind, family,
 * handle, parent and info.
 *
 * Returns: %TRUE if the objects contain the same values, %FALSE if they do not.
 *
 * Since: 1.12
 **/
gboolean
nm_tc_action_equal (NMTCAction *action, NMTCAction *other)
{
	GHashTableIter iter;
	const char *key;
	GVariant *value, *value2;
	guint n;

	g_return_val_if_fail (!action || action->refcount > 0, FALSE);
	g_return_val_if_fail (!other || other->refcount > 0, FALSE);

	if (action == other)
		return TRUE;
	if (!action || !other)
		return FALSE;

	if (g_strcmp0 (action->kind, other->kind) != 0)
		return FALSE;

	n = action->attributes ? g_hash_table_size (action->attributes) : 0;
	if (n != (other->attributes ? g_hash_table_size (other->attributes) : 0))
		return FALSE;
	if (n) {
		g_hash_table_iter_init (&iter, action->attributes);
		while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &value)) {
			value2 = g_hash_table_lookup (other->attributes, key);
			if (!value2)
				return FALSE;
			if (!g_variant_equal (value, value2))
				return FALSE;
		}
	}

	return TRUE;
}

/**
 * nm_tc_action_dup:
 * @action: the #NMTCAction
 *
 * Creates a copy of @action
 *
 * Returns: (transfer full): a copy of @action
 *
 * Since: 1.12
 **/
NMTCAction *
nm_tc_action_dup (NMTCAction *action)
{
	NMTCAction *copy;

	g_return_val_if_fail (action != NULL, NULL);
	g_return_val_if_fail (action->refcount > 0, NULL);

	copy = nm_tc_action_new (action->kind, NULL);

	if (action->attributes) {
		GHashTableIter iter;
		const char *key;
		GVariant *value;

		g_hash_table_iter_init (&iter, action->attributes);
		while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &value))
			nm_tc_action_set_attribute (copy, key, value);
	}

	return copy;
}

/**
 * nm_tc_action_get_kind:
 * @action: the #NMTCAction
 *
 * Returns:
 *
 * Since: 1.12
 **/
const char *
nm_tc_action_get_kind (NMTCAction *action)
{
	g_return_val_if_fail (action != NULL, NULL);
	g_return_val_if_fail (action->refcount > 0, NULL);

	return action->kind;
}

/**
 * nm_tc_action_get_attribute_names:
 * @action: the #NMTCAction
 *
 * Gets an array of attribute names defined on @action.
 *
 * Returns: (transfer full): a %NULL-terminated array of attribute names,
 **/
char **
nm_tc_action_get_attribute_names (NMTCAction *action)
{
	const char **names;

	g_return_val_if_fail (action, NULL);

	names = nm_utils_strdict_get_keys (action->attributes, TRUE, NULL);
	return nm_utils_strv_make_deep_copied_nonnull (names);
}

/**
 * nm_tc_action_get_attribute:
 * @action: the #NMTCAction
 * @name: the name of an action attribute
 *
 * Gets the value of the attribute with name @name on @action
 *
 * Returns: (transfer none): the value of the attribute with name @name on
 *   @action, or %NULL if @action has no such attribute.
 **/
GVariant *
nm_tc_action_get_attribute (NMTCAction *action, const char *name)
{
	g_return_val_if_fail (action != NULL, NULL);
	g_return_val_if_fail (name != NULL && *name != '\0', NULL);

	if (action->attributes)
		return g_hash_table_lookup (action->attributes, name);
	else
		return NULL;
}

/**
 * nm_tc_action_set_attribute:
 * @action: the #NMTCAction
 * @name: the name of an action attribute
 * @value: (transfer none) (allow-none): the value
 *
 * Sets or clears the named attribute on @action to the given value.
 **/
void
nm_tc_action_set_attribute (NMTCAction *action, const char *name, GVariant *value)
{
	g_return_if_fail (action != NULL);
	g_return_if_fail (name != NULL && *name != '\0');
	g_return_if_fail (strcmp (name, "kind") != 0);

	if (!action->attributes) {
		action->attributes = g_hash_table_new_full (nm_str_hash, g_str_equal,
		                                             g_free, (GDestroyNotify) g_variant_unref);
	}

	if (value)
		g_hash_table_insert (action->attributes, g_strdup (name), g_variant_ref_sink (value));
	else
		g_hash_table_remove (action->attributes, name);
}

/*****************************************************************************/

G_DEFINE_BOXED_TYPE (NMTCTfilter, nm_tc_tfilter, nm_tc_tfilter_dup, nm_tc_tfilter_unref)

struct NMTCTfilter {
	guint refcount;

	char *kind;
	guint32 handle;
	guint32 parent;
	NMTCAction *action;
};

/**
 * nm_tc_tfilter_new:
 * @kind: name of the queueing discipline
 * @parent: the parent queueing discipline
 * @error: location to store error, or %NULL
 *
 * Creates a new #NMTCTfilter object.
 *
 * Returns: (transfer full): the new #NMTCTfilter object, or %NULL on error
 *
 * Since: 1.12
 **/
NMTCTfilter *
nm_tc_tfilter_new (const char *kind,
                   guint32 parent,
                   GError **error)
{
	NMTCTfilter *tfilter;

	if (!kind || !*kind || strchr (kind, ' ') || strchr (kind, '\t')) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid kind"), kind);
		return NULL;
	}

	if (!parent) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("parent handle missing"));
		return NULL;
	}

	tfilter = g_slice_new0 (NMTCTfilter);
	tfilter->refcount = 1;

	tfilter->kind = g_strdup (kind);
	tfilter->parent = parent;

	return tfilter;
}

/**
 * nm_tc_tfilter_ref:
 * @tfilter: the #NMTCTfilter
 *
 * Increases the reference count of the object.
 *
 * Since: 1.12
 **/
void
nm_tc_tfilter_ref (NMTCTfilter *tfilter)
{
	g_return_if_fail (tfilter != NULL);
	g_return_if_fail (tfilter->refcount > 0);

	tfilter->refcount++;
}

/**
 * nm_tc_tfilter_unref:
 * @tfilter: the #NMTCTfilter
 *
 * Decreases the reference count of the object.  If the reference count
 * reaches zero, the object will be destroyed.
 *
 * Since: 1.12
 **/
void
nm_tc_tfilter_unref (NMTCTfilter *tfilter)
{
	g_return_if_fail (tfilter != NULL);
	g_return_if_fail (tfilter->refcount > 0);

	tfilter->refcount--;
	if (tfilter->refcount == 0) {
		g_free (tfilter->kind);
		if (tfilter->action)
			nm_tc_action_unref (tfilter->action);
		g_slice_free (NMTCTfilter, tfilter);
	}
}

/**
 * nm_tc_tfilter_equal:
 * @tfilter: the #NMTCTfilter
 * @other: the #NMTCTfilter to compare @tfilter to.
 *
 * Determines if two #NMTCTfilter objects contain the same kind, family,
 * handle, parent and info.
 *
 * Returns: %TRUE if the objects contain the same values, %FALSE if they do not.
 *
 * Since: 1.12
 **/
gboolean
nm_tc_tfilter_equal (NMTCTfilter *tfilter, NMTCTfilter *other)
{
	g_return_val_if_fail (tfilter != NULL, FALSE);
	g_return_val_if_fail (tfilter->refcount > 0, FALSE);

	g_return_val_if_fail (other != NULL, FALSE);
	g_return_val_if_fail (other->refcount > 0, FALSE);

	if (   tfilter->handle != other->handle
	    || tfilter->parent != other->parent
	    || g_strcmp0 (tfilter->kind, other->kind) != 0
	    || !nm_tc_action_equal (tfilter->action, other->action))
		return FALSE;

	return TRUE;
}

static guint
_nm_tc_tfilter_hash (NMTCTfilter *tfilter)
{
	gs_free const char **names = NULL;
	guint i, attr_hash;
	GVariant *variant;
	NMHashState h;
	guint length;

	nm_hash_init (&h, 63624437);
	nm_hash_update_vals (&h,
	                     tfilter->handle,
	                     tfilter->parent);
	nm_hash_update_str0 (&h, tfilter->kind);
	if (tfilter->action) {
		nm_hash_update_str0 (&h, tfilter->action->kind);
		names = nm_utils_strdict_get_keys (tfilter->action->attributes, TRUE, &length);
		for (i = 0; i < length; i++) {
			nm_hash_update_str (&h, names[i]);
			variant = g_hash_table_lookup (tfilter->action->attributes, names[i]);
			if (g_variant_type_is_basic (g_variant_get_type (variant))) {
				/* g_variant_hash() works only for basic types, thus
				 * we ignore any non-basic attribute. Actions differing
				 * only for non-basic attributes will collide. */
				attr_hash = g_variant_hash (variant);
				nm_hash_update_val (&h, attr_hash);
			}
		}
	}
	return nm_hash_complete (&h);
}

/**
 * nm_tc_tfilter_dup:
 * @tfilter: the #NMTCTfilter
 *
 * Creates a copy of @tfilter
 *
 * Returns: (transfer full): a copy of @tfilter
 *
 * Since: 1.12
 **/
NMTCTfilter *
nm_tc_tfilter_dup (NMTCTfilter *tfilter)
{
	NMTCTfilter *copy;

	g_return_val_if_fail (tfilter != NULL, NULL);
	g_return_val_if_fail (tfilter->refcount > 0, NULL);

	copy = nm_tc_tfilter_new (tfilter->kind, tfilter->parent, NULL);
	nm_tc_tfilter_set_handle (copy, tfilter->handle);
	nm_tc_tfilter_set_action (copy, tfilter->action);

	return copy;
}

/**
 * nm_tc_tfilter_get_kind:
 * @tfilter: the #NMTCTfilter
 *
 * Returns:
 *
 * Since: 1.12
 **/
const char *
nm_tc_tfilter_get_kind (NMTCTfilter *tfilter)
{
	g_return_val_if_fail (tfilter != NULL, NULL);
	g_return_val_if_fail (tfilter->refcount > 0, NULL);

	return tfilter->kind;
}

/**
 * nm_tc_tfilter_get_handle:
 * @tfilter: the #NMTCTfilter
 *
 * Returns: the queueing discipline handle
 *
 * Since: 1.12
 **/
guint32
nm_tc_tfilter_get_handle (NMTCTfilter *tfilter)
{
	g_return_val_if_fail (tfilter != NULL, TC_H_UNSPEC);
	g_return_val_if_fail (tfilter->refcount > 0, TC_H_UNSPEC);

	return tfilter->handle;
}

/**
 * nm_tc_tfilter_set_handle:
 * @tfilter: the #NMTCTfilter
 * @handle: the queueing discipline handle
 *
 * Sets the queueing discipline handle.
 *
 * Since: 1.12
 **/
void
nm_tc_tfilter_set_handle (NMTCTfilter *tfilter, guint32 handle)
{
	g_return_if_fail (tfilter != NULL);
	g_return_if_fail (tfilter->refcount > 0);

	tfilter->handle = handle;
}

/**
 * nm_tc_tfilter_get_parent:
 * @tfilter: the #NMTCTfilter
 *
 * Returns: the parent class
 *
 * Since: 1.12
 **/
guint32
nm_tc_tfilter_get_parent (NMTCTfilter *tfilter)
{
	g_return_val_if_fail (tfilter != NULL, TC_H_UNSPEC);
	g_return_val_if_fail (tfilter->refcount > 0, TC_H_UNSPEC);

	return tfilter->parent;
}

/**
 * nm_tc_tfilter_get_action:
 * @tfilter: the #NMTCTfilter
 *
 * Returns: the action associated with a traffic filter.
 *
 * Since: 1.12
 **/
NMTCAction *
nm_tc_tfilter_get_action (NMTCTfilter *tfilter)
{
	g_return_val_if_fail (tfilter != NULL, TC_H_UNSPEC);
	g_return_val_if_fail (tfilter->refcount > 0, TC_H_UNSPEC);

	if (tfilter->action == NULL)
		return NULL;

	return tfilter->action;
}

/**
 * nm_tc_tfilter_set_action:
 * @tfilter: the #NMTCTfilter
 * @action: the action object
 *
 * Sets the action associated with a traffic filter.
 *
 * Since: 1.12
 **/
void
nm_tc_tfilter_set_action (NMTCTfilter *tfilter, NMTCAction *action)
{
	g_return_if_fail (tfilter != NULL);
	g_return_if_fail (tfilter->refcount > 0);

	if (action)
		nm_tc_action_ref (action);
	if (tfilter->action)
		nm_tc_action_unref (tfilter->action);
	tfilter->action = action;
}

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMSettingTCConfig,
	PROP_QDISCS,
	PROP_TFILTERS,
);

/**
 * NMSettingTCConfig:
 *
 * Linux Traffic Control Settings.
 *
 * Since: 1.12
 */
struct _NMSettingTCConfig {
	NMSetting parent;
	GPtrArray *qdiscs;
	GPtrArray *tfilters;
};

struct _NMSettingTCConfigClass {
	NMSettingClass parent;
};

G_DEFINE_TYPE (NMSettingTCConfig, nm_setting_tc_config, NM_TYPE_SETTING)

/*****************************************************************************/

/**
 * nm_setting_tc_config_get_num_qdiscs:
 * @setting: the #NMSettingTCConfig
 *
 * Returns: the number of configured queueing disciplines
 *
 * Since: 1.12
 **/
guint
nm_setting_tc_config_get_num_qdiscs (NMSettingTCConfig *self)
{
	g_return_val_if_fail (NM_IS_SETTING_TC_CONFIG (self), 0);

	return self->qdiscs->len;
}

/**
 * nm_setting_tc_config_get_qdisc:
 * @setting: the #NMSettingTCConfig
 * @idx: index number of the qdisc to return
 *
 * Returns: (transfer none): the qdisc at index @idx
 *
 * Since: 1.12
 **/
NMTCQdisc *
nm_setting_tc_config_get_qdisc (NMSettingTCConfig *self, guint idx)
{
	g_return_val_if_fail (NM_IS_SETTING_TC_CONFIG (self), NULL);
	g_return_val_if_fail (idx < self->qdiscs->len, NULL);

	return self->qdiscs->pdata[idx];
}

/**
 * nm_setting_tc_config_add_qdisc:
 * @setting: the #NMSettingTCConfig
 * @qdisc: the qdisc to add
 *
 * Appends a new qdisc and associated information to the setting.  The
 * given qdisc is duplicated internally and is not changed by this function.
 * If an identical qdisc (considering attributes as well) already exists, the
 * qdisc is not added and the function returns %FALSE.
 *
 * Returns: %TRUE if the qdisc was added; %FALSE if the qdisc was already known.
 *
 * Since: 1.12
 **/
gboolean
nm_setting_tc_config_add_qdisc (NMSettingTCConfig *self,
                                NMTCQdisc *qdisc)
{
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_TC_CONFIG (self), FALSE);
	g_return_val_if_fail (qdisc != NULL, FALSE);

	for (i = 0; i < self->qdiscs->len; i++) {
		if (nm_tc_qdisc_equal (self->qdiscs->pdata[i], qdisc))
			return FALSE;
	}

	g_ptr_array_add (self->qdiscs, nm_tc_qdisc_dup (qdisc));
	_notify (self, PROP_QDISCS);
	return TRUE;
}

/**
 * nm_setting_tc_config_remove_qdisc:
 * @setting: the #NMSettingTCConfig
 * @idx: index number of the qdisc
 *
 * Removes the qdisc at index @idx.
 *
 * Since: 1.12
 **/
void
nm_setting_tc_config_remove_qdisc (NMSettingTCConfig *self, guint idx)
{
	g_return_if_fail (NM_IS_SETTING_TC_CONFIG (self));

	g_return_if_fail (idx < self->qdiscs->len);

	g_ptr_array_remove_index (self->qdiscs, idx);
	_notify (self, PROP_QDISCS);
}

/**
 * nm_setting_tc_config_remove_qdisc_by_value:
 * @setting: the #NMSettingTCConfig
 * @qdisc: the qdisc to remove
 *
 * Removes the first matching qdisc that matches @qdisc.
 *
 * Returns: %TRUE if the qdisc was found and removed; %FALSE if it was not.
 *
 * Since: 1.12
 **/
gboolean
nm_setting_tc_config_remove_qdisc_by_value (NMSettingTCConfig *self,
                                            NMTCQdisc *qdisc)
{
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_TC_CONFIG (self), FALSE);
	g_return_val_if_fail (qdisc != NULL, FALSE);

	for (i = 0; i < self->qdiscs->len; i++) {
		if (nm_tc_qdisc_equal (self->qdiscs->pdata[i], qdisc)) {
			g_ptr_array_remove_index (self->qdiscs, i);
			_notify (self, PROP_QDISCS);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_tc_config_clear_qdiscs:
 * @setting: the #NMSettingTCConfig
 *
 * Removes all configured queueing disciplines.
 *
 * Since: 1.12
 **/
void
nm_setting_tc_config_clear_qdiscs (NMSettingTCConfig *self)
{
	g_return_if_fail (NM_IS_SETTING_TC_CONFIG (self));

	if (self->qdiscs->len != 0) {
		g_ptr_array_set_size (self->qdiscs, 0);
		_notify (self, PROP_QDISCS);
	}
}

/*****************************************************************************/
/**
 * nm_setting_tc_config_get_num_tfilters:
 * @setting: the #NMSettingTCConfig
 *
 * Returns: the number of configured queueing disciplines
 *
 * Since: 1.12
 **/
guint
nm_setting_tc_config_get_num_tfilters (NMSettingTCConfig *self)
{
	g_return_val_if_fail (NM_IS_SETTING_TC_CONFIG (self), 0);

	return self->tfilters->len;
}

/**
 * nm_setting_tc_config_get_tfilter:
 * @setting: the #NMSettingTCConfig
 * @idx: index number of the tfilter to return
 *
 * Returns: (transfer none): the tfilter at index @idx
 *
 * Since: 1.12
 **/
NMTCTfilter *
nm_setting_tc_config_get_tfilter (NMSettingTCConfig *self, guint idx)
{
	g_return_val_if_fail (NM_IS_SETTING_TC_CONFIG (self), NULL);
	g_return_val_if_fail (idx < self->tfilters->len, NULL);

	return self->tfilters->pdata[idx];
}

/**
 * nm_setting_tc_config_add_tfilter:
 * @setting: the #NMSettingTCConfig
 * @tfilter: the tfilter to add
 *
 * Appends a new tfilter and associated information to the setting.  The
 * given tfilter is duplicated internally and is not changed by this function.
 * If an identical tfilter (considering attributes as well) already exists, the
 * tfilter is not added and the function returns %FALSE.
 *
 * Returns: %TRUE if the tfilter was added; %FALSE if the tfilter was already known.
 *
 * Since: 1.12
 **/
gboolean
nm_setting_tc_config_add_tfilter (NMSettingTCConfig *self,
                                  NMTCTfilter *tfilter)
{
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_TC_CONFIG (self), FALSE);
	g_return_val_if_fail (tfilter != NULL, FALSE);

	for (i = 0; i < self->tfilters->len; i++) {
		if (nm_tc_tfilter_equal (self->tfilters->pdata[i], tfilter))
			return FALSE;
	}

	g_ptr_array_add (self->tfilters, nm_tc_tfilter_dup (tfilter));
	_notify (self, PROP_TFILTERS);
	return TRUE;
}

/**
 * nm_setting_tc_config_remove_tfilter:
 * @setting: the #NMSettingTCConfig
 * @idx: index number of the tfilter
 *
 * Removes the tfilter at index @idx.
 *
 * Since: 1.12
 **/
void
nm_setting_tc_config_remove_tfilter (NMSettingTCConfig *self, guint idx)
{
	g_return_if_fail (NM_IS_SETTING_TC_CONFIG (self));
	g_return_if_fail (idx < self->tfilters->len);

	g_ptr_array_remove_index (self->tfilters, idx);
	_notify (self, PROP_TFILTERS);
}

/**
 * nm_setting_tc_config_remove_tfilter_by_value:
 * @setting: the #NMSettingTCConfig
 * @tfilter: the tfilter to remove
 *
 * Removes the first matching tfilter that matches @tfilter.
 *
 * Returns: %TRUE if the tfilter was found and removed; %FALSE if it was not.
 *
 * Since: 1.12
 **/
gboolean
nm_setting_tc_config_remove_tfilter_by_value (NMSettingTCConfig *self,
                                              NMTCTfilter *tfilter)
{
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_TC_CONFIG (self), FALSE);
	g_return_val_if_fail (tfilter != NULL, FALSE);

	for (i = 0; i < self->tfilters->len; i++) {
		if (nm_tc_tfilter_equal (self->tfilters->pdata[i], tfilter)) {
			g_ptr_array_remove_index (self->tfilters, i);
			_notify (self, PROP_TFILTERS);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_tc_config_clear_tfilters:
 * @setting: the #NMSettingTCConfig
 *
 * Removes all configured queueing disciplines.
 *
 * Since: 1.12
 **/
void
nm_setting_tc_config_clear_tfilters (NMSettingTCConfig *self)
{
	g_return_if_fail (NM_IS_SETTING_TC_CONFIG (self));

	if (self->tfilters->len != 0) {
		g_ptr_array_set_size (self->tfilters, 0);
		_notify (self, PROP_TFILTERS);
	}
}

/*****************************************************************************/

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingTCConfig *self = NM_SETTING_TC_CONFIG (setting);
	guint i;

	if (self->qdiscs->len != 0) {
		gs_unref_hashtable GHashTable *ht = NULL;

		ht = g_hash_table_new ((GHashFunc) _nm_tc_qdisc_hash,
		                       (GEqualFunc) nm_tc_qdisc_equal);
		for (i = 0; i < self->qdiscs->len; i++) {
			if (!g_hash_table_add (ht, self->qdiscs->pdata[i])) {
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
				                     _("there are duplicate TC qdiscs"));
				g_prefix_error (error,
				                "%s.%s: ",
				                NM_SETTING_TC_CONFIG_SETTING_NAME,
				                NM_SETTING_TC_CONFIG_QDISCS);
				return FALSE;
			}
		}
	}

	if (self->tfilters->len != 0) {
		gs_unref_hashtable GHashTable *ht = NULL;

		ht = g_hash_table_new ((GHashFunc) _nm_tc_tfilter_hash,
		                       (GEqualFunc) nm_tc_tfilter_equal);
		for (i = 0; i < self->tfilters->len; i++) {
			if (!g_hash_table_add (ht, self->tfilters->pdata[i])) {
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
				                     _("there are duplicate TC filters"));
				g_prefix_error (error,
				                "%s.%s: ",
				                NM_SETTING_TC_CONFIG_SETTING_NAME,
				                NM_SETTING_TC_CONFIG_TFILTERS);
				return FALSE;
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
	NMSettingTCConfig *a_tc_config = NM_SETTING_TC_CONFIG (setting);
	NMSettingTCConfig *b_tc_config = NM_SETTING_TC_CONFIG (other);
	guint i;

	if (nm_streq (sett_info->property_infos[property_idx].name, NM_SETTING_TC_CONFIG_QDISCS)) {
		if (other) {
			if (a_tc_config->qdiscs->len != b_tc_config->qdiscs->len)
				return FALSE;
			for (i = 0; i < a_tc_config->qdiscs->len; i++) {
				if (!nm_tc_qdisc_equal (a_tc_config->qdiscs->pdata[i], b_tc_config->qdiscs->pdata[i]))
					return FALSE;
			}
		}
		return TRUE;
	}

	if (nm_streq (sett_info->property_infos[property_idx].name, NM_SETTING_TC_CONFIG_TFILTERS)) {
		if (other) {
			if (a_tc_config->tfilters->len != b_tc_config->tfilters->len)
				return FALSE;
			for (i = 0; i < a_tc_config->tfilters->len; i++) {
				if (!nm_tc_tfilter_equal (a_tc_config->tfilters->pdata[i], b_tc_config->tfilters->pdata[i]))
					return FALSE;
			}
		}
		return TRUE;
	}

	return NM_SETTING_CLASS (nm_setting_tc_config_parent_class)->compare_property (sett_info,
	                                                                               property_idx,
	                                                                               setting,
	                                                                               other,
	                                                                               flags);
}

/**
 * _qdiscs_to_variant:
 * @qdiscs: (element-type NMTCQdisc): an array of #NMTCQdisc objects
 *
 * Utility function to convert a #GPtrArray of #NMTCQdisc objects representing
 * TC qdiscs into a #GVariant of type 'aa{sv}' representing an array
 * of NetworkManager TC qdiscs.
 *
 * Returns: (transfer none): a new floating #GVariant representing @qdiscs.
 **/
static GVariant *
_qdiscs_to_variant (GPtrArray *qdiscs)
{
	GVariantBuilder builder;
	int i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aa{sv}"));

	if (qdiscs) {
		for (i = 0; i < qdiscs->len; i++) {
			NMTCQdisc *qdisc = qdiscs->pdata[i];
			GVariantBuilder qdisc_builder;

			g_variant_builder_init (&qdisc_builder, G_VARIANT_TYPE_VARDICT);

			g_variant_builder_add (&qdisc_builder, "{sv}", "kind",
			                       g_variant_new_string (nm_tc_qdisc_get_kind (qdisc)));

			g_variant_builder_add (&qdisc_builder, "{sv}", "handle",
			                       g_variant_new_uint32 (nm_tc_qdisc_get_handle (qdisc)));

			g_variant_builder_add (&qdisc_builder, "{sv}", "parent",
			                       g_variant_new_uint32 (nm_tc_qdisc_get_parent (qdisc)));

			g_variant_builder_add (&builder, "a{sv}", &qdisc_builder);
		}
	}

	return g_variant_builder_end (&builder);
}

/**
 * _qdiscs_from_variant:
 * @value: a #GVariant of type 'aa{sv}'
 *
 * Utility function to convert a #GVariant representing a list of TC qdiscs
 * into a #GPtrArray of * #NMTCQdisc objects.
 *
 * Returns: (transfer full) (element-type NMTCQdisc): a newly allocated
 *   #GPtrArray of #NMTCQdisc objects
 **/
static GPtrArray *
_qdiscs_from_variant (GVariant *value)
{
	GPtrArray *qdiscs;
	GVariant *qdisc_var;
	GVariantIter iter;
	GError *error = NULL;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("aa{sv}")), NULL);

	g_variant_iter_init (&iter, value);
	qdiscs = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_tc_qdisc_unref);

	while (g_variant_iter_next (&iter, "@a{sv}", &qdisc_var)) {
		const char *kind;
		guint32 handle;
		guint32 parent;
		NMTCQdisc *qdisc;

		if (   !g_variant_lookup (qdisc_var, "kind", "&s", &kind)
		    || !g_variant_lookup (qdisc_var, "parent", "u", &parent)) {
			//g_warning ("Ignoring invalid qdisc");
			goto next;
		}

		qdisc = nm_tc_qdisc_new (kind, parent, &error);
		if (!qdisc) {
			//g_warning ("Ignoring invalid qdisc: %s", error->message);
			g_clear_error (&error);
			goto next;
		}

		if (g_variant_lookup (qdisc_var, "handle", "u", &handle))
			nm_tc_qdisc_set_handle (qdisc, handle);

		g_ptr_array_add (qdiscs, qdisc);
next:
		g_variant_unref (qdisc_var);
	}

	return qdiscs;
}

static GVariant *
tc_qdiscs_get (NMSetting *setting,
               const char *property)
{
	GPtrArray *qdiscs;
	GVariant *ret;

	g_object_get (setting, NM_SETTING_TC_CONFIG_QDISCS, &qdiscs, NULL);
	ret = _qdiscs_to_variant (qdiscs);
	g_ptr_array_unref (qdiscs);

	return ret;
}

static gboolean
tc_qdiscs_set (NMSetting *setting,
               GVariant *connection_dict,
               const char *property,
               GVariant *value,
               NMSettingParseFlags parse_flags,
               GError **error)
{
	GPtrArray *qdiscs;

	qdiscs = _qdiscs_from_variant (value);
	g_object_set (setting, NM_SETTING_TC_CONFIG_QDISCS, qdiscs, NULL);
	g_ptr_array_unref (qdiscs);

	return TRUE;
}

static GVariant *
_action_to_variant (NMTCAction *action)
{
	GVariantBuilder builder;
	gs_strfreev char **attrs = nm_tc_action_get_attribute_names (action);
	int i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

	g_variant_builder_add (&builder, "{sv}", "kind",
	                       g_variant_new_string (nm_tc_action_get_kind (action)));

	for (i = 0; attrs[i]; i++) {
		g_variant_builder_add (&builder, "{sv}", attrs[i],
		                       nm_tc_action_get_attribute (action, attrs[i]));
	}

	return g_variant_builder_end (&builder);
}

/**
 * _tfilters_to_variant:
 * @tfilters: (element-type NMTCTfilter): an array of #NMTCTfilter objects
 *
 * Utility function to convert a #GPtrArray of #NMTCTfilter objects representing
 * TC tfilters into a #GVariant of type 'aa{sv}' representing an array
 * of NetworkManager TC tfilters.
 *
 * Returns: (transfer none): a new floating #GVariant representing @tfilters.
 **/
static GVariant *
_tfilters_to_variant (GPtrArray *tfilters)
{
	GVariantBuilder builder;
	int i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aa{sv}"));

	if (tfilters) {
		for (i = 0; i < tfilters->len; i++) {
			NMTCTfilter *tfilter = tfilters->pdata[i];
			NMTCAction  *action = nm_tc_tfilter_get_action (tfilter);
			GVariantBuilder tfilter_builder;

			g_variant_builder_init (&tfilter_builder, G_VARIANT_TYPE ("a{sv}"));

			g_variant_builder_add (&tfilter_builder, "{sv}", "kind",
			                       g_variant_new_string (nm_tc_tfilter_get_kind (tfilter)));
			g_variant_builder_add (&tfilter_builder, "{sv}", "handle",
			                       g_variant_new_uint32 (nm_tc_tfilter_get_handle (tfilter)));
			g_variant_builder_add (&tfilter_builder, "{sv}", "parent",
			                       g_variant_new_uint32 (nm_tc_tfilter_get_parent (tfilter)));

			if (action) {
				g_variant_builder_add (&tfilter_builder, "{sv}", "action",
				                       _action_to_variant (action));
			}

			g_variant_builder_add (&builder, "a{sv}", &tfilter_builder);
		}
	}

	return g_variant_builder_end (&builder);
}

/**
 * _tfilters_from_variant:
 * @value: a #GVariant of type 'aa{sv}'
 *
 * Utility function to convert a #GVariant representing a list of TC tfilters
 * into a #GPtrArray of * #NMTCTfilter objects.
 *
 * Returns: (transfer full) (element-type NMTCTfilter): a newly allocated
 *   #GPtrArray of #NMTCTfilter objects
 **/
static GPtrArray *
_tfilters_from_variant (GVariant *value)
{
	GPtrArray *tfilters;
	GVariant *tfilter_var;
	GVariantIter iter;
	GError *error = NULL;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("aa{sv}")), NULL);

	g_variant_iter_init (&iter, value);
	tfilters = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_tc_tfilter_unref);

	while (g_variant_iter_next (&iter, "@a{sv}", &tfilter_var)) {
		NMTCTfilter *tfilter = NULL;
		const char *kind;
		guint32 handle;
		guint32 parent;
		NMTCAction *action;
		const char *action_kind = NULL;
		char *action_key;
		GVariantIter action_iter;
		GVariant *action_var = NULL;
		GVariant *action_val;

		if (   !g_variant_lookup (tfilter_var, "kind", "&s", &kind)
		    || !g_variant_lookup (tfilter_var, "parent", "u", &parent)) {
			//g_warning ("Ignoring invalid tfilter");
			goto next;
		}

		tfilter = nm_tc_tfilter_new (kind, parent, &error);
		if (!tfilter) {
			//g_warning ("Ignoring invalid tfilter: %s", error->message);
			g_clear_error (&error);
			goto next;
		}

		if (g_variant_lookup (tfilter_var, "handle", "u", &handle))
			nm_tc_tfilter_set_handle (tfilter, handle);

		action_var = g_variant_lookup_value (tfilter_var, "action", G_VARIANT_TYPE_VARDICT);

		if (action_var) {
			if (!g_variant_lookup (action_var, "kind", "&s", &action_kind)) {
				//g_warning ("Ignoring tfilter with invalid action");
				goto next;
			}

			action = nm_tc_action_new (action_kind, &error);
			if (!action) {
				//g_warning ("Ignoring tfilter with invalid action: %s", error->message);
				g_clear_error (&error);
				goto next;
			}

			g_variant_iter_init (&action_iter, action_var);
			while (g_variant_iter_next (&action_iter, "{&sv}", &action_key, &action_val)) {
				if (strcmp (action_key, "kind") != 0)
					nm_tc_action_set_attribute (action, action_key, action_val);
				g_variant_unref (action_val);
			}

			nm_tc_tfilter_set_action (tfilter, action);
			nm_tc_action_unref (action);
		}

		nm_tc_tfilter_ref (tfilter);
		g_ptr_array_add (tfilters, tfilter);
next:
		if (tfilter)
			nm_tc_tfilter_unref (tfilter);
		if (action_var)
			g_variant_unref (action_var);
		g_variant_unref (tfilter_var);
	}

	return tfilters;
}

static GVariant *
tc_tfilters_get (NMSetting *setting,
                 const char *property)
{
	GPtrArray *tfilters;
	GVariant *ret;

	g_object_get (setting, NM_SETTING_TC_CONFIG_TFILTERS, &tfilters, NULL);
	ret = _tfilters_to_variant (tfilters);
	g_ptr_array_unref (tfilters);

	return ret;
}

static gboolean
tc_tfilters_set (NMSetting *setting,
                 GVariant *connection_dict,
                 const char *property,
                 GVariant *value,
                 NMSettingParseFlags parse_flags,
                 GError **error)
{
	GPtrArray *tfilters;

	tfilters = _tfilters_from_variant (value);
	g_object_set (setting, NM_SETTING_TC_CONFIG_TFILTERS, tfilters, NULL);
	g_ptr_array_unref (tfilters);

	return TRUE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingTCConfig *self = NM_SETTING_TC_CONFIG (object);

	switch (prop_id) {
	case PROP_QDISCS:
		g_value_take_boxed (value, _nm_utils_copy_array (self->qdiscs,
		                                                 (NMUtilsCopyFunc) nm_tc_qdisc_dup,
		                                                 (GDestroyNotify) nm_tc_qdisc_unref));
		break;
	case PROP_TFILTERS:
		g_value_take_boxed (value, _nm_utils_copy_array (self->tfilters,
		                                                 (NMUtilsCopyFunc) nm_tc_tfilter_dup,
		                                                 (GDestroyNotify) nm_tc_tfilter_unref));
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
	NMSettingTCConfig *self = NM_SETTING_TC_CONFIG (object);

	switch (prop_id) {
	case PROP_QDISCS:
		g_ptr_array_unref (self->qdiscs);
		self->qdiscs = _nm_utils_copy_array (g_value_get_boxed (value),
		                                     (NMUtilsCopyFunc) nm_tc_qdisc_dup,
		                                     (GDestroyNotify) nm_tc_qdisc_unref);
		break;
	case PROP_TFILTERS:
		g_ptr_array_unref (self->tfilters);
		self->tfilters = _nm_utils_copy_array (g_value_get_boxed (value),
		                                       (NMUtilsCopyFunc) nm_tc_tfilter_dup,
		                                       (GDestroyNotify) nm_tc_tfilter_unref);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_tc_config_init (NMSettingTCConfig *self)
{
	self->qdiscs = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_tc_qdisc_unref);
	self->tfilters = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_tc_tfilter_unref);
}

/**
 * nm_setting_tc_config_new:
 *
 * Creates a new #NMSettingTCConfig object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingTCConfig object
 *
 * Since: 1.12
 **/
NMSetting *
nm_setting_tc_config_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_TC_CONFIG, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingTCConfig *self = NM_SETTING_TC_CONFIG (object);

	g_ptr_array_unref (self->qdiscs);
	g_ptr_array_unref (self->tfilters);

	G_OBJECT_CLASS (nm_setting_tc_config_parent_class)->finalize (object);
}

static void
nm_setting_tc_config_class_init (NMSettingTCConfigClass *klass)
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
	 * NMSettingTCConfig:qdiscs: (type GPtrArray(NMTCQdisc))
	 *
	 * Array of TC queueing disciplines.
	 **/
	/* ---ifcfg-rh---
	 * property: qdiscs
	 * variable: QDISC1(+), QDISC2(+), ...
	 * description: Queueing disciplines
	 * example: QDISC1=ingress, QDISC2="root handle 1234: fq_codel"
	 * ---end---
	 */
	obj_properties[PROP_QDISCS] =
	    g_param_spec_boxed (NM_SETTING_TC_CONFIG_QDISCS, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READWRITE |
	                        NM_SETTING_PARAM_INFERRABLE |
	                        G_PARAM_STATIC_STRINGS);

	_properties_override_add_override (properties_override,
	                                   obj_properties[PROP_QDISCS],
	                                   G_VARIANT_TYPE ("aa{sv}"),
	                                   tc_qdiscs_get,
	                                   tc_qdiscs_set,
	                                   NULL);

	/**
	 * NMSettingTCConfig:tfilters: (type GPtrArray(NMTCTfilter))
	 *
	 * Array of TC traffic filters.
	 **/
	/* ---ifcfg-rh---
	 * property: qdiscs
	 * variable: FILTER1(+), FILTER2(+), ...
	 * description: Traffic filters
	 * example: FILTER1="parent ffff: matchall action simple sdata Input", ...
	 * ---end---
	 */
	obj_properties[PROP_TFILTERS] =
	    g_param_spec_boxed (NM_SETTING_TC_CONFIG_TFILTERS, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READWRITE |
	                        NM_SETTING_PARAM_INFERRABLE |
	                        G_PARAM_STATIC_STRINGS);

	_properties_override_add_override (properties_override,
	                                   obj_properties[PROP_TFILTERS],
	                                   G_VARIANT_TYPE ("aa{sv}"),
	                                   tc_tfilters_get,
	                                   tc_tfilters_set,
	                                   NULL);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit_full (setting_class, NM_META_SETTING_TYPE_TC_CONFIG,
	                               NULL, properties_override);
}
