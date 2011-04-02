/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
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
 * (C) Copyright 2007 - 2011 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#include <string.h>
#include <ctype.h>
#include "nm-utils.h"
#include "nm-dbus-glib-types.h"
#include "nm-param-spec-specialized.h"
#include "nm-setting-connection.h"

/**
 * SECTION:nm-setting-connection
 * @short_description: Describes general connection properties
 * @include: nm-setting-connection.h
 *
 * The #NMSettingConnection object is a #NMSetting subclass that describes
 * properties that apply to all #NMConnection objects, regardless of what type
 * of network connection they describe.  Each #NMConnection object must contain
 * a #NMSettingConnection setting.
 **/

/**
 * nm_setting_connection_error_quark:
 *
 * Registers an error quark for #NMSettingConnection if necessary.
 *
 * Returns: the error quark used for #NMSettingConnection errors.
 **/
GQuark
nm_setting_connection_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-connection-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_setting_connection_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			ENUM_ENTRY (NM_SETTING_CONNECTION_ERROR_UNKNOWN, "UnknownError"),
			ENUM_ENTRY (NM_SETTING_CONNECTION_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			ENUM_ENTRY (NM_SETTING_CONNECTION_ERROR_MISSING_PROPERTY, "MissingProperty"),
			ENUM_ENTRY (NM_SETTING_CONNECTION_ERROR_TYPE_SETTING_NOT_FOUND, "TypeSettingNotFound"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMSettingConnectionError", values);
	}
	return etype;
}


G_DEFINE_TYPE (NMSettingConnection, nm_setting_connection, NM_TYPE_SETTING)

#define NM_SETTING_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_CONNECTION, NMSettingConnectionPrivate))

typedef enum {
	PERM_TYPE_USER = 0,
} PermType;

typedef struct {
	guint8 ptype;
	char *item;
} Permission;

typedef struct {
	char *id;
	char *uuid;
	char *type;
	GSList *permissions; /* list of Permission structs */
	gboolean autoconnect;
	guint64 timestamp;
	gboolean read_only;
} NMSettingConnectionPrivate;

enum {
	PROP_0,
	PROP_ID,
	PROP_UUID,
	PROP_TYPE,
	PROP_PERMISSIONS,
	PROP_AUTOCONNECT,
	PROP_TIMESTAMP,
	PROP_READ_ONLY,

	LAST_PROP
};

/***********************************************************************/

#define PERM_USER_PREFIX  "user:"

static Permission *
permission_new_from_str (const char *str)
{
	Permission *p;
	const char *last_colon;
	size_t ulen = 0, i;

	g_return_val_if_fail (strncmp (str, PERM_USER_PREFIX, strlen (PERM_USER_PREFIX)) == 0, NULL);
	str += strlen (PERM_USER_PREFIX);

	last_colon = strrchr (str, ':');
	if (last_colon) {
		/* Ensure that somebody didn't pass "user::" */
		g_return_val_if_fail (last_colon > str, NULL);

		/* Reject :[detail] for now */
		g_return_val_if_fail (*(last_colon + 1) == '\0', NULL);

		/* Make sure we don't include detail in the username */
		ulen = last_colon - str;
	} else
		ulen = strlen (str);

	/* Sanity check the length of the username */
	g_return_val_if_fail (ulen < 100, NULL);

	/* Make sure there's no ':' in the username */
	for (i = 0; i < ulen; i++)
		g_return_val_if_fail (str[i] != ':', NULL);

	/* And the username must be valid UTF-8 */
	g_return_val_if_fail (g_utf8_validate (str, -1, NULL) == TRUE, NULL);

	/* Yay, valid... create the new permission */
	p = g_slice_new0 (Permission);
	p->ptype = PERM_TYPE_USER;
	if (last_colon) {
		p->item = g_malloc (ulen + 1);
		memcpy (p->item, str, ulen);
		p->item[ulen] = '\0';
	} else
		p->item = g_strdup (str);

	return p;
}

static Permission *
permission_new (const char *uname)
{
	Permission *p;

	g_return_val_if_fail (uname, NULL);
	g_return_val_if_fail (uname[0] != '\0', NULL);
	g_return_val_if_fail (strchr (uname, ':') == NULL, NULL);
	g_return_val_if_fail (g_utf8_validate (uname, -1, NULL) == TRUE, NULL);

	/* Yay, valid... create the new permission */
	p = g_slice_new0 (Permission);
	p->ptype = PERM_TYPE_USER;
	p->item = g_strdup (uname);
	return p;
}

static char *
permission_to_string (Permission *p)
{
	return g_strdup_printf (PERM_USER_PREFIX "%s:", p->item);
}

static void
permission_free (Permission *p)
{
	g_free (p->item);
	memset (p, 0, sizeof (*p));
	g_slice_free (Permission, p);
}

/***********************************************************************/

/**
 * nm_setting_connection_new:
 *
 * Creates a new #NMSettingConnection object with default values.
 *
 * Returns: the new empty #NMSettingConnection object
 **/
NMSetting *nm_setting_connection_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_CONNECTION, NULL);
}

/**
 * nm_setting_connection_get_id:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:id property of the connection.
 *
 * Returns: the connection ID
 **/
const char *
nm_setting_connection_get_id (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), NULL);

	return NM_SETTING_CONNECTION_GET_PRIVATE (setting)->id;
}

/**
 * nm_setting_connection_get_uuid:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:uuid property of the connection.
 *
 * Returns: the connection UUID
 **/
const char *
nm_setting_connection_get_uuid (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), NULL);

	return NM_SETTING_CONNECTION_GET_PRIVATE (setting)->uuid;
}

/**
 * nm_setting_connection_get_connection_type:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:type property of the connection.
 *
 * Returns: the connection type
 **/
const char *
nm_setting_connection_get_connection_type (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), NULL);

	return NM_SETTING_CONNECTION_GET_PRIVATE (setting)->type;
}


/**
 * nm_setting_connection_get_num_permissions:
 * @setting: the #NMSettingConnection
 *
 * Returns the number of entires in the #NMSettingConnection:permissions
 * property of this setting.
 *
 * Returns: the number of permissions entires
 */
guint32
nm_setting_connection_get_num_permissions (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), 0);

	return g_slist_length (NM_SETTING_CONNECTION_GET_PRIVATE (setting)->permissions);
}

/**
 * nm_setting_connection_get_permission:
 * @setting: the #NMSettingConnection
 * @idx: the zero-based index of the permissions entry
 * @out_ptype: on return, the permission type (at this time, always "user")
 * @out_pitem: on return, the permission item (formatted accoring to @ptype, see
 * #NMSettingConnection:permissions for more detail
 * @out_detail: on return, the permission detail (at this time, always NULL)
 *
 * Retrieve one of the entries of the #NMSettingConnection:permissions property
 * of this setting.
 *
 * Returns: %TRUE if a permission was returned, %FALSE if @idx was invalid
 */
gboolean
nm_setting_connection_get_permission (NMSettingConnection *setting,
                                      guint32 idx,
                                      const char **out_ptype,
                                      const char **out_pitem,
                                      const char **out_detail)
{
	NMSettingConnectionPrivate *priv;
	Permission *p;

	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), FALSE);

	priv = NM_SETTING_CONNECTION_GET_PRIVATE (setting);

	g_return_val_if_fail (idx < g_slist_length (priv->permissions), FALSE);

	p = g_slist_nth_data (priv->permissions, idx);
	if (out_ptype)
		*out_ptype = "user";
	if (out_pitem)
		*out_pitem = p->item;
	if (out_detail)
		*out_detail = NULL;

	return TRUE;
}

/**
 * nm_setting_connection_permissions_user_allowed:
 * @setting: the #NMSettingConnection
 * @uname: the user name to check permissions for
 *
 * Checks whether the given username is allowed to view/access this connection.
 *
 * Returns: %TRUE if the requested user is allowed to view this connection,
 * %FALSE if the given user is not allowed to view this connection
 */
gboolean
nm_setting_connection_permissions_user_allowed (NMSettingConnection *setting,
                                                const char *uname)
{
	NMSettingConnectionPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), FALSE);
	g_return_val_if_fail (uname != NULL, FALSE);
	g_return_val_if_fail (*uname != '\0', FALSE);

	priv = NM_SETTING_CONNECTION_GET_PRIVATE (setting);

	/* If no permissions, visible to all */
	if (priv->permissions == NULL)
		return TRUE;

	/* Find the username in the permissions list */
	for (iter = priv->permissions; iter; iter = g_slist_next (iter)) {
		Permission *p = iter->data;

		if (strcmp (uname, p->item) == 0)
			return TRUE;
	}

	return FALSE;
}

/**
 * nm_setting_connection_add_permission:
 * @setting: the #NMSettingConnection
 * @ptype: the permission type; at this time only "user" is supported
 * @pitem: the permission item formatted as required for @ptype
 * @detail: (allow-none): unused at this time; must be %NULL
 *
 * Adds a permission to the connection's permission list.  At this time, only
 * the "user" permission type is supported, and @pitem must be a username. See
 * #NMSettingConnection:permissions: for more details.
 *
 * Returns: TRUE if the permission was unique and was successfully added to the
 * list, FALSE if @ptype or @pitem was invalid or it the permission was already
 * present in the list
 */
gboolean
nm_setting_connection_add_permission (NMSettingConnection *setting,
                                      const char *ptype,
                                      const char *pitem,
                                      const char *detail)
{
	NMSettingConnectionPrivate *priv;
	Permission *p;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), FALSE);
	g_return_val_if_fail (ptype, FALSE);
	g_return_val_if_fail (strlen (ptype) > 0, FALSE);
	g_return_val_if_fail (detail == NULL, FALSE);

	/* Only "user" for now... */
	g_return_val_if_fail (strcmp (ptype, "user") == 0, FALSE);

	priv = NM_SETTING_CONNECTION_GET_PRIVATE (setting);

	/* No dupes */
	for (iter = priv->permissions; iter; iter = g_slist_next (iter)) {
		p = iter->data;
		if (strcmp (pitem, p->item) == 0)
			return FALSE;
	}

	p = permission_new (pitem);
	g_return_val_if_fail (p != NULL, FALSE);
	priv->permissions = g_slist_append (priv->permissions, p);

	return TRUE;
}

/**
 * nm_setting_connection_remove_permission:
 * @setting: the #NMSettingConnection
 * @idx: the zero-based index of the permission to remove
 *
 * Removes the permission at index @idx from the connection.
 */
void
nm_setting_connection_remove_permission (NMSettingConnection *setting,
                                         guint32 idx)
{
	NMSettingConnectionPrivate *priv;
	GSList *iter;

	g_return_if_fail (NM_IS_SETTING_CONNECTION (setting));

	priv = NM_SETTING_CONNECTION_GET_PRIVATE (setting);
	iter = g_slist_nth (priv->permissions, idx);
	g_return_if_fail (iter != NULL);

	permission_free ((Permission *) iter->data);
	priv->permissions = g_slist_delete_link (priv->permissions, iter);
}


/**
 * nm_setting_connection_get_autoconnect:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:autoconnect property of the connection.
 *
 * Returns: the connection's autoconnect behavior
 **/
gboolean
nm_setting_connection_get_autoconnect (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), FALSE);

	return NM_SETTING_CONNECTION_GET_PRIVATE (setting)->autoconnect;
}

/**
 * nm_setting_connection_get_timestamp:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:timestamp property of the connection.
 *
 * Returns: the connection's timestamp
 **/
guint64
nm_setting_connection_get_timestamp (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), 0);

	return NM_SETTING_CONNECTION_GET_PRIVATE (setting)->timestamp;
}

/**
 * nm_setting_connection_get_read_only:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:read-only property of the connection.
 *
 * Returns: %TRUE if the connection is read-only, %FALSE if it is not
 **/
gboolean
nm_setting_connection_get_read_only (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), TRUE);

	return NM_SETTING_CONNECTION_GET_PRIVATE (setting)->read_only;
}

static gint
find_setting_by_name (gconstpointer a, gconstpointer b)
{
	NMSetting *setting = NM_SETTING (a);
	const char *str = (const char *) b;

	return strcmp (nm_setting_get_name (setting), str);
}

static gboolean
validate_uuid (const char *uuid)
{
	int i;

	if (!uuid || !strlen (uuid))
		return FALSE;

	for (i = 0; i < strlen (uuid); i++) {
		if (!isxdigit (uuid[i]) && (uuid[i] != '-'))
			return FALSE;
	}

	return TRUE;
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingConnectionPrivate *priv = NM_SETTING_CONNECTION_GET_PRIVATE (setting);

	if (!priv->id) {
		g_set_error (error,
		             NM_SETTING_CONNECTION_ERROR,
		             NM_SETTING_CONNECTION_ERROR_MISSING_PROPERTY,
		             NM_SETTING_CONNECTION_ID);
		return FALSE;
	} else if (!strlen (priv->id)) {
		g_set_error (error,
		             NM_SETTING_CONNECTION_ERROR,
		             NM_SETTING_CONNECTION_ERROR_INVALID_PROPERTY,
		             NM_SETTING_CONNECTION_ID);
		return FALSE;
	}

	if (!priv->uuid) {
		g_set_error (error,
		             NM_SETTING_CONNECTION_ERROR,
		             NM_SETTING_CONNECTION_ERROR_MISSING_PROPERTY,
		             NM_SETTING_CONNECTION_UUID);
		return FALSE;
	} else if (!validate_uuid (priv->uuid)) {
		g_set_error (error,
		             NM_SETTING_CONNECTION_ERROR,
		             NM_SETTING_CONNECTION_ERROR_INVALID_PROPERTY,
		             NM_SETTING_CONNECTION_UUID);
		return FALSE;
	}

	if (!priv->type) {
		g_set_error (error,
		             NM_SETTING_CONNECTION_ERROR,
		             NM_SETTING_CONNECTION_ERROR_MISSING_PROPERTY,
		             NM_SETTING_CONNECTION_TYPE);
		return FALSE;
	} else if (!strlen (priv->type)) {
		g_set_error (error,
		             NM_SETTING_CONNECTION_ERROR,
		             NM_SETTING_CONNECTION_ERROR_INVALID_PROPERTY,
		             NM_SETTING_CONNECTION_TYPE);
		return FALSE;
	}

	/* Make sure the corresponding 'type' item is present */
	if (all_settings && !g_slist_find_custom (all_settings, priv->type, find_setting_by_name)) {
		g_set_error (error,
		             NM_SETTING_CONNECTION_ERROR,
		             NM_SETTING_CONNECTION_ERROR_TYPE_SETTING_NOT_FOUND,
		             NM_SETTING_CONNECTION_TYPE);
		return FALSE;
	}

	return TRUE;
}

static void
nm_setting_connection_init (NMSettingConnection *setting)
{
	g_object_set (setting, NM_SETTING_NAME, NM_SETTING_CONNECTION_SETTING_NAME, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingConnectionPrivate *priv = NM_SETTING_CONNECTION_GET_PRIVATE (object);

	g_free (priv->id);
	g_free (priv->uuid);
	g_free (priv->type);
	nm_utils_slist_free (priv->permissions, (GDestroyNotify) permission_free);

	G_OBJECT_CLASS (nm_setting_connection_parent_class)->finalize (object);
}

static GSList *
perm_stringlist_to_permlist (GSList *strlist)
{
	GSList *list = NULL, *iter;

	for (iter = strlist; iter; iter = g_slist_next (iter)) {
		Permission *p;

		p = permission_new_from_str ((const char *) iter->data);
		if (p)
			list = g_slist_append (list, p);
	}

	return list;
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingConnectionPrivate *priv = NM_SETTING_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_ID:
		g_free (priv->id);
		priv->id = g_value_dup_string (value);
		break;
	case PROP_UUID:
		g_free (priv->uuid);
		priv->uuid = g_value_dup_string (value);
		break;
	case PROP_TYPE:
		g_free (priv->type);
		priv->type = g_value_dup_string (value);
		break;
	case PROP_PERMISSIONS:
		nm_utils_slist_free (priv->permissions, (GDestroyNotify) permission_free);
		priv->permissions = perm_stringlist_to_permlist (g_value_get_boxed (value));
		break;
	case PROP_AUTOCONNECT:
		priv->autoconnect = g_value_get_boolean (value);
		break;
	case PROP_TIMESTAMP:
		priv->timestamp = g_value_get_uint64 (value);
		break;
	case PROP_READ_ONLY:
		priv->read_only = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static GSList *
perm_permlist_to_stringlist (GSList *permlist)
{
	GSList *list = NULL, *iter;

	for (iter = permlist; iter; iter = g_slist_next (iter))
		list = g_slist_append (list, permission_to_string ((Permission *) iter->data));
	return list;
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingConnection *setting = NM_SETTING_CONNECTION (object);
	NMSettingConnectionPrivate *priv = NM_SETTING_CONNECTION_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_ID:
		g_value_set_string (value, nm_setting_connection_get_id (setting));
		break;
	case PROP_UUID:
		g_value_set_string (value, nm_setting_connection_get_uuid (setting));
		break;
	case PROP_TYPE:
		g_value_set_string (value, nm_setting_connection_get_connection_type (setting));
		break;
	case PROP_PERMISSIONS:
		g_value_take_boxed (value, perm_permlist_to_stringlist (priv->permissions));
		break;
	case PROP_AUTOCONNECT:
		g_value_set_boolean (value, nm_setting_connection_get_autoconnect (setting));
		break;
	case PROP_TIMESTAMP:
		g_value_set_uint64 (value, nm_setting_connection_get_timestamp (setting));
		break;
	case PROP_READ_ONLY:
		g_value_set_boolean (value, nm_setting_connection_get_read_only (setting));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_connection_class_init (NMSettingConnectionClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingConnectionPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;

	/* Properties */

	/**
	 * NMSettingConnection:id:
	 *
	 * A human readable unique idenfier for the connection, like "Work WiFi" or
	 * "T-Mobile 3G".
	 **/
	g_object_class_install_property
		(object_class, PROP_ID,
		 g_param_spec_string (NM_SETTING_CONNECTION_ID,
						  "ID",
						  "User-readable connection identifier/name.  Must be "
						  "one or more characters and may change over the lifetime "
						  "of the connection if the user decides to rename it.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));

	/**
	 * NMSettingConnection:uuid:
	 *
	 * A universally unique idenfier for the connection, for example generated
	 * with libuuid.  Should be assigned when the connection is created, and
	 * never changed as long as the connection still applies to the same
	 * network.  For example, should not be changed when the
	 * #NMSettingConnection:id or #NMSettingIP4Config changes, but might need
	 * to be re-created when the WiFi SSID, mobile broadband network provider,
	 * or #NMSettingConnection:type changes.
	 *
	 * The UUID must be in the format '2815492f-7e56-435e-b2e9-246bd7cdc664'
	 * (ie, contains only hexadecimal characters and '-').  A suitable UUID may
	 * be generated by nm_utils_uuid_generate() or
	 * nm_utils_uuid_generate_from_string().
	 **/
	g_object_class_install_property
		(object_class, PROP_UUID,
		 g_param_spec_string (NM_SETTING_CONNECTION_UUID,
						  "UUID",
						  "Universally unique connection identifier.  Must be "
						  "in the format '2815492f-7e56-435e-b2e9-246bd7cdc664' "
						  "(ie, contains only hexadecimal characters and '-'). "
						  "The UUID should be assigned when the connection is "
						  "created and never changed as long as the connection "
						  "still applies to the same network.  For example, "
						  "it should not be changed when the user changes the "
						  "connection's 'id', but should be recreated when the "
						  "WiFi SSID, mobile broadband network provider, or the "
						  "connection type changes.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));

	/**
	 * NMSettingConnection:type:
	 *
	 * The general hardware type of the device used for the network connection,
	 * contains the name of the #NMSetting object that describes that hardware
	 * type's parameters.  For example, for WiFi devices, the name of the
	 * #NMSettingWireless setting.
	 **/
	g_object_class_install_property
		(object_class, PROP_TYPE,
		 g_param_spec_string (NM_SETTING_CONNECTION_TYPE,
						  "Type",
						  "Base type of the connection.  For hardware-dependent "
						  "connections, should contain the setting name of the "
						  "hardware-type specific setting (ie, '802-3-ethernet' "
						  "or '802-11-wireless' or 'bluetooth', etc), and for "
						  "non-hardware dependent connections like VPN or "
						  "otherwise, should contain the setting name of that "
						  "setting type (ie, 'vpn' or 'bridge', etc).",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingConnection:permissions:
	 * 
	 * An array of strings defining what access a given user has to this
	 * connection.  If this is NULL or empty, all users are allowed to access
	 * this connection.  Otherwise a user is allowed to access this connection
	 * if and only if they are in this list. Each entry is of the form
	 * "[type]:[id]:[reserved]", for example:
	 *
	 *    user:dcbw:blah
	 *
	 * At this time only the 'user' [type] is allowed.  Any other values are
	 * ignored and reserved for future use.  [id] is the username that this
	 * permission refers to, which may not contain the ':' character. Any
	 * [reserved] information present must be ignored and is reserved for
	 * future use.  All of [type], [id], and [reserved] must be valid UTF-8.
	 */
	g_object_class_install_property
		(object_class, PROP_PERMISSIONS,
		 _nm_param_spec_specialized (NM_SETTING_CONNECTION_PERMISSIONS,
		                  "Permissions",
		                  "An array of strings defining what access a given "
		                  "user has to this connection.  If this is NULL or "
		                  "empty, all users are allowed to access this "
		                  "connection.  Otherwise a user is allowed to access "
		                  "this connection if and only if they are in this "
		                  "array. Each entry is of the form "
		                  "\"[type]:[id]:[reserved]\", for example: "
		                  "\"user:dcbw:blah\"  At this time only the 'user' "
		                  "[type] is allowed.  Any other values are ignored and "
		                  "reserved for future use.  [id] is the username that "
		                  "this permission refers to, which may not contain the "
		                  "':' character.  Any [reserved] information (if "
		                  "present) must be ignored and is reserved for future "
		                  "use.  All of [type], [id], and [reserved] must be "
		                  "valid UTF-8.",
		                  DBUS_TYPE_G_LIST_OF_STRING,
		                  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingConnection:autoconnect:
	 *
	 * Whether or not the connection should be automatically connected by
	 * NetworkManager when the resources for the connection are available.
	 * %TRUE to automatically activate the connection, %FALSE to require manual
	 * intervention to activate the connection.  Defaults to %TRUE.
	 **/
	g_object_class_install_property
		(object_class, PROP_AUTOCONNECT,
		 g_param_spec_boolean (NM_SETTING_CONNECTION_AUTOCONNECT,
						   "Autoconnect",
						   "If TRUE, NetworkManager will activate this connection "
						   "when its network resources are available.  If FALSE, "
						   "the connection must be manually activated by the user "
						   "or some other mechanism.",
						   TRUE,
						   G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));

	/**
	 * NMSettingConnection:timestamp:
	 *
	 * The time, in seconds since the Unix Epoch, that the connection was last
	 * _successfully_ fully activated.
	 **/
	g_object_class_install_property
		(object_class, PROP_TIMESTAMP,
		 g_param_spec_uint64 (NM_SETTING_CONNECTION_TIMESTAMP,
						  "Timestamp",
						  "Timestamp (in seconds since the Unix Epoch) that the "
						  "connection was last successfully activated.  Settings "
						  "services should update the connection timestamp "
						  "periodically when the connection is active to ensure "
						  "that an active connection has the latest timestamp.",
						  0, G_MAXUINT64, 0,
						  G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));

	/**
	 * NMSettingConnection:read-only:
	 *
	 * %TRUE if the connection can be modified using the providing settings
	 * service's D-Bus interface with the right privileges, or %FALSE
	 * if the connection is read-only and cannot be modified.
	 **/
	g_object_class_install_property
	    (object_class, PROP_READ_ONLY,
	     g_param_spec_boolean (NM_SETTING_CONNECTION_READ_ONLY,
	                      "Read-Only",
	                      "If TRUE, the connection is read-only and cannot be "
	                      "changed by the user or any other mechanism.  This is "
	                      "normally set for system connections whose plugin "
	                      "cannot yet write updated connections back out.",
	                      FALSE,
	                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_FUZZY_IGNORE));
}
