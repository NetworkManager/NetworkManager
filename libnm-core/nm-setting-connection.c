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
 * Copyright 2007 - 2013 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-setting-connection.h"

#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-core-enum-types.h"
#include "nm-connection-private.h"
#include "nm-setting-bond.h"
#include "nm-setting-bridge.h"
#include "nm-setting-team.h"
#include "nm-setting-vlan.h"

/**
 * SECTION:nm-setting-connection
 * @short_description: Describes general connection properties
 *
 * The #NMSettingConnection object is a #NMSetting subclass that describes
 * properties that apply to all #NMConnection objects, regardless of what type
 * of network connection they describe.  Each #NMConnection object must contain
 * a #NMSettingConnection setting.
 **/

/*****************************************************************************/

typedef enum {
	PERM_TYPE_USER = 0,
} PermType;

typedef struct {
	guint8 ptype;
	char *item;
} Permission;

NM_GOBJECT_PROPERTIES_DEFINE (NMSettingConnection,
	PROP_ID,
	PROP_UUID,
	PROP_INTERFACE_NAME,
	PROP_TYPE,
	PROP_PERMISSIONS,
	PROP_AUTOCONNECT,
	PROP_AUTOCONNECT_PRIORITY,
	PROP_AUTOCONNECT_RETRIES,
	PROP_MULTI_CONNECT,
	PROP_TIMESTAMP,
	PROP_READ_ONLY,
	PROP_ZONE,
	PROP_MASTER,
	PROP_SLAVE_TYPE,
	PROP_AUTOCONNECT_SLAVES,
	PROP_SECONDARIES,
	PROP_GATEWAY_PING_TIMEOUT,
	PROP_METERED,
	PROP_LLDP,
	PROP_MDNS,
	PROP_LLMNR,
	PROP_STABLE_ID,
	PROP_AUTH_RETRIES,
	PROP_WAIT_DEVICE_TIMEOUT,
);

typedef struct {
	char *id;
	char *uuid;
	char *stable_id;
	char *interface_name;
	char *type;
	char *master;
	char *slave_type;
	NMSettingConnectionAutoconnectSlaves autoconnect_slaves;
	GSList *permissions; /* list of Permission structs */
	gboolean autoconnect;
	int autoconnect_priority;
	int autoconnect_retries;
	int multi_connect;
	guint64 timestamp;
	gboolean read_only;
	char *zone;
	GSList *secondaries; /* secondary connections to activate with the base connection */
	guint gateway_ping_timeout;
	NMMetered metered;
	NMSettingConnectionLldp lldp;
	int auth_retries;
	int mdns;
	int llmnr;
	int wait_device_timeout;
} NMSettingConnectionPrivate;

G_DEFINE_TYPE (NMSettingConnection, nm_setting_connection, NM_TYPE_SETTING)

#define NM_SETTING_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_CONNECTION, NMSettingConnectionPrivate))

/*****************************************************************************/

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

/*****************************************************************************/

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
 * nm_setting_connection_get_stable_id:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:stable_id property of the connection.
 *
 * Returns: the stable-id for the connection
 *
 * Since: 1.4
 **/
const char *
nm_setting_connection_get_stable_id (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), NULL);

	return NM_SETTING_CONNECTION_GET_PRIVATE (setting)->stable_id;
}

/**
 * nm_setting_connection_get_interface_name:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:interface-name property of the connection.
 *
 * Returns: the connection's interface name
 **/
const char *
nm_setting_connection_get_interface_name (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), NULL);

	return NM_SETTING_CONNECTION_GET_PRIVATE (setting)->interface_name;
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
 * Returns the number of entries in the #NMSettingConnection:permissions
 * property of this setting.
 *
 * Returns: the number of permissions entries
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
 * @out_pitem: on return, the permission item (formatted according to @ptype, see
 * #NMSettingConnection:permissions for more detail
 * @out_detail: on return, the permission detail (at this time, always %NULL)
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
 * Returns: %TRUE if the permission was unique and was successfully added to the
 * list, %FALSE if @ptype or @pitem was invalid or it the permission was already
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
	g_return_val_if_fail (ptype && ptype[0], FALSE);
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
	_notify (setting, PROP_PERMISSIONS);

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
	_notify (setting, PROP_PERMISSIONS);
}

/**
 * nm_setting_connection_remove_permission_by_value:
 * @setting: the #NMSettingConnection
 * @ptype: the permission type; at this time only "user" is supported
 * @pitem: the permission item formatted as required for @ptype
 * @detail: (allow-none): unused at this time; must be %NULL
 *
 * Removes the permission from the connection.
 * At this time, only the "user" permission type is supported, and @pitem must
 * be a username. See #NMSettingConnection:permissions: for more details.
 *
 * Returns: %TRUE if the permission was found and removed; %FALSE if it was not.
 */
gboolean
nm_setting_connection_remove_permission_by_value (NMSettingConnection *setting,
                                                  const char *ptype,
                                                  const char *pitem,
                                                  const char *detail)
{
	NMSettingConnectionPrivate *priv;
	Permission *p;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), FALSE);
	g_return_val_if_fail (ptype && ptype[0], FALSE);
	g_return_val_if_fail (detail == NULL, FALSE);
	g_return_val_if_fail (pitem != NULL, FALSE);

	/* Only "user" for now... */
	g_return_val_if_fail (strcmp (ptype, "user") == 0, FALSE);

	priv = NM_SETTING_CONNECTION_GET_PRIVATE (setting);
	for (iter = priv->permissions; iter; iter = g_slist_next (iter)) {
		p = iter->data;
		if (strcmp (pitem, p->item) == 0) {
			permission_free ((Permission *) iter->data);
			priv->permissions = g_slist_delete_link (priv->permissions, iter);
			_notify (setting, PROP_PERMISSIONS);
			return TRUE;
		}
	}
	return FALSE;
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
 * nm_setting_connection_get_autoconnect_priority:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:autoconnect-priority property of the connection.
 * The higher number, the higher priority.
 *
 * Returns: the connection's autoconnect priority
 **/
int
nm_setting_connection_get_autoconnect_priority (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), 0);

	return NM_SETTING_CONNECTION_GET_PRIVATE (setting)->autoconnect_priority;
}

/**
 * nm_setting_connection_get_autoconnect_retries:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:autoconnect-retries property of the connection.
 * Zero means infinite, -1 means the global default value.
 *
 * Returns: the connection's autoconnect retries
 *
 * Since: 1.6
 **/
int
nm_setting_connection_get_autoconnect_retries (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), -1);

	return NM_SETTING_CONNECTION_GET_PRIVATE (setting)->autoconnect_retries;
}

/**
 * nm_setting_connection_get_multi_connect:
 * @setting: the #NMSettingConnection
 *
 * Returns: the #NMSettingConnection:multi-connect property of the connection.
 *
 * Since: 1.14
 **/
NMConnectionMultiConnect
nm_setting_connection_get_multi_connect (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), -1);

	return (NMConnectionMultiConnect) NM_SETTING_CONNECTION_GET_PRIVATE (setting)->multi_connect;
}

/**
 * nm_setting_connection_get_auth_retries:
 * @setting: the #NMSettingConnection
 *
 * Returns the value contained in the #NMSettingConnection:auth-retries property.
 *
 * Returns: the configured authentication retries. Zero means
 * infinity and -1 means a global default value.
 *
 * Since: 1.10
 **/
int
nm_setting_connection_get_auth_retries (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), -1);

	return NM_SETTING_CONNECTION_GET_PRIVATE (setting)->auth_retries;
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

static GVariant *
_to_dbus_fcn_timestamp (const NMSettInfoSetting *sett_info,
                        guint property_idx,
                        NMConnection *connection,
                        NMSetting *setting,
                        NMConnectionSerializationFlags flags,
                        const NMConnectionSerializationOptions *options)
{
	guint64 v;

	v =   options && options->timestamp.has
	    ? options->timestamp.val
	    : NM_SETTING_CONNECTION_GET_PRIVATE (setting)->timestamp;

	if (v == 0u)
		return NULL;

	return g_variant_new_uint64 (v);
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

/**
 * nm_setting_connection_get_zone:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:zone property of the connection.
 *
 * Returns: the trust level of a connection
 **/
const char *
nm_setting_connection_get_zone (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), NULL);

	return NM_SETTING_CONNECTION_GET_PRIVATE (setting)->zone;
}

/**
 * nm_setting_connection_get_master:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:master property of the connection.
 *
 * Returns: interface name of the master device or UUID of the master
 * connection.
 */
const char *
nm_setting_connection_get_master (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), NULL);

	return NM_SETTING_CONNECTION_GET_PRIVATE (setting)->master;
}

/**
 * nm_setting_connection_get_slave_type:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:slave-type property of the connection.
 *
 * Returns: the type of slave this connection is, if any
 */
const char *
nm_setting_connection_get_slave_type (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), NULL);

	return NM_SETTING_CONNECTION_GET_PRIVATE (setting)->slave_type;
}

/**
 * nm_setting_connection_is_slave_type:
 * @setting: the #NMSettingConnection
 * @type: the setting name (ie #NM_SETTING_BOND_SETTING_NAME) to be matched
 * against @setting's slave type
 *
 * Returns: %TRUE if connection is of the given slave @type
 */
gboolean
nm_setting_connection_is_slave_type (NMSettingConnection *setting,
                                     const char *type)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), FALSE);

	return !g_strcmp0 (NM_SETTING_CONNECTION_GET_PRIVATE (setting)->slave_type, type);
}

/**
 * nm_setting_connection_get_wait_device_timeout:
 * @setting: the #NMSettingConnection
 *
 * Returns: the %NM_SETTING_CONNECTION_WAIT_DEVICE_TIMEOUT property with
 *   the timeout in milli seconds. -1 is the default.
 *
 * Since: 1.20
 */
gint32
nm_setting_connection_get_wait_device_timeout (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), -1);

	return NM_SETTING_CONNECTION_GET_PRIVATE (setting)->wait_device_timeout;
}

/**
 * nm_setting_connection_get_autoconnect_slaves:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:autoconnect-slaves property of the connection.
 *
 * Returns: whether slaves of the connection should be activated together
 *          with the connection.
 *
 * Since: 1.2
 **/
NMSettingConnectionAutoconnectSlaves
nm_setting_connection_get_autoconnect_slaves (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_DEFAULT);

	return NM_SETTING_CONNECTION_GET_PRIVATE (setting)->autoconnect_slaves;
}

/**
 * nm_setting_connection_get_num_secondaries:
 * @setting: the #NMSettingConnection
 *
 * Returns: the number of configured secondary connection UUIDs
 **/
guint32
nm_setting_connection_get_num_secondaries (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), 0);

	return g_slist_length (NM_SETTING_CONNECTION_GET_PRIVATE (setting)->secondaries);
}

/**
 * nm_setting_connection_get_secondary:
 * @setting: the #NMSettingConnection
 * @idx: the zero-based index of the secondary connection UUID entry
 *
 * Returns: the secondary connection UUID at index @idx
 **/
const char *
nm_setting_connection_get_secondary (NMSettingConnection *setting, guint32 idx)
{
	NMSettingConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), NULL);

	priv = NM_SETTING_CONNECTION_GET_PRIVATE (setting);
	g_return_val_if_fail (idx <= g_slist_length (priv->secondaries), NULL);

	return (const char *) g_slist_nth_data (priv->secondaries, idx);
}

/**
 * nm_setting_connection_add_secondary:
 * @setting: the #NMSettingConnection
 * @sec_uuid: the secondary connection UUID to add
 *
 * Adds a new secondary connection UUID to the setting.
 *
 * Returns: %TRUE if the secondary connection UUID was added; %FALSE if the UUID
 * was already present
 **/
gboolean
nm_setting_connection_add_secondary (NMSettingConnection *setting,
                                     const char *sec_uuid)
{
	NMSettingConnectionPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), FALSE);
	g_return_val_if_fail (sec_uuid != NULL, FALSE);
	g_return_val_if_fail (sec_uuid[0] != '\0', FALSE);

	priv = NM_SETTING_CONNECTION_GET_PRIVATE (setting);
	for (iter = priv->secondaries; iter; iter = g_slist_next (iter)) {
		if (!strcmp (sec_uuid, (char *) iter->data))
			return FALSE;
	}

	priv->secondaries = g_slist_append (priv->secondaries, g_strdup (sec_uuid));
	_notify (setting, PROP_SECONDARIES);
	return TRUE;
}

/**
 * nm_setting_connection_remove_secondary:
 * @setting: the #NMSettingConnection
 * @idx: index number of the secondary connection UUID
 *
 * Removes the secondary coonnection UUID at index @idx.
 **/
void
nm_setting_connection_remove_secondary (NMSettingConnection *setting, guint32 idx)
{
	NMSettingConnectionPrivate *priv;
	GSList *elt;

	g_return_if_fail (NM_IS_SETTING_CONNECTION (setting));

	priv = NM_SETTING_CONNECTION_GET_PRIVATE (setting);
	elt = g_slist_nth (priv->secondaries, idx);
	g_return_if_fail (elt != NULL);

	g_free (elt->data);
	priv->secondaries = g_slist_delete_link (priv->secondaries, elt);
	_notify (setting, PROP_SECONDARIES);
}

/**
 * nm_setting_connection_remove_secondary_by_value:
 * @setting: the #NMSettingConnection
 * @sec_uuid: the secondary connection UUID to remove
 *
 * Removes the secondary coonnection UUID @sec_uuid.
 *
 * Returns: %TRUE if the secondary connection UUID was found and removed; %FALSE if it was not.
 **/
gboolean
nm_setting_connection_remove_secondary_by_value (NMSettingConnection *setting,
                                                 const char *sec_uuid)
{
	NMSettingConnectionPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), FALSE);
	g_return_val_if_fail (sec_uuid != NULL, FALSE);
	g_return_val_if_fail (sec_uuid[0] != '\0', FALSE);

	priv = NM_SETTING_CONNECTION_GET_PRIVATE (setting);
	for (iter = priv->secondaries; iter; iter = g_slist_next (iter)) {
		if (!strcmp (sec_uuid, (char *) iter->data)) {
			priv->secondaries = g_slist_delete_link (priv->secondaries, iter);
			_notify (setting, PROP_SECONDARIES);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_connection_get_gateway_ping_timeout:
 * @setting: the #NMSettingConnection
 *
 * Returns: the value contained in the #NMSettingConnection:gateway-ping-timeout
 * property.
 **/
guint32
nm_setting_connection_get_gateway_ping_timeout (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), 0);

	return NM_SETTING_CONNECTION_GET_PRIVATE (setting)->gateway_ping_timeout;
}

/**
 * nm_setting_connection_get_metered:
 * @setting: the #NMSettingConnection
 *
 * Returns: the #NMSettingConnection:metered property of the setting.
 *
 * Since: 1.2
 **/
NMMetered
nm_setting_connection_get_metered (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting),
	                      NM_METERED_UNKNOWN);

	return NM_SETTING_CONNECTION_GET_PRIVATE (setting)->metered;
}

/**
 * nm_setting_connection_get_lldp:
 * @setting: the #NMSettingConnection
 *
 * Returns the #NMSettingConnection:lldp property of the connection.
 *
 * Returns: a %NMSettingConnectionLldp which indicates whether LLDP must be
 * enabled for the connection.
 *
 * Since: 1.2
 **/
NMSettingConnectionLldp
nm_setting_connection_get_lldp (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting), NM_SETTING_CONNECTION_LLDP_DEFAULT);

	return NM_SETTING_CONNECTION_GET_PRIVATE (setting)->lldp;
}

/**
 * nm_setting_connection_get_mdns:
 * @setting: the #NMSettingConnection
 *
 * Returns: the #NMSettingConnection:mdns property of the setting.
 *
 * Since: 1.12
 **/
NMSettingConnectionMdns
nm_setting_connection_get_mdns (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting),
	                      NM_SETTING_CONNECTION_MDNS_DEFAULT);

	return NM_SETTING_CONNECTION_GET_PRIVATE (setting)->mdns;
}

/**
 * nm_setting_connection_get_llmnr:
 * @setting: the #NMSettingConnection
 *
 * Returns: the #NMSettingConnection:llmnr property of the setting.
 *
 * Since: 1.14
 **/
NMSettingConnectionLlmnr
nm_setting_connection_get_llmnr (NMSettingConnection *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CONNECTION (setting),
	                      NM_SETTING_CONNECTION_LLMNR_DEFAULT);

	return NM_SETTING_CONNECTION_GET_PRIVATE (setting)->llmnr;
}

static void
_set_error_missing_base_setting (GError **error, const char *type)
{
	g_set_error (error,
	             NM_CONNECTION_ERROR,
	             NM_CONNECTION_ERROR_MISSING_SETTING,
	             _("setting required for connection of type '%s'"),
	             type);
	g_prefix_error (error, "%s: ", type);
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingConnectionPrivate *priv = NM_SETTING_CONNECTION_GET_PRIVATE (setting);
	gboolean is_slave;
	const char *slave_setting_type;
	NMSetting *normerr_base_type = NULL;
	const char *type;
	const char *slave_type;
	const char *normerr_slave_setting_type = NULL;
	const char *normerr_missing_slave_type = NULL;
	const char *normerr_missing_slave_type_port = NULL;
	gboolean normerr_base_setting = FALSE;

	if (!priv->id) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_ID);
		return FALSE;
	} else if (!priv->id[0]) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_ID);
		return FALSE;
	}

	if (priv->uuid && !nm_utils_is_uuid (priv->uuid)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid UUID"),
		             priv->uuid);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_UUID);
		return FALSE;
	}

	if (priv->interface_name) {
		GError *tmp_error = NULL;

		if (!nm_utils_is_valid_iface_name (priv->interface_name, &tmp_error)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             "'%s': %s", priv->interface_name, tmp_error->message);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_INTERFACE_NAME);
			g_error_free (tmp_error);
			return FALSE;
		}
	}

	type = priv->type;
	if (!type) {
		if (   !connection
		    || !(normerr_base_type = _nm_connection_find_base_type_setting (connection))) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
			                     _("property is missing"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_TYPE);
			return FALSE;
		}
		type = nm_setting_get_name (normerr_base_type);
	} else {
		GType base_type;

		if (!type[0]) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("property is empty"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_TYPE);
			return FALSE;
		}

		base_type = nm_setting_lookup_type (type);
		if (   base_type == G_TYPE_INVALID
		    || _nm_setting_type_get_base_type_priority (base_type) == NM_SETTING_PRIORITY_INVALID) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("connection type '%s' is not valid"),
			             type);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_TYPE);
			return FALSE;
		}

		/* Make sure the corresponding 'type' item is present */
		if (   connection
		    && !nm_connection_get_setting_by_name (connection, type)) {
			NMSetting *s_base;
			NMConnection *connection2;

			s_base = g_object_new (base_type, NULL);
			connection2 = nm_simple_connection_new_clone (connection);
			nm_connection_add_setting (connection2, s_base);

			normerr_base_setting = nm_setting_verify (s_base, connection2, NULL);

			g_object_unref (connection2);

			if (!normerr_base_setting) {
				_set_error_missing_base_setting (error, type);
				return FALSE;
			}
		}
	}

	is_slave = FALSE;
	slave_setting_type = NULL;
	slave_type = priv->slave_type;
	if (slave_type) {
		is_slave = _nm_setting_slave_type_is_valid (slave_type, &slave_setting_type);
		if (!is_slave) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("Unknown slave type '%s'"), slave_type);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_SLAVE_TYPE);
			return FALSE;
		}
	}

	if (is_slave) {
		if (!priv->master) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_MISSING_PROPERTY,
			             _("Slave connections need a valid '%s' property"), NM_SETTING_CONNECTION_MASTER);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_MASTER);
			return FALSE;
		}
		if (   slave_setting_type
		    && connection
		    && !nm_connection_get_setting_by_name (connection, slave_setting_type))
			normerr_slave_setting_type = slave_setting_type;
	} else {
		nm_assert (!slave_type);
		if (priv->master) {
			NMSetting *s_port;

			if (   connection
			    && (slave_type = _nm_connection_detect_slave_type (connection, &s_port))) {
				normerr_missing_slave_type = slave_type;
				normerr_missing_slave_type_port = nm_setting_get_name (s_port);
			} else {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_MISSING_PROPERTY,
				             _("Cannot set '%s' without '%s'"),
				             NM_SETTING_CONNECTION_MASTER, NM_SETTING_CONNECTION_SLAVE_TYPE);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_SLAVE_TYPE);
				return FALSE;
			}
		}
	}

	if (   strcmp (type, NM_SETTING_OVS_PORT_SETTING_NAME) == 0
	    && slave_type
	    && strcmp (slave_type, NM_SETTING_OVS_BRIDGE_SETTING_NAME) != 0) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_MISSING_PROPERTY,
		             _("'%s' connections must be enslaved to '%s', not '%s'"),
		             NM_SETTING_OVS_PORT_SETTING_NAME,
		             NM_SETTING_OVS_BRIDGE_SETTING_NAME,
		             slave_type);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_SLAVE_TYPE);
		return FALSE;
	}

	if (priv->metered != NM_METERED_UNKNOWN &&
	    priv->metered != NM_METERED_YES &&
	    priv->metered != NM_METERED_NO) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("metered value %d is not valid"), priv->metered);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME,
		                NM_SETTING_CONNECTION_METERED);
		return FALSE;
	}

	if (   priv->mdns < (int) NM_SETTING_CONNECTION_MDNS_DEFAULT
	    || priv->mdns > (int) NM_SETTING_CONNECTION_MDNS_YES) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("value %d is not valid"), priv->mdns);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME,
		                NM_SETTING_CONNECTION_MDNS);
		return FALSE;
	}

	if (   priv->llmnr < (int) NM_SETTING_CONNECTION_LLMNR_DEFAULT
	    || priv->llmnr > (int) NM_SETTING_CONNECTION_LLMNR_YES) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("value %d is not valid"), priv->llmnr);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME,
		                NM_SETTING_CONNECTION_LLMNR);
		return FALSE;
	}

	if (!NM_IN_SET (priv->multi_connect, (int) NM_CONNECTION_MULTI_CONNECT_DEFAULT,
	                                     (int) NM_CONNECTION_MULTI_CONNECT_SINGLE,
	                                     (int) NM_CONNECTION_MULTI_CONNECT_MANUAL_MULTIPLE,
	                                     (int) NM_CONNECTION_MULTI_CONNECT_MULTIPLE)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("value %d is not valid"), priv->multi_connect);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME,
		                NM_SETTING_CONNECTION_MULTI_CONNECT);
		return FALSE;
	}

	if (   priv->wait_device_timeout != -1
	    && !priv->interface_name) {
		/* currently, only waiting by interface-name is implemented. Hence reject
		 * configurations that are not implemented (yet). */
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("wait-device-timeout requires %s"),
		             NM_SETTING_CONNECTION_INTERFACE_NAME);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME,
		                NM_SETTING_CONNECTION_WAIT_DEVICE_TIMEOUT);
		return FALSE;
	}

	/* *** errors above here should be always fatal, below NORMALIZABLE_ERROR *** */

	if (!priv->uuid) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_UUID);
		return NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
	}

	if (normerr_base_type) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_MISSING_PROPERTY,
		             _("property type should be set to '%s'"),
		             nm_setting_get_name (normerr_base_type));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_TYPE);
		return NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
	}

	if (normerr_base_setting) {
		_set_error_missing_base_setting (error, priv->type);
		return NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
	}

	if (normerr_slave_setting_type) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_MISSING_SETTING,
		             _("slave-type '%s' requires a '%s' setting in the connection"),
		             priv->slave_type, normerr_slave_setting_type);
		g_prefix_error (error, "%s: ", normerr_slave_setting_type);
		return NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
	}

	if (normerr_missing_slave_type) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_MISSING_PROPERTY,
		             _("Detect a slave connection with '%s' set and a port type '%s'. '%s' should be set to '%s'"),
		             NM_SETTING_CONNECTION_MASTER, normerr_missing_slave_type_port,
		             NM_SETTING_CONNECTION_SLAVE_TYPE, normerr_missing_slave_type);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_SLAVE_TYPE);
		return NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
	}

	if (connection) {
		gboolean has_bridge_port = FALSE;

		if (   (   !nm_streq0 (priv->slave_type, NM_SETTING_BRIDGE_SETTING_NAME)
		        && (has_bridge_port = !!nm_connection_get_setting_by_name (connection, NM_SETTING_BRIDGE_PORT_SETTING_NAME)))
		    || (   !nm_streq0 (priv->slave_type, NM_SETTING_TEAM_SETTING_NAME)
		        && nm_connection_get_setting_by_name (connection, NM_SETTING_TEAM_PORT_SETTING_NAME))) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_SETTING,
			             _("A slave connection with '%s' set to '%s' cannot have a '%s' setting"),
			             NM_SETTING_CONNECTION_SLAVE_TYPE, priv->slave_type ?: "",
			             has_bridge_port ? NM_SETTING_BRIDGE_PORT_SETTING_NAME : NM_SETTING_TEAM_PORT_SETTING_NAME);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_SLAVE_TYPE);
			return NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
		}
	}

	return TRUE;
}

static const char *
find_virtual_interface_name (GVariant *connection_dict)
{
	GVariant *setting_dict;
	const char *interface_name;

	setting_dict = g_variant_lookup_value (connection_dict, NM_SETTING_BOND_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
	if (!setting_dict)
		setting_dict = g_variant_lookup_value (connection_dict, NM_SETTING_BRIDGE_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
	if (!setting_dict)
		setting_dict = g_variant_lookup_value (connection_dict, NM_SETTING_TEAM_SETTING_NAME, NM_VARIANT_TYPE_SETTING);
	if (!setting_dict)
		setting_dict = g_variant_lookup_value (connection_dict, NM_SETTING_VLAN_SETTING_NAME, NM_VARIANT_TYPE_SETTING);

	if (!setting_dict)
		return NULL;

	/* All of the deprecated virtual interface name properties were named "interface-name". */
	if (!g_variant_lookup (setting_dict, "interface-name", "&s", &interface_name))
		interface_name = NULL;

	g_variant_unref (setting_dict);
	return interface_name;
}

static gboolean
nm_setting_connection_set_interface_name (NMSetting *setting,
                                          GVariant *connection_dict,
                                          const char *property,
                                          GVariant *value,
                                          NMSettingParseFlags parse_flags,
                                          GError **error)
{
	const char *interface_name;

	/* For compatibility reasons, if there is an invalid virtual interface name,
	 * we need to make verification fail, even if that virtual name would be
	 * overridden by a valid connection.interface-name.
	 */
	interface_name = find_virtual_interface_name (connection_dict);
	if (!interface_name || nm_utils_is_valid_iface_name (interface_name, NULL))
		interface_name = g_variant_get_string (value, NULL);

	g_object_set (G_OBJECT (setting),
	              NM_SETTING_CONNECTION_INTERFACE_NAME, interface_name,
	              NULL);

	return TRUE;
}

static gboolean
nm_setting_connection_no_interface_name (NMSetting *setting,
                                         GVariant *connection_dict,
                                         const char *property,
                                         NMSettingParseFlags parse_flags,
                                         GError **error)
{
	const char *virtual_interface_name;

	virtual_interface_name = find_virtual_interface_name (connection_dict);
	g_object_set (G_OBJECT (setting),
	              NM_SETTING_CONNECTION_INTERFACE_NAME, virtual_interface_name,
	              NULL);
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
	if (   NM_FLAGS_HAS (flags, NM_SETTING_COMPARE_FLAG_IGNORE_ID)
	    && nm_streq (sett_info->property_infos[property_idx].name, NM_SETTING_CONNECTION_ID))
		return NM_TERNARY_DEFAULT;

	if (   NM_FLAGS_HAS(flags, NM_SETTING_COMPARE_FLAG_IGNORE_TIMESTAMP)
	    && nm_streq (sett_info->property_infos[property_idx].name, NM_SETTING_CONNECTION_TIMESTAMP))
		return NM_TERNARY_DEFAULT;

	return NM_SETTING_CLASS (nm_setting_connection_parent_class)->compare_property (sett_info,
	                                                                                property_idx,
	                                                                                con_a,
	                                                                                set_a,
	                                                                                con_b,
	                                                                                set_b,
	                                                                                flags);
}

static GSList *
perm_strv_to_permlist (char **strv)
{
	GSList *list = NULL;
	int i;

	if (!strv)
		return NULL;

	for (i = 0; strv[i]; i++) {
		Permission *p;

		p = permission_new_from_str (strv[i]);
		if (p)
			list = g_slist_append (list, p);
	}

	return list;
}

static char **
perm_permlist_to_strv (GSList *permlist)
{
	GPtrArray *strings;
	GSList *iter;

	strings = g_ptr_array_new ();
	for (iter = permlist; iter; iter = g_slist_next (iter))
		g_ptr_array_add (strings, permission_to_string ((Permission *) iter->data));
	g_ptr_array_add (strings, NULL);

	return (char **) g_ptr_array_free (strings, FALSE);
}

/*****************************************************************************/

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
	case PROP_STABLE_ID:
		g_value_set_string (value, nm_setting_connection_get_stable_id (setting));
		break;
	case PROP_INTERFACE_NAME:
		g_value_set_string (value, nm_setting_connection_get_interface_name (setting));
		break;
	case PROP_TYPE:
		g_value_set_string (value, nm_setting_connection_get_connection_type (setting));
		break;
	case PROP_PERMISSIONS:
		g_value_take_boxed (value, perm_permlist_to_strv (priv->permissions));
		break;
	case PROP_AUTOCONNECT:
		g_value_set_boolean (value, nm_setting_connection_get_autoconnect (setting));
		break;
	case PROP_AUTOCONNECT_PRIORITY:
		g_value_set_int (value, nm_setting_connection_get_autoconnect_priority (setting));
		break;
	case PROP_AUTOCONNECT_RETRIES:
		g_value_set_int (value, nm_setting_connection_get_autoconnect_retries (setting));
		break;
	case PROP_MULTI_CONNECT:
		g_value_set_int (value, priv->multi_connect);
		break;
	case PROP_TIMESTAMP:
		g_value_set_uint64 (value, nm_setting_connection_get_timestamp (setting));
		break;
	case PROP_READ_ONLY:
		g_value_set_boolean (value, nm_setting_connection_get_read_only (setting));
		break;
	case PROP_ZONE:
		g_value_set_string (value, nm_setting_connection_get_zone (setting));
		break;
	case PROP_MASTER:
		g_value_set_string (value, nm_setting_connection_get_master (setting));
		break;
	case PROP_SLAVE_TYPE:
		g_value_set_string (value, nm_setting_connection_get_slave_type (setting));
		break;
	case PROP_AUTOCONNECT_SLAVES:
		g_value_set_enum (value, nm_setting_connection_get_autoconnect_slaves (setting));
		break;
	case PROP_SECONDARIES:
		g_value_take_boxed (value, _nm_utils_slist_to_strv (priv->secondaries, TRUE));
		break;
	case PROP_GATEWAY_PING_TIMEOUT:
		g_value_set_uint (value, priv->gateway_ping_timeout);
		break;
	case PROP_METERED:
		g_value_set_enum (value, priv->metered);
		break;
	case PROP_LLDP:
		g_value_set_int (value, priv->lldp);
		break;
	case PROP_AUTH_RETRIES:
		g_value_set_int (value, priv->auth_retries);
		break;
	case PROP_MDNS:
		g_value_set_int (value, priv->mdns);
		break;
	case PROP_LLMNR:
		g_value_set_int (value, priv->llmnr);
		break;
	case PROP_WAIT_DEVICE_TIMEOUT:
		g_value_set_int (value, priv->wait_device_timeout);
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
	case PROP_STABLE_ID:
		g_free (priv->stable_id);
		priv->stable_id = g_value_dup_string (value);
		break;
	case PROP_INTERFACE_NAME:
		g_free (priv->interface_name);
		priv->interface_name = g_value_dup_string (value);
		break;
	case PROP_TYPE:
		g_free (priv->type);
		priv->type = g_value_dup_string (value);
		break;
	case PROP_PERMISSIONS:
		g_slist_free_full (priv->permissions, (GDestroyNotify) permission_free);
		priv->permissions = perm_strv_to_permlist (g_value_get_boxed (value));
		break;
	case PROP_AUTOCONNECT:
		priv->autoconnect = g_value_get_boolean (value);
		break;
	case PROP_AUTOCONNECT_PRIORITY:
		priv->autoconnect_priority = g_value_get_int (value);
		break;
	case PROP_AUTOCONNECT_RETRIES:
		priv->autoconnect_retries = g_value_get_int (value);
		break;
	case PROP_MULTI_CONNECT:
		priv->multi_connect = g_value_get_int (value);
		break;
	case PROP_TIMESTAMP:
		priv->timestamp = g_value_get_uint64 (value);
		break;
	case PROP_READ_ONLY:
		priv->read_only = g_value_get_boolean (value);
		break;
	case PROP_ZONE:
		g_free (priv->zone);
		priv->zone = g_value_dup_string (value);
		break;
	case PROP_MASTER:
		g_free (priv->master);
		priv->master = g_value_dup_string (value);
		break;
	case PROP_SLAVE_TYPE:
		g_free (priv->slave_type);
		priv->slave_type = g_value_dup_string (value);
		break;
	case PROP_AUTOCONNECT_SLAVES:
		priv->autoconnect_slaves = g_value_get_enum (value);
		break;
	case PROP_SECONDARIES:
		g_slist_free_full (priv->secondaries, g_free);
		priv->secondaries = _nm_utils_strv_to_slist (g_value_get_boxed (value), TRUE);
		break;
	case PROP_GATEWAY_PING_TIMEOUT:
		priv->gateway_ping_timeout = g_value_get_uint (value);
		break;
	case PROP_METERED:
		priv->metered = g_value_get_enum (value);
		break;
	case PROP_LLDP:
		priv->lldp = g_value_get_int (value);
		break;
	case PROP_AUTH_RETRIES:
		priv->auth_retries = g_value_get_int (value);
		break;
	case PROP_MDNS:
		priv->mdns = g_value_get_int (value);
		break;
	case PROP_LLMNR:
		priv->llmnr = g_value_get_int (value);
		break;
	case PROP_WAIT_DEVICE_TIMEOUT:
		priv->wait_device_timeout = g_value_get_int (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_connection_init (NMSettingConnection *setting)
{
	NMSettingConnectionPrivate *priv = NM_SETTING_CONNECTION_GET_PRIVATE (setting);

	priv->mdns = NM_SETTING_CONNECTION_MDNS_DEFAULT;
	priv->llmnr = NM_SETTING_CONNECTION_LLMNR_DEFAULT;
	priv->wait_device_timeout = -1;
}

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

static void
finalize (GObject *object)
{
	NMSettingConnectionPrivate *priv = NM_SETTING_CONNECTION_GET_PRIVATE (object);

	g_free (priv->id);
	g_free (priv->uuid);
	g_free (priv->stable_id);
	g_free (priv->interface_name);
	g_free (priv->type);
	g_free (priv->zone);
	g_free (priv->master);
	g_free (priv->slave_type);
	g_slist_free_full (priv->permissions, (GDestroyNotify) permission_free);
	g_slist_free_full (priv->secondaries, g_free);

	G_OBJECT_CLASS (nm_setting_connection_parent_class)->finalize (object);
}

static void
nm_setting_connection_class_init (NMSettingConnectionClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);
	GArray *properties_override = _nm_sett_info_property_override_create_array ();

	g_type_class_add_private (klass, sizeof (NMSettingConnectionPrivate));

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize     = finalize;

	setting_class->verify           = verify;
	setting_class->compare_property = compare_property;

	/**
	 * NMSettingConnection:id:
	 *
	 * A human readable unique identifier for the connection, like "Work Wi-Fi"
	 * or "T-Mobile 3G".
	 **/
	/* ---ifcfg-rh---
	 * property: id
	 * variable: NAME(+)
	 * description: User friendly name for the connection profile.
	 * ---end---
	 */
	obj_properties[PROP_ID] =
	    g_param_spec_string (NM_SETTING_CONNECTION_ID, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_FUZZY_IGNORE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingConnection:uuid:
	 *
	 * A universally unique identifier for the connection, for example generated
	 * with libuuid.  It should be assigned when the connection is created, and
	 * never changed as long as the connection still applies to the same
	 * network.  For example, it should not be changed when the
	 * #NMSettingConnection:id property or #NMSettingIP4Config changes, but
	 * might need to be re-created when the Wi-Fi SSID, mobile broadband network
	 * provider, or #NMSettingConnection:type property changes.
	 *
	 * The UUID must be in the format "2815492f-7e56-435e-b2e9-246bd7cdc664"
	 * (ie, contains only hexadecimal characters and "-").  A suitable UUID may
	 * be generated by nm_utils_uuid_generate() or
	 * nm_utils_uuid_generate_from_string().
	 **/
	/* ---ifcfg-rh---
	 * property: uuid
	 * variable: UUID(+)
	 * description: UUID for the connection profile. When missing, NetworkManager
	 *   creates the UUID itself (by hashing the filename).
	 * ---end---
	 */
	obj_properties[PROP_UUID] =
	    g_param_spec_string (NM_SETTING_CONNECTION_UUID, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_FUZZY_IGNORE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingConnection:stable-id:
	 *
	 * This represents the identity of the connection used for various purposes.
	 * It allows to configure multiple profiles to share the identity. Also,
	 * the stable-id can contain placeholders that are substituted dynamically and
	 * deterministically depending on the context.
	 *
	 * The stable-id is used for generating IPv6 stable private addresses
	 * with ipv6.addr-gen-mode=stable-privacy. It is also used to seed the
	 * generated cloned MAC address for ethernet.cloned-mac-address=stable
	 * and wifi.cloned-mac-address=stable. It is also used as DHCP client
	 * identifier with ipv4.dhcp-client-id=stable and to derive the DHCP
	 * DUID with ipv6.dhcp-duid=stable-[llt,ll,uuid].
	 *
	 * Note that depending on the context where it is used, other parameters are
	 * also seeded into the generation algorithm. For example, a per-host key
	 * is commonly also included, so that different systems end up generating
	 * different IDs. Or with ipv6.addr-gen-mode=stable-privacy, also the device's
	 * name is included, so that different interfaces yield different addresses.
	 *
	 * The '$' character is treated special to perform dynamic substitutions
	 * at runtime. Currently supported are "${CONNECTION}", "${DEVICE}", "${MAC}",
	 * "${BOOT}", "${RANDOM}".
	 * These effectively create unique IDs per-connection, per-device, per-boot,
	 * or every time. Note that "${DEVICE}" corresponds to the interface name of the
	 * device and "${MAC}" is the permanent MAC address of the device.
	 * Any unrecognized patterns following '$' are treated verbatim, however
	 * are reserved for future use. You are thus advised to avoid '$' or
	 * escape it as "$$".
	 * For example, set it to "${CONNECTION}-${BOOT}-${DEVICE}" to create a unique id for
	 * this connection that changes with every reboot and differs depending on the
	 * interface where the profile activates.
	 *
	 * If the value is unset, a global connection default is consulted. If the
	 * value is still unset, the default is similar to "${CONNECTION}" and uses
	 * a unique, fixed ID for the connection.
	 *
	 * Since: 1.4
	 **/
	/* ---ifcfg-rh---
	 * property: stable-id
	 * variable: STABLE_ID(+)
	 * description: Token to generate stable IDs.
	 * ---end---
	 */
	obj_properties[PROP_STABLE_ID] =
	    g_param_spec_string (NM_SETTING_CONNECTION_STABLE_ID, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_FUZZY_IGNORE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingConnection:interface-name:
	 *
	 * The name of the network interface this connection is bound to. If not
	 * set, then the connection can be attached to any interface of the
	 * appropriate type (subject to restrictions imposed by other settings).
	 *
	 * For software devices this specifies the name of the created device.
	 *
	 * For connection types where interface names cannot easily be made
	 * persistent (e.g. mobile broadband or USB Ethernet), this property should
	 * not be used. Setting this property restricts the interfaces a connection
	 * can be used with, and if interface names change or are reordered the
	 * connection may be applied to the wrong interface.
	 **/
	/* ---ifcfg-rh---
	 * property: interface-name
	 * variable: DEVICE
	 * description: Interface name of the device this profile is bound to. The variable
	 *   can be left out when the profile should apply for more devices. Note that DEVICE
	 *   can be required for some connection types.
	 * ---end---
	 */
	obj_properties[PROP_INTERFACE_NAME] =
	    g_param_spec_string (NM_SETTING_CONNECTION_INTERFACE_NAME, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_INFERRABLE |
	                         G_PARAM_STATIC_STRINGS);

	_properties_override_add_override (properties_override,
	                                   obj_properties[PROP_INTERFACE_NAME],
	                                   G_VARIANT_TYPE_STRING,
	                                   NULL,
	                                   nm_setting_connection_set_interface_name,
	                                   nm_setting_connection_no_interface_name);

	/**
	 * NMSettingConnection:type:
	 *
	 * Base type of the connection. For hardware-dependent connections, should
	 * contain the setting name of the hardware-type specific setting (ie,
	 * "802-3-ethernet" or "802-11-wireless" or "bluetooth", etc), and for
	 * non-hardware dependent connections like VPN or otherwise, should contain
	 * the setting name of that setting type (ie, "vpn" or "bridge", etc).
	 **/
	/* ---ifcfg-rh---
	 * property: type
	 * variable: TYPE (DEVICETYPE, DEVICE)
	 * values: Ethernet, Wireless, InfiniBand, Bridge, Bond, Vlan, Team, TeamPort
	 * description: Base type of the connection. DEVICETYPE is used for teaming
	 *   connections.
	 * example: TYPE=Ethernet; TYPE=Bond; TYPE=Bridge; DEVICETYPE=TeamPort
	 * ---end---
	 */
	obj_properties[PROP_TYPE] =
	    g_param_spec_string (NM_SETTING_CONNECTION_TYPE, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_INFERRABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingConnection:permissions:
	 *
	 * An array of strings defining what access a given user has to this
	 * connection.  If this is %NULL or empty, all users are allowed to access
	 * this connection; otherwise users are allowed if and only if they are in
	 * this list.  When this is not empty, the connection can be active only when
	 * one of the specified users is logged into an active session.  Each entry
	 * is of the form "[type]:[id]:[reserved]"; for example, "user:dcbw:blah".
	 *
	 * At this time only the "user" [type] is allowed.  Any other values are
	 * ignored and reserved for future use.  [id] is the username that this
	 * permission refers to, which may not contain the ":" character. Any
	 * [reserved] information present must be ignored and is reserved for future
	 * use.  All of [type], [id], and [reserved] must be valid UTF-8.
	 */
	/* ---ifcfg-rh---
	 * property: permissions
	 * variable: USERS(+)
	 * description: Restrict to certain users the access to this connection, and
	 *     allow the connection to be active only when at least one of the
	 *     specified users is logged into an active session.
	 * example: USERS="joe bob"
	 * ---end---
	 */
	obj_properties[PROP_PERMISSIONS] =
	    g_param_spec_boxed (NM_SETTING_CONNECTION_PERMISSIONS, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingConnection:autoconnect:
	 *
	 * Whether or not the connection should be automatically connected by
	 * NetworkManager when the resources for the connection are available.
	 * %TRUE to automatically activate the connection, %FALSE to require manual
	 * intervention to activate the connection.
	 *
	 * Note that autoconnect is not implemented for VPN profiles. See
	 * #NMSettingConnection:secondaries as an alternative to automatically
	 * connect VPN profiles.
	 **/
	/* ---ifcfg-rh---
	 * property: autoconnect
	 * variable: ONBOOT
	 * default: yes
	 * description: Whether the connection should be autoconnected (not only while booting).
	 * ---end---
	 */
	obj_properties[PROP_AUTOCONNECT] =
	    g_param_spec_boolean (NM_SETTING_CONNECTION_AUTOCONNECT, "", "",
	                          TRUE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT |
	                          NM_SETTING_PARAM_FUZZY_IGNORE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingConnection:autoconnect-priority:
	 *
	 * The autoconnect priority. If the connection is set to autoconnect,
	 * connections with higher priority will be preferred. Defaults to 0.
	 * The higher number means higher priority.
	 **/
	/* ---ifcfg-rh---
	 * property: autoconnect-priority
	 * variable: AUTOCONNECT_PRIORITY(+)
	 * values: -999 to 999
	 * default: 0
	 * description: Connection priority for automatic activation. Connections with
	 *  higher numbers are preferred when selecting profiles for automatic activation.
	 * example: AUTOCONNECT_PRIORITY=20
	 * ---end---
	 */
	obj_properties[PROP_AUTOCONNECT_PRIORITY] =
	     g_param_spec_int (NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY, "", "",
	                       NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_MIN,
	                       NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_MAX,
	                       NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_DEFAULT,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_FUZZY_IGNORE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingConnection:autoconnect-retries:
	 *
	 * The number of times a connection should be tried when autoactivating before
	 * giving up. Zero means forever, -1 means the global default (4 times if not
	 * overridden). Setting this to 1 means to try activation only once before
	 * blocking autoconnect. Note that after a timeout, NetworkManager will try
	 * to autoconnect again.
	 */
	/* ---ifcfg-rh---
	 * property: autoconnect-retries
	 * variable: AUTOCONNECT_RETRIES(+)
	 * description: The number of times a connection should be autoactivated
	 * before giving up and switching to the next one.
	 * values: -1 (use global default), 0 (forever) or a positive value
	 * example: AUTOCONNECT_RETRIES=1
	 * ---end---
	 */
	obj_properties[PROP_AUTOCONNECT_RETRIES] =
	     g_param_spec_int (NM_SETTING_CONNECTION_AUTOCONNECT_RETRIES, "", "",
	                       -1, G_MAXINT32, -1,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_FUZZY_IGNORE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingConnection:multi-connect:
	 *
	 * Specifies whether the profile can be active multiple times at a particular
	 * moment. The value is of type #NMConnectionMultiConnect.
	 *
	 * Since: 1.14
	 */
	/* ---ifcfg-rh---
	 * property: multi-connect
	 * variable: MULTI_CONNECT(+)
	 * description: whether the profile can be active on multiple devices at a given
	 *   moment. The values are numbers corresponding to #NMConnectionMultiConnect enum.
	 * example: ZONE=3
	 * ---end---
	 */
	obj_properties[PROP_MULTI_CONNECT] =
	     g_param_spec_int (NM_SETTING_CONNECTION_MULTI_CONNECT, "", "",
	                       G_MININT32, G_MAXINT32, NM_CONNECTION_MULTI_CONNECT_DEFAULT,
	                       G_PARAM_READWRITE |
	                       NM_SETTING_PARAM_FUZZY_IGNORE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingConnection:timestamp:
	 *
	 * The time, in seconds since the Unix Epoch, that the connection was last
	 * _successfully_ fully activated.
	 *
	 * NetworkManager updates the connection timestamp periodically when the
	 * connection is active to ensure that an active connection has the latest
	 * timestamp. The property is only meant for reading (changes to this
	 * property will not be preserved).
	 **/
	obj_properties[PROP_TIMESTAMP] =
	    g_param_spec_uint64 (NM_SETTING_CONNECTION_TIMESTAMP, "", "",
	                         0, G_MAXUINT64, 0,
	                         G_PARAM_READWRITE |
	                         G_PARAM_CONSTRUCT |
	                         NM_SETTING_PARAM_FUZZY_IGNORE |
	                         G_PARAM_STATIC_STRINGS);

	_properties_override_add_override (properties_override,
	                                   obj_properties[PROP_TIMESTAMP],
	                                   G_VARIANT_TYPE_UINT64,
	                                   _to_dbus_fcn_timestamp,
	                                   NULL,
	                                   NULL);

	/**
	 * NMSettingConnection:read-only:
	 *
	 * %FALSE if the connection can be modified using the provided settings
	 * service's D-Bus interface with the right privileges, or %TRUE if the
	 * connection is read-only and cannot be modified.
	 **/
	obj_properties[PROP_READ_ONLY] =
	    g_param_spec_boolean (NM_SETTING_CONNECTION_READ_ONLY, "", "",
	                          FALSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT |
	                          NM_SETTING_PARAM_FUZZY_IGNORE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingConnection:zone:
	 *
	 * The trust level of a the connection.  Free form case-insensitive string
	 * (for example "Home", "Work", "Public").  %NULL or unspecified zone means
	 * the connection will be placed in the default zone as defined by the
	 * firewall.
	 *
	 * When updating this property on a currently activated connection,
	 * the change takes effect immediately.
	 **/
	/* ---ifcfg-rh---
	 * property: zone
	 * variable: ZONE(+)
	 * description: Trust level of this connection. The string is usually used
	 *   for a firewall.
	 * example: ZONE=Work
	 * ---end---
	 */
	obj_properties[PROP_ZONE] =
	    g_param_spec_string (NM_SETTING_CONNECTION_ZONE, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_CONSTRUCT |
	                         NM_SETTING_PARAM_FUZZY_IGNORE |
	                         NM_SETTING_PARAM_REAPPLY_IMMEDIATELY |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingConnection:master:
	 *
	 * Interface name of the master device or UUID of the master connection.
	 **/
	/* ---ifcfg-rh---
	 * property: master
	 * variable: MASTER, MASTER_UUID, TEAM_MASTER, TEAM_MASTER_UUID, BRIDGE, BRIDGE_UUID
	 * description: Reference to master connection. The variable used depends on
	 *   the connection type and the value. In general, if the *_UUID variant is present,
	 *   the variant without *_UUID is ignored. NetworkManager attempts to write both
	 *   for compatibility with legacy tooling.
	 * ---end---
	 */
	obj_properties[PROP_MASTER] =
	    g_param_spec_string (NM_SETTING_CONNECTION_MASTER, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_FUZZY_IGNORE |
	                         NM_SETTING_PARAM_INFERRABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingConnection:slave-type:
	 *
	 * Setting name of the device type of this slave's master connection (eg,
	 * %NM_SETTING_BOND_SETTING_NAME), or %NULL if this connection is not a
	 * slave.
	 **/
	/* ---ifcfg-rh---
	 * property: slave-type
	 * variable: MASTER, MASTER_UUID, TEAM_MASTER, TEAM_MASTER_UUID, DEVICETYPE,
	 *   BRIDGE, BRIDGE_UUID
	 * description: Slave type doesn't map directly to a variable, but it is
	 *   recognized using different variables.  MASTER and MASTER_UUID for bonding,
	 *   TEAM_MASTER, TEAM_MASTER_UUID and DEVICETYPE for teaming, BRIDGE
	 *   and BRIDGE_UUID for bridging.
	 * ---end---
	 */
	obj_properties[PROP_SLAVE_TYPE] =
	    g_param_spec_string (NM_SETTING_CONNECTION_SLAVE_TYPE, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_FUZZY_IGNORE |
	                         NM_SETTING_PARAM_INFERRABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingConnection:autoconnect-slaves:
	 *
	 * Whether or not slaves of this connection should be automatically brought up
	 * when NetworkManager activates this connection. This only has a real effect
	 * for master connections. The properties #NMSettingConnection:autoconnect,
	 * #NMSettingConnection:autoconnect-priority and #NMSettingConnection:autoconnect-retries
	 * are unrelated to this setting.
	 * The permitted values are: 0: leave slave connections untouched,
	 * 1: activate all the slave connections with this connection, -1: default.
	 * If -1 (default) is set, global connection.autoconnect-slaves is read to
	 * determine the real value. If it is default as well, this fallbacks to 0.
	 *
	 * Since: 1.2
	 **/
	/* ---ifcfg-rh---
	 * property: autoconnect-slaves
	 * variable: AUTOCONNECT_SLAVES(+)
	 * default: missing variable means global default
	 * description: Whether slaves of this connection should be auto-connected
	 *   when this connection is activated.
	 * ---end---
	 */
	obj_properties[PROP_AUTOCONNECT_SLAVES] =
	    g_param_spec_enum (NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES, "", "",
	                       NM_TYPE_SETTING_CONNECTION_AUTOCONNECT_SLAVES,
	                       NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_DEFAULT,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_FUZZY_IGNORE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingConnection:secondaries:
	 *
	 * List of connection UUIDs that should be activated when the base
	 * connection itself is activated. Currently only VPN connections are
	 * supported.
	 **/
	/* ---ifcfg-rh---
	 * property: secondaries
	 * variable: SECONDARY_UUIDS(+)
	 * description: UUID of VPN connections that should be activated
	 *   together with this connection.
	 * ---end---
	 */
	obj_properties[PROP_SECONDARIES] =
	    g_param_spec_boxed (NM_SETTING_CONNECTION_SECONDARIES, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READWRITE |
	                        NM_SETTING_PARAM_FUZZY_IGNORE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingConnection:gateway-ping-timeout:
	 *
	 * If greater than zero, delay success of IP addressing until either the
	 * timeout is reached, or an IP gateway replies to a ping.
	 **/
	/* ---ifcfg-rh---
	 * property: gateway-ping-timeout
	 * variable: GATEWAY_PING_TIMEOUT(+)
	 * default: 0
	 * description: If greater than zero, the IP connectivity will be checked by
	 *   pinging the gateway and waiting for the specified timeout (in seconds).
	 * example: GATEWAY_PING_TIMEOUT=5
	 * ---end---
	 */
	obj_properties[PROP_GATEWAY_PING_TIMEOUT] =
	    g_param_spec_uint (NM_SETTING_CONNECTION_GATEWAY_PING_TIMEOUT, "", "",
	                       0, 600, 0,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingConnection:metered:
	 *
	 * Whether the connection is metered.
	 *
	 * When updating this property on a currently activated connection,
	 * the change takes effect immediately.
	 *
	 * Since: 1.2
	 **/
	/* ---ifcfg-rh---
	 * property: metered
	 * variable: CONNECTION_METERED(+)
	 * values: yes,no,unknown
	 * description: Whether the device is metered
	 * example: CONNECTION_METERED=yes
	 * ---end---
	 */
	obj_properties[PROP_METERED] =
	    g_param_spec_enum (NM_SETTING_CONNECTION_METERED, "", "",
	                       NM_TYPE_METERED,
	                       NM_METERED_UNKNOWN,
	                       G_PARAM_READWRITE |
	                       NM_SETTING_PARAM_REAPPLY_IMMEDIATELY |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingConnection:lldp:
	 *
	 * Whether LLDP is enabled for the connection.
	 *
	 * Since: 1.2
	 **/
	/* ---ifcfg-rh---
	 * property: lldp
	 * variable: LLDP(+)
	 * values: boolean value or 'rx'
	 * default: missing variable means global default
	 * description: whether LLDP is enabled for the connection
	 * example: LLDP=no
	 * ---end---
	 */
	obj_properties[PROP_LLDP] =
	    g_param_spec_int (NM_SETTING_CONNECTION_LLDP, "", "",
	                      G_MININT32, G_MAXINT32, NM_SETTING_CONNECTION_LLDP_DEFAULT,
	                      NM_SETTING_PARAM_FUZZY_IGNORE |
	                      G_PARAM_READWRITE |
	                      G_PARAM_CONSTRUCT |
	                      G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingConnection:auth-retries:
	 *
	 * The number of retries for the authentication. Zero means to try indefinitely; -1 means
	 * to use a global default. If the global default is not set, the authentication
	 * retries for 3 times before failing the connection.
	 *
	 * Currently this only applies to 802-1x authentication.
	 *
	 * Since: 1.10
	 **/
	/* ---ifcfg-rh---
	 * property: auth-retries
	 * variable: AUTH_RETRIES(+)
	 * default: 0
	 * description: Number of retries for authentication.
	 * ---end---
	 */
	obj_properties[PROP_AUTH_RETRIES] =
	    g_param_spec_int (NM_SETTING_CONNECTION_AUTH_RETRIES, "", "",
	                      -1, G_MAXINT32, -1,
	                      G_PARAM_READWRITE |
	                      G_PARAM_CONSTRUCT |
	                      NM_SETTING_PARAM_FUZZY_IGNORE |
	                      G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingConnection:mdns:
	 *
	 * Whether mDNS is enabled for the connection.
	 *
	 * The permitted values are: yes: register hostname and resolving
	 * for the connection, no: disable mDNS for the interface, resolve:
	 * do not register hostname but allow resolving of mDNS host names.
	 *
	 * This feature requires a plugin which supports mDNS. One such
	 * plugin is dns-systemd-resolved.
	 *
	 * Since: 1.12
	 **/
	/* ---ifcfg-rh---
	 * property: mdns
	 * variable: MDNS(+)
	 * values: yes,no,resolve
	 * default: missing variable means global default
	 * description: Whether or not mDNS is enabled for the connection
	 * example: MDNS=yes
	 * ---end---
	 */
	obj_properties[PROP_MDNS] =
	    g_param_spec_int (NM_SETTING_CONNECTION_MDNS, "", "",
	                      G_MININT32, G_MAXINT32,
	                      NM_SETTING_CONNECTION_MDNS_DEFAULT,
	                      G_PARAM_READWRITE |
	                      G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingConnection:llmnr:
	 *
	 * Whether Link-Local Multicast Name Resolution (LLMNR) is enabled
	 * for the connection. LLMNR is a protocol based on the Domain Name
	 * System (DNS) packet format that allows both IPv4 and IPv6 hosts
	 * to perform name resolution for hosts on the same local link.
	 *
	 * The permitted values are: yes: register hostname and resolving
	 * for the connection, no: disable LLMNR for the interface, resolve:
	 * do not register hostname but allow resolving of LLMNR host names.
	 *
	 * This feature requires a plugin which supports LLMNR. One such
	 * plugin is dns-systemd-resolved.
	 *
	 * Since: 1.14
	 **/
	/* ---ifcfg-rh---
	 * property: llmnr
	 * variable: LLMNR(+)
	 * values: yes,no,resolve
	 * default: missing variable means global default
	 * description: Whether or not LLMNR is enabled for the connection
	 * example: LLMNR=yes
	 * ---end---
	 */
	obj_properties[PROP_LLMNR] =
	    g_param_spec_int (NM_SETTING_CONNECTION_LLMNR, "", "",
	                      G_MININT32, G_MAXINT32,
	                      NM_SETTING_CONNECTION_LLMNR_DEFAULT,
	                      G_PARAM_READWRITE |
	                      G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingConnection:wait-device-timeout:
	 *
	 * Timeout in milliseconds to wait for device at startup.
	 * During boot, devices may take a while to be detected by the driver.
	 * This property will cause to delay NetworkManager-wait-online.service
	 * and nm-online to give the device a chance to appear.
	 *
	 * Note that this property only works together with NMSettingConnection:interface-name
	 * to identify the device that will be waited for.
	 *
	 * The value 0 means no wait time. The default value is -1, which
	 * currently has the same meaning as no wait time.
	 *
	 * Since: 1.20
	 **/
	/* ---ifcfg-rh---
	 * property: wait-device-timeout
	 * variable: DEVTIMEOUT(+)
	 * values: timeout in seconds.
	 * description: for initscripts compatibility, this variable must be
	 *   a whole integer. If necessary, NetworkManager stores also a fractional
	 *   component for the milliseconds.
	 * example: DEVTIMEOUT=5
	 * ---end---
	 */
	obj_properties[PROP_WAIT_DEVICE_TIMEOUT] =
	    g_param_spec_int (NM_SETTING_CONNECTION_WAIT_DEVICE_TIMEOUT, "", "",
	                      -1, G_MAXINT32, -1,
	                      G_PARAM_READWRITE |
	                      G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit_full (setting_class, NM_META_SETTING_TYPE_CONNECTION,
	                               NULL, properties_override);
}
