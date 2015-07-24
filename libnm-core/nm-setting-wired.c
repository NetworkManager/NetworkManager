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
 * Copyright 2007 - 2014 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#include "config.h"

#include <string.h>
#include <net/ethernet.h>
#include <glib/gi18n-lib.h>

#include "nm-setting-wired.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"
#include "nm-macros-internal.h"

/**
 * SECTION:nm-setting-wired
 * @short_description: Describes connection properties for Ethernet-based networks
 *
 * The #NMSettingWired object is a #NMSetting subclass that describes properties
 * necessary for connection to Ethernet networks.
 **/

G_DEFINE_TYPE_WITH_CODE (NMSettingWired, nm_setting_wired, NM_TYPE_SETTING,
                         _nm_register_setting (WIRED, 1))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_WIRED)

#define NM_SETTING_WIRED_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_WIRED, NMSettingWiredPrivate))

typedef struct {
	char *port;
	guint32 speed;
	char *duplex;
	gboolean auto_negotiate;
	char *device_mac_address;
	char *cloned_mac_address;
	GArray *mac_address_blacklist;
	guint32 mtu;
	char **s390_subchannels;
	char *s390_nettype;
	GHashTable *s390_options;
	NMSettingWiredWakeOnLan wol;
	char *wol_password;
} NMSettingWiredPrivate;

enum {
	PROP_0,
	PROP_PORT,
	PROP_SPEED,
	PROP_DUPLEX,
	PROP_AUTO_NEGOTIATE,
	PROP_MAC_ADDRESS,
	PROP_CLONED_MAC_ADDRESS,
	PROP_MAC_ADDRESS_BLACKLIST,
	PROP_MTU,
	PROP_S390_SUBCHANNELS,
	PROP_S390_NETTYPE,
	PROP_S390_OPTIONS,
	PROP_WAKE_ON_LAN,
	PROP_WAKE_ON_LAN_PASSWORD,

	LAST_PROP
};

static const char *valid_s390_opts[] = {
	"portno", "layer2", "portname", "protocol", "priority_queueing",
	"buffer_count", "isolation", "total", "inter", "inter_jumbo", "route4",
	"route6", "fake_broadcast", "broadcast_mode", "canonical_macaddr",
	"checksumming", "sniffer", "large_send", "ipato_enable", "ipato_invert4",
	"ipato_add4", "ipato_invert6", "ipato_add6", "vipa_add4", "vipa_add6",
	"rxip_add4", "rxip_add6", "lancmd_timeout", "ctcprot",
	NULL
};

/**
 * nm_setting_wired_new:
 *
 * Creates a new #NMSettingWired object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingWired object
 **/
NMSetting *
nm_setting_wired_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_WIRED, NULL);
}

/**
 * nm_setting_wired_get_port:
 * @setting: the #NMSettingWired
 *
 * Returns: the #NMSettingWired:port property of the setting
 **/
const char *
nm_setting_wired_get_port (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->port;
}

/**
 * nm_setting_wired_get_speed:
 * @setting: the #NMSettingWired
 *
 * Returns: the #NMSettingWired:speed property of the setting
 **/
guint32
nm_setting_wired_get_speed (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), 0);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->speed;
}

/**
 * nm_setting_wired_get_duplex:
 * @setting: the #NMSettingWired
 *
 * Returns: the #NMSettingWired:duplex property of the setting
 **/
const char *
nm_setting_wired_get_duplex (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->duplex;
}

/**
 * nm_setting_wired_get_auto_negotiate:
 * @setting: the #NMSettingWired
 *
 * Returns: the #NMSettingWired:auto-negotiate property of the setting
 **/
gboolean
nm_setting_wired_get_auto_negotiate (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), FALSE);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->auto_negotiate;
}

/**
 * nm_setting_wired_get_mac_address:
 * @setting: the #NMSettingWired
 *
 * Returns: the #NMSettingWired:mac-address property of the setting
 **/
const char *
nm_setting_wired_get_mac_address (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->device_mac_address;
}

/**
 * nm_setting_wired_get_cloned_mac_address:
 * @setting: the #NMSettingWired
 *
 * Returns: the #NMSettingWired:cloned-mac-address property of the setting
 **/
const char *
nm_setting_wired_get_cloned_mac_address (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->cloned_mac_address;
}

/**
 * nm_setting_wired_get_mac_address_blacklist:
 * @setting: the #NMSettingWired
 *
 * Returns: the #NMSettingWired:mac-address-blacklist property of the setting
 **/
const char * const *
nm_setting_wired_get_mac_address_blacklist (NMSettingWired *setting)
{
	NMSettingWiredPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	priv = NM_SETTING_WIRED_GET_PRIVATE (setting);
	return (const char * const *) priv->mac_address_blacklist->data;
}

/**
 * nm_setting_wired_get_num_mac_blacklist_items:
 * @setting: the #NMSettingWired
 *
 * Returns: the number of blacklisted MAC addresses
 **/
guint32
nm_setting_wired_get_num_mac_blacklist_items (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), 0);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->mac_address_blacklist->len;
}

/**
 * nm_setting_wired_get_mac_blacklist_item:
 * @setting: the #NMSettingWired
 * @idx: the zero-based index of the MAC address entry
 *
 * Returns: the blacklisted MAC address string (hex-digits-and-colons notation)
 * at index @idx
 **/
const char *
nm_setting_wired_get_mac_blacklist_item (NMSettingWired *setting, guint32 idx)
{
	NMSettingWiredPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	priv = NM_SETTING_WIRED_GET_PRIVATE (setting);
	g_return_val_if_fail (idx <= priv->mac_address_blacklist->len, NULL);

	return g_array_index (priv->mac_address_blacklist, const char *, idx);
}

/**
 * nm_setting_wired_add_mac_blacklist_item:
 * @setting: the #NMSettingWired
 * @mac: the MAC address string (hex-digits-and-colons notation) to blacklist
 *
 * Adds a new MAC address to the #NMSettingWired:mac-address-blacklist property.
 *
 * Returns: %TRUE if the MAC address was added; %FALSE if the MAC address
 * is invalid or was already present
 **/
gboolean
nm_setting_wired_add_mac_blacklist_item (NMSettingWired *setting, const char *mac)
{
	NMSettingWiredPrivate *priv;
	const char *candidate;
	int i;

	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), FALSE);
	g_return_val_if_fail (mac != NULL, FALSE);

	if (!nm_utils_hwaddr_valid (mac, ETH_ALEN))
		return FALSE;

	priv = NM_SETTING_WIRED_GET_PRIVATE (setting);
	for (i = 0; i < priv->mac_address_blacklist->len; i++) {
		candidate = g_array_index (priv->mac_address_blacklist, char *, i);
		if (nm_utils_hwaddr_matches (mac, -1, candidate, -1))
			return FALSE;
	}

	mac = nm_utils_hwaddr_canonical (mac, ETH_ALEN);
	g_array_append_val (priv->mac_address_blacklist, mac);
	g_object_notify (G_OBJECT (setting), NM_SETTING_WIRED_MAC_ADDRESS_BLACKLIST);
	return TRUE;
}

/**
 * nm_setting_wired_remove_mac_blacklist_item:
 * @setting: the #NMSettingWired
 * @idx: index number of the MAC address
 *
 * Removes the MAC address at index @idx from the blacklist.
 **/
void
nm_setting_wired_remove_mac_blacklist_item (NMSettingWired *setting, guint32 idx)
{
	NMSettingWiredPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_WIRED (setting));

	priv = NM_SETTING_WIRED_GET_PRIVATE (setting);
	g_return_if_fail (idx < priv->mac_address_blacklist->len);

	g_array_remove_index (priv->mac_address_blacklist, idx);
	g_object_notify (G_OBJECT (setting), NM_SETTING_WIRED_MAC_ADDRESS_BLACKLIST);
}

/**
 * nm_setting_wired_remove_mac_blacklist_item_by_value:
 * @setting: the #NMSettingWired
 * @mac: the MAC address string (hex-digits-and-colons notation) to remove from
 * the blacklist
 *
 * Removes the MAC address @mac from the blacklist.
 *
 * Returns: %TRUE if the MAC address was found and removed; %FALSE if it was not.
 **/
gboolean
nm_setting_wired_remove_mac_blacklist_item_by_value (NMSettingWired *setting, const char *mac)
{
	NMSettingWiredPrivate *priv;
	const char *candidate;
	int i;

	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), FALSE);
	g_return_val_if_fail (mac != NULL, FALSE);

	priv = NM_SETTING_WIRED_GET_PRIVATE (setting);
	for (i = 0; i < priv->mac_address_blacklist->len; i++) {
		candidate = g_array_index (priv->mac_address_blacklist, char *, i);
		if (!nm_utils_hwaddr_matches (mac, -1, candidate, -1)) {
			g_array_remove_index (priv->mac_address_blacklist, i);
			g_object_notify (G_OBJECT (setting), NM_SETTING_WIRED_MAC_ADDRESS_BLACKLIST);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_wired_clear_mac_blacklist_items:
 * @setting: the #NMSettingWired
 *
 * Removes all blacklisted MAC addresses.
 **/
void
nm_setting_wired_clear_mac_blacklist_items (NMSettingWired *setting)
{
	g_return_if_fail (NM_IS_SETTING_WIRED (setting));

	g_array_set_size (NM_SETTING_WIRED_GET_PRIVATE (setting)->mac_address_blacklist, 0);
	g_object_notify (G_OBJECT (setting), NM_SETTING_WIRED_MAC_ADDRESS_BLACKLIST);
}

/**
 * nm_setting_wired_get_mtu:
 * @setting: the #NMSettingWired
 *
 * Returns: the #NMSettingWired:mtu property of the setting
 **/
guint32
nm_setting_wired_get_mtu (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), 0);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->mtu;
}

/**
 * nm_setting_wired_get_s390_subchannels:
 * @setting: the #NMSettingWired
 *
 * Return the list of s390 subchannels that identify the device that this
 * connection is applicable to.  The connection should only be used in
 * conjunction with that device.
 *
 * Returns: (transfer none) (element-type utf8): array of strings, each specifying
 *   one subchannel the s390 device uses to communicate to the host.
 **/
const char * const *
nm_setting_wired_get_s390_subchannels (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	return (const char * const *) NM_SETTING_WIRED_GET_PRIVATE (setting)->s390_subchannels;
}

/**
 * nm_setting_wired_get_s390_nettype:
 * @setting: the #NMSettingWired
 *
 * Returns the s390 device type this connection should apply to.  Will be one
 * of 'qeth', 'lcs', or 'ctc'.
 *
 * Returns: the s390 device type
 **/
const char *
nm_setting_wired_get_s390_nettype (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->s390_nettype;
}

/**
 * nm_setting_wired_get_num_s390_options:
 * @setting: the #NMSettingWired
 *
 * Returns the number of s390-specific options that should be set for this
 * device when it is activated.  This can be used to retrieve each s390
 * option individually using nm_setting_wired_get_s390_option().
 *
 * Returns: the number of s390-specific device options
 **/
guint32
nm_setting_wired_get_num_s390_options (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), 0);

	return g_hash_table_size (NM_SETTING_WIRED_GET_PRIVATE (setting)->s390_options);
}

/**
 * nm_setting_wired_get_s390_option:
 * @setting: the #NMSettingWired
 * @idx: index of the desired option, from 0 to
 * nm_setting_wired_get_num_s390_options() - 1
 * @out_key: (out) (transfer none): on return, the key name of the s390 specific
 *   option; this value is owned by the setting and should not be modified
 * @out_value: (out) (transfer none): on return, the value of the key of the
 *   s390 specific option; this value is owned by the setting and should not be
 *   modified
 *
 * Given an index, return the value of the s390 option at that index.  indexes
 * are *not* guaranteed to be static across modifications to options done by
 * nm_setting_wired_add_s390_option() and nm_setting_wired_remove_s390_option(),
 * and should not be used to refer to options except for short periods of time
 * such as during option iteration.
 *
 * Returns: %TRUE on success if the index was valid and an option was found,
 * %FALSE if the index was invalid (ie, greater than the number of options
 * currently held by the setting)
 **/
gboolean
nm_setting_wired_get_s390_option (NMSettingWired *setting,
                                  guint32 idx,
                                  const char **out_key,
                                  const char **out_value)
{
	const char *_key, *_value;
	GHashTableIter iter;
	guint i = 0;

	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), FALSE);

	g_hash_table_iter_init (&iter, NM_SETTING_WIRED_GET_PRIVATE (setting)->s390_options);
	while (g_hash_table_iter_next (&iter, (gpointer) &_key, (gpointer) &_value)) {
		if (i == idx) {
			if (out_key)
				*out_key = _key;
			if (out_value)
				*out_value = _value;
			return TRUE;
		}
		i++;
	}
	g_return_val_if_reached (FALSE);
}

/**
 * nm_setting_wired_get_s390_option_by_key:
 * @setting: the #NMSettingWired
 * @key: the key for which to retrieve the value
 *
 * Returns the value associated with the s390-specific option specified by
 * @key, if it exists.
 *
 * Returns: the value, or %NULL if the key/value pair was never added to the
 * setting; the value is owned by the setting and must not be modified
 **/
const char *
nm_setting_wired_get_s390_option_by_key (NMSettingWired *setting,
                                         const char *key)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);
	g_return_val_if_fail (key != NULL, NULL);
	g_return_val_if_fail (strlen (key), NULL);

	return g_hash_table_lookup (NM_SETTING_WIRED_GET_PRIVATE (setting)->s390_options, key);
}

/**
 * nm_setting_wired_add_s390_option:
 * @setting: the #NMSettingWired
 * @key: key name for the option
 * @value: value for the option
 *
 * Add an option to the table.  The option is compared to an internal list
 * of allowed options.  Key names may contain only alphanumeric characters
 * (ie [a-zA-Z0-9]).  Adding a new key replaces any existing key/value pair that
 * may already exist.
 *
 * Returns: %TRUE if the option was valid and was added to the internal option
 * list, %FALSE if it was not.
 **/
gboolean
nm_setting_wired_add_s390_option (NMSettingWired *setting,
                                  const char *key,
                                  const char *value)
{
	size_t value_len;

	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), FALSE);
	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (strlen (key), FALSE);
	g_return_val_if_fail (_nm_utils_string_in_list (key, valid_s390_opts), FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	value_len = strlen (value);
	g_return_val_if_fail (value_len > 0 && value_len < 200, FALSE);

	g_hash_table_insert (NM_SETTING_WIRED_GET_PRIVATE (setting)->s390_options,
	                     g_strdup (key),
	                     g_strdup (value));
	g_object_notify (G_OBJECT (setting), NM_SETTING_WIRED_S390_OPTIONS);
	return TRUE;
}

/**
 * nm_setting_wired_remove_s390_option:
 * @setting: the #NMSettingWired
 * @key: key name for the option to remove
 *
 * Remove the s390-specific option referenced by @key from the internal option
 * list.
 *
 * Returns: %TRUE if the option was found and removed from the internal option
 * list, %FALSE if it was not.
 **/
gboolean
nm_setting_wired_remove_s390_option (NMSettingWired *setting,
                                     const char *key)
{
	gboolean found;

	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), FALSE);
	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (strlen (key), FALSE);

	found = g_hash_table_remove (NM_SETTING_WIRED_GET_PRIVATE (setting)->s390_options, key);
	if (found)
		g_object_notify (G_OBJECT (setting), NM_SETTING_WIRED_S390_OPTIONS);
	return found;
}

/**
 * nm_setting_wired_get_valid_s390_options:
 * @setting: the #NMSettingWired
 *
 * Returns a list of valid s390 options.
 *
 * Returns: (transfer none): a %NULL-terminated array of strings of valid s390 options.
 **/
const char **
nm_setting_wired_get_valid_s390_options (NMSettingWired *setting)
{
	return valid_s390_opts;
}

/**
 * nm_setting_wired_get_wake_on_lan:
 * @setting: the #NMSettingWired
 *
 * Returns the Wake-on-LAN options enabled for the connection
 *
 * Returns: the Wake-on-LAN options
 *
 * Since: 1.2
 */
NMSettingWiredWakeOnLan
nm_setting_wired_get_wake_on_lan (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NM_SETTING_WIRED_WAKE_ON_LAN_NONE);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->wol;
}

/**
 * nm_setting_wired_get_wake_on_lan_password:
 * @setting: the #NMSettingWired
 *
 * Returns the Wake-on-LAN password. This only applies to
 * %NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC.
 *
 * Returns: the Wake-on-LAN setting password, or %NULL if there is no password.
 *
 * Since: 1.2
 */
const char *
nm_setting_wired_get_wake_on_lan_password (NMSettingWired *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_WIRED (setting), NULL);

	return NM_SETTING_WIRED_GET_PRIVATE (setting)->wol_password;
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingWiredPrivate *priv = NM_SETTING_WIRED_GET_PRIVATE (setting);
	const char *valid_ports[] = { "tp", "aui", "bnc", "mii", NULL };
	const char *valid_duplex[] = { "half", "full", NULL };
	const char *valid_nettype[] = { "qeth", "lcs", "ctc", NULL };
	GHashTableIter iter;
	const char *key, *value;
	int i;

	if (priv->port && !_nm_utils_string_in_list (priv->port, valid_ports)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid Ethernet port value"),
		             priv->port);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_PORT);
		return FALSE;
	}

	if (priv->duplex && !_nm_utils_string_in_list (priv->duplex, valid_duplex)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid duplex value"),
		             priv->duplex);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_DUPLEX);
		return FALSE;
	}

	if (priv->device_mac_address && !nm_utils_hwaddr_valid (priv->device_mac_address, ETH_ALEN)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("is not a valid MAC address"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_MAC_ADDRESS);
		return FALSE;
	}

	for (i = 0; i < priv->mac_address_blacklist->len; i++) {
		const char *mac = g_array_index (priv->mac_address_blacklist, const char *, i);

		if (!nm_utils_hwaddr_valid (mac, ETH_ALEN)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("'%s' is not a valid MAC address"),
			             mac);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_MAC_ADDRESS_BLACKLIST);
			return FALSE;
		}
	}

	if (priv->s390_subchannels) {
		int len = g_strv_length (priv->s390_subchannels);

		if (len != 2 && len != 3) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("property is invalid"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_S390_SUBCHANNELS);
			return FALSE;
		}
	}

	if (priv->s390_nettype && !_nm_utils_string_in_list (priv->s390_nettype, valid_nettype)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_S390_NETTYPE);
		return FALSE;
	}

	g_hash_table_iter_init (&iter, priv->s390_options);
	while (g_hash_table_iter_next (&iter, (gpointer) &key, (gpointer) &value)) {
		if (   !_nm_utils_string_in_list (key, valid_s390_opts)
		    || !strlen (value)
		    || (strlen (value) > 200)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("invalid '%s' or its value '%s'"),
			             key, value);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_S390_OPTIONS);
			return FALSE;
		}
	}

	if (priv->cloned_mac_address && !nm_utils_hwaddr_valid (priv->cloned_mac_address, ETH_ALEN)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("is not a valid MAC address"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_CLONED_MAC_ADDRESS);
		return FALSE;
	}

	if (   NM_FLAGS_HAS (priv->wol, NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT)
	    && NM_FLAGS_ANY (priv->wol, NM_SETTING_WIRED_WAKE_ON_LAN_ALL)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("Wake-on-LAN mode 'default' is incompatible with other flags"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_WAKE_ON_LAN);
		return FALSE;
	}

	if (priv->wol_password && !NM_FLAGS_HAS (priv->wol, NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("Wake-on-LAN password can only be used with magic packet mode"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_WAKE_ON_LAN_PASSWORD);
		return FALSE;
	}

	if (priv->wol_password && !nm_utils_hwaddr_valid (priv->wol_password, ETH_ALEN)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("is not a valid MAC address"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_WAKE_ON_LAN_PASSWORD);
		return FALSE;
	}

	return TRUE;
}

static void
clear_blacklist_item (char **item_p)
{
	g_free (*item_p);
}

static void
nm_setting_wired_init (NMSettingWired *setting)
{
	NMSettingWiredPrivate *priv = NM_SETTING_WIRED_GET_PRIVATE (setting);

	priv->s390_options = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	/* We use GArray rather than GPtrArray so it will automatically be NULL-terminated */
	priv->mac_address_blacklist = g_array_new (TRUE, FALSE, sizeof (char *));
	g_array_set_clear_func (priv->mac_address_blacklist, (GDestroyNotify) clear_blacklist_item);
}

static void
finalize (GObject *object)
{
	NMSettingWiredPrivate *priv = NM_SETTING_WIRED_GET_PRIVATE (object);

	g_free (priv->port);
	g_free (priv->duplex);
	g_free (priv->s390_nettype);

	g_hash_table_destroy (priv->s390_options);

	g_free (priv->device_mac_address);
	g_free (priv->cloned_mac_address);
	g_array_unref (priv->mac_address_blacklist);

	if (priv->s390_subchannels)
		g_strfreev (priv->s390_subchannels);

	g_free (priv->wol_password);

	G_OBJECT_CLASS (nm_setting_wired_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingWiredPrivate *priv = NM_SETTING_WIRED_GET_PRIVATE (object);
	const char * const *blacklist;
	const char *mac;
	int i;

	switch (prop_id) {
	case PROP_PORT:
		g_free (priv->port);
		priv->port = g_value_dup_string (value);
		break;
	case PROP_SPEED:
		priv->speed = g_value_get_uint (value);
		break;
	case PROP_DUPLEX:
		g_free (priv->duplex);
		priv->duplex = g_value_dup_string (value);
		break;
	case PROP_AUTO_NEGOTIATE:
		priv->auto_negotiate = g_value_get_boolean (value);
		break;
	case PROP_MAC_ADDRESS:
		g_free (priv->device_mac_address);
		priv->device_mac_address = _nm_utils_hwaddr_canonical_or_invalid (g_value_get_string (value),
		                                                                  ETH_ALEN);
		break;
	case PROP_CLONED_MAC_ADDRESS:
		g_free (priv->cloned_mac_address);
		priv->cloned_mac_address = _nm_utils_hwaddr_canonical_or_invalid (g_value_get_string (value),
		                                                                  ETH_ALEN);
		break;
	case PROP_MAC_ADDRESS_BLACKLIST:
		blacklist = g_value_get_boxed (value);
		g_array_set_size (priv->mac_address_blacklist, 0);
		if (blacklist && *blacklist) {
			for (i = 0; blacklist[i]; i++) {
				mac = _nm_utils_hwaddr_canonical_or_invalid (blacklist[i], ETH_ALEN);
				g_array_append_val (priv->mac_address_blacklist, mac);
			}
		}
		break;
	case PROP_MTU:
		priv->mtu = g_value_get_uint (value);
		break;
	case PROP_S390_SUBCHANNELS:
		if (priv->s390_subchannels)
			g_strfreev (priv->s390_subchannels);
		priv->s390_subchannels = g_value_dup_boxed (value);
		break;
	case PROP_S390_NETTYPE:
		g_free (priv->s390_nettype);
		priv->s390_nettype = g_value_dup_string (value);
		break;
	case PROP_S390_OPTIONS:
		g_hash_table_unref (priv->s390_options);
		priv->s390_options = _nm_utils_copy_strdict (g_value_get_boxed (value));
		break;
	case PROP_WAKE_ON_LAN:
		priv->wol = g_value_get_uint (value);
		break;
	case PROP_WAKE_ON_LAN_PASSWORD:
		g_free (priv->wol_password);
		priv->wol_password = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingWired *setting = NM_SETTING_WIRED (object);
	NMSettingWiredPrivate *priv = NM_SETTING_WIRED_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_PORT:
		g_value_set_string (value, nm_setting_wired_get_port (setting));
		break;
	case PROP_SPEED:
		g_value_set_uint (value, nm_setting_wired_get_speed (setting));
		break;
	case PROP_DUPLEX:
		g_value_set_string (value, nm_setting_wired_get_duplex (setting));
		break;
	case PROP_AUTO_NEGOTIATE:
		g_value_set_boolean (value, nm_setting_wired_get_auto_negotiate (setting));
		break;
	case PROP_MAC_ADDRESS:
		g_value_set_string (value, nm_setting_wired_get_mac_address (setting));
		break;
	case PROP_CLONED_MAC_ADDRESS:
		g_value_set_string (value, nm_setting_wired_get_cloned_mac_address (setting));
		break;
	case PROP_MAC_ADDRESS_BLACKLIST:
		g_value_set_boxed (value, (char **) priv->mac_address_blacklist->data);
		break;
	case PROP_MTU:
		g_value_set_uint (value, nm_setting_wired_get_mtu (setting));
		break;
	case PROP_S390_SUBCHANNELS:
		g_value_set_boxed (value, priv->s390_subchannels);
		break;
	case PROP_S390_NETTYPE:
		g_value_set_string (value, nm_setting_wired_get_s390_nettype (setting));
		break;
	case PROP_S390_OPTIONS:
		g_value_take_boxed (value, _nm_utils_copy_strdict (priv->s390_options));
		break;
	case PROP_WAKE_ON_LAN:
		g_value_set_uint (value, priv->wol);
		break;
	case PROP_WAKE_ON_LAN_PASSWORD:
		g_value_set_string (value, priv->wol_password);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_wired_class_init (NMSettingWiredClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingWiredPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;

	/* Properties */
	/**
	 * NMSettingWired:port:
	 *
	 * Specific port type to use if multiple the device supports multiple
	 * attachment methods.  One of "tp" (Twisted Pair), "aui" (Attachment Unit
	 * Interface), "bnc" (Thin Ethernet) or "mii" (Media Independent Interface.
	 * If the device supports only one port type, this setting is ignored.
	 **/
	/* ---ifcfg-rh---
	 * property: port
	 * variable: (none)
	 * description: The property is not saved by the plugin.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_PORT,
		 g_param_spec_string (NM_SETTING_WIRED_PORT, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWired:speed:
	 *
	 * If non-zero, request that the device use only the specified speed.  In
	 * Mbit/s, ie 100 == 100Mbit/s.
	 **/
	/* ---ifcfg-rh---
	 * property: speed
	 * variable: (none)
	 * description: The property is not saved by the plugin.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_SPEED,
		 g_param_spec_uint (NM_SETTING_WIRED_SPEED, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWired:duplex:
	 *
	 * If specified, request that the device only use the specified duplex mode.
	 * Either "half" or "full".
	 **/
	/* ---ifcfg-rh---
	 * property: duplex
	 * variable: (none)
	 * description: The property is not saved by the plugin.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_DUPLEX,
		 g_param_spec_string (NM_SETTING_WIRED_DUPLEX, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWired:auto-negotiate:
	 *
	 * If %TRUE, allow auto-negotiation of port speed and duplex mode.  If
	 * %FALSE, do not allow auto-negotiation, in which case the "speed" and
	 * "duplex" properties should be set.
	 **/
	/* ---ifcfg-rh---
	 * property: auto-negotiate
	 * variable: (none)
	 * description: The property is not saved by the plugin.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_AUTO_NEGOTIATE,
		 g_param_spec_boolean (NM_SETTING_WIRED_AUTO_NEGOTIATE, "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWired:mac-address:
	 *
	 * If specified, this connection will only apply to the Ethernet device
	 * whose permanent MAC address matches. This property does not change the
	 * MAC address of the device (i.e. MAC spoofing).
	 **/
	/* ---keyfile---
	 * property: mac-address
	 * format: ususal hex-digits-and-colons notation
	 * description: MAC address in traditional hex-digits-and-colons notation
	 *   (e.g. 00:22:68:12:79:A2), or semicolon separated list of 6 bytes (obsolete)
	 *   (e.g. 0;34;104;18;121;162)
	 * ---end---
	 * ---ifcfg-rh---
	 * property: mac-address
	 * variable: HWADDR
	 * description: Hardware address of the device in traditional hex-digits-and-colons
	 *    notation (e.g. 00:22:68:14:5A:05).
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_MAC_ADDRESS,
		 g_param_spec_string (NM_SETTING_WIRED_MAC_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_INFERRABLE |
		                      G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class, NM_SETTING_WIRED_MAC_ADDRESS,
	                                      G_VARIANT_TYPE_BYTESTRING,
	                                      _nm_utils_hwaddr_to_dbus,
	                                      _nm_utils_hwaddr_from_dbus);

	/**
	 * NMSettingWired:cloned-mac-address:
	 *
	 * If specified, request that the device use this MAC address instead of its
	 * permanent MAC address.  This is known as MAC cloning or spoofing.
	 **/
	/* ---keyfile---
	 * property: cloned-mac-address
	 * format: ususal hex-digits-and-colons notation
	 * description: Cloned MAC address in traditional hex-digits-and-colons notation
	 *   (e.g. 00:22:68:12:79:B2), or semicolon separated list of 6 bytes (obsolete)
	 *   (e.g. 0;34;104;18;121;178).
	 * ---end---
	 * ---ifcfg-rh---
	 * property: cloned-mac-address
	 * variable: MACADDR
	 * description: Cloned (spoofed) MAC address in traditional hex-digits-and-colons
	 *    notation (e.g. 00:22:68:14:5A:99).
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_CLONED_MAC_ADDRESS,
		 g_param_spec_string (NM_SETTING_WIRED_CLONED_MAC_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_INFERRABLE |
		                      G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class, NM_SETTING_WIRED_CLONED_MAC_ADDRESS,
	                                      G_VARIANT_TYPE_BYTESTRING,
	                                      _nm_utils_hwaddr_to_dbus,
	                                      _nm_utils_hwaddr_from_dbus);

	/**
	 * NMSettingWired:mac-address-blacklist:
	 *
	 * If specified, this connection will never apply to the Ethernet device
	 * whose permanent MAC address matches an address in the list.  Each MAC
	 * address is in the standard hex-digits-and-colons notation
	 * (00:11:22:33:44:55).
	 **/
	/* ---keyfile---
	 * property: mac-address-blacklist
	 * format: list of MACs (separated with semicolons)
	 * description: MAC address blacklist.
	 * example: mac-address-blacklist= 00:22:68:12:79:A6;00:22:68:12:79:78
	 * ---end---
	 * ---ifcfg-rh---
	 * property: mac-address-blacklist
	 * variable: HWADDR_BLACKLIST(+)
	 * description: It denies usage of the connection for any device whose address
	 *   is listed.
	 * example: HWADDR_BLACKLIST="00:22:68:11:69:08 00:11:22:11:44:55"
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_MAC_ADDRESS_BLACKLIST,
		 g_param_spec_boxed (NM_SETTING_WIRED_MAC_ADDRESS_BLACKLIST, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READWRITE |
		                     NM_SETTING_PARAM_FUZZY_IGNORE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWired:mtu:
	 *
	 * If non-zero, only transmit packets of the specified size or smaller,
	 * breaking larger packets up into multiple Ethernet frames.
	 **/
	/* ---ifcfg-rh---
	 * property: mtu
	 * variable: MTU
	 * description: MTU of the interface.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_MTU,
		 g_param_spec_uint (NM_SETTING_WIRED_MTU, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    NM_SETTING_PARAM_FUZZY_IGNORE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWired:s390-subchannels:
	 *
	 * Identifies specific subchannels that this network device uses for
	 * communication with z/VM or s390 host.  Like the
	 * #NMSettingWired:mac-address property for non-z/VM devices, this property
	 * can be used to ensure this connection only applies to the network device
	 * that uses these subchannels.  The list should contain exactly 3 strings,
	 * and each string may only be composed of hexadecimal characters and the
	 * period (.) character.
	 **/
	/* ---ifcfg-rh---
	 * property: s390-subchannels
	 * variable: SUBCHANNELS
	 * description: Subchannels for IBM S390 hosts.
	 * example: SUBCHANNELS=0.0.b00a,0.0.b00b,0.0.b00c
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_S390_SUBCHANNELS,
		 g_param_spec_boxed (NM_SETTING_WIRED_S390_SUBCHANNELS, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READWRITE |
		                     NM_SETTING_PARAM_INFERRABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWired:s390-nettype:
	 *
	 * s390 network device type; one of "qeth", "lcs", or "ctc", representing
	 * the different types of virtual network devices available on s390 systems.
	 **/
	/* ---ifcfg-rh---
	 * property: s390-nettype
	 * variable: NETTYPE
	 * values: "qeth", "lcs" or "ctc"
	 * description: Network type of the S390 host.
	 * example: NETTYPE=qeth
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_S390_NETTYPE,
		 g_param_spec_string (NM_SETTING_WIRED_S390_NETTYPE, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_INFERRABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWired:s390-options:
	 *
	 * Dictionary of key/value pairs of s390-specific device options.  Both keys
	 * and values must be strings.  Allowed keys include "portno", "layer2",
	 * "portname", "protocol", among others.  Key names must contain only
	 * alphanumeric characters (ie, [a-zA-Z0-9]).
	 *
	 * Type: GHashTable(utf8,utf8)
	 **/
	/* ---ifcfg-rh---
	 * property: s390-options
	 * variable: OPTIONS and PORTNAME, CTCPROTO,
	 * description: S390 device options. All options go to OPTIONS, except for
	 *   "portname" and "ctcprot" that have their own variables.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_S390_OPTIONS,
		 g_param_spec_boxed (NM_SETTING_WIRED_S390_OPTIONS, "", "",
		                     G_TYPE_HASH_TABLE,
		                     G_PARAM_READWRITE |
		                     NM_SETTING_PARAM_INFERRABLE |
		                     G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class, NM_SETTING_WIRED_S390_OPTIONS,
	                                      G_VARIANT_TYPE ("a{ss}"),
	                                      _nm_utils_strdict_to_dbus,
	                                      _nm_utils_strdict_from_dbus);

	/**
	 * NMSettingWired:wake-on-lan:
	 *
	 * The #NMSettingWiredWakeOnLan options to enable. Not all devices support all options.
	 * May be any combination of %NM_SETTING_WIRED_WAKE_ON_LAN_PHY,
	 * %NM_SETTING_WIRED_WAKE_ON_LAN_UNICAST, %NM_SETTING_WIRED_WAKE_ON_LAN_MULTICAST,
	 * %NM_SETTING_WIRED_WAKE_ON_LAN_BROADCAST, %NM_SETTING_WIRED_WAKE_ON_LAN_ARP,
	 * %NM_SETTING_WIRED_WAKE_ON_LAN_MAGIC.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_WAKE_ON_LAN,
		 g_param_spec_uint (NM_SETTING_WIRED_WAKE_ON_LAN, "", "",
		                    0, G_MAXUINT32, NM_SETTING_WIRED_WAKE_ON_LAN_DEFAULT,
		                    G_PARAM_CONSTRUCT |
		                    G_PARAM_READWRITE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingWired:wake-on-lan-password:
	 *
	 * If specified, the password used with magic-packet-based
	 * Wake-on-LAN, represented as an Ethernet MAC address.  If %NULL,
	 * no password will be required.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_WAKE_ON_LAN_PASSWORD,
		 g_param_spec_string (NM_SETTING_WIRED_WAKE_ON_LAN_PASSWORD, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));
}
