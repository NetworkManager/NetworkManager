/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <glib.h>
#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <gconf/gconf-client.h>
#include <gnome-keyring.h>
#include <iwlib.h>

#include "applet.h"
#include "applet-compat.h"
#include "gconf-helpers.h"
#include "nm-utils.h"
#include "cipher.h"
#include "cipher-wep-hex.h"
#include "cipher-wep-ascii.h"
#include "cipher-wep-passphrase.h"


/*
 * Authentication modes
 */
typedef enum NMDeviceAuthMethod
{
	NM_DEVICE_AUTH_METHOD_UNKNOWN = 0,
	NM_DEVICE_AUTH_METHOD_NONE,
	NM_DEVICE_AUTH_METHOD_OPEN_SYSTEM,
	NM_DEVICE_AUTH_METHOD_SHARED_KEY
} NMDeviceAuthMethod;

/*
 * Encryption key types
 */
typedef enum NMEncKeyType
{
	NM_ENC_TYPE_UNKNOWN = 0,
	NM_ENC_TYPE_NONE,
	NM_ENC_TYPE_HEX_KEY,
	NM_ENC_TYPE_ASCII_KEY,
	NM_ENC_TYPE_128_BIT_PASSPHRASE
	/* FIXME: WPA and 802.1x support */
} NMEncKeyType;

#define WEP_PREFIX	"wep_"


static void
unset_nm_gconf_key (GConfClient *client,
                    const char *escaped_network,
                    const char *key_name)
{
	char *	key;

	g_return_if_fail (client != NULL);
	g_return_if_fail (escaped_network != NULL);
	g_return_if_fail (key_name != NULL);

	key = g_strdup_printf ("%s/%s/%s",
                            GCONF_PATH_WIRELESS_NETWORKS,
                            escaped_network,
                            key_name);
	gconf_client_unset (client, key, NULL);
	g_free (key);
}

static void
set_entry_cipher (GConfClient *client,
                  const char *escaped_network,
                  int we_cipher)
{
	char *key;

	g_return_if_fail (client != NULL);
	g_return_if_fail (escaped_network != NULL);

	key = g_strdup_printf ("%s/%s/we_cipher", GCONF_PATH_WIRELESS_NETWORKS, escaped_network);
	gconf_client_set_int (client, key, we_cipher, NULL);
	g_free (key);
}

static void
convert_entry_auth_algorithm (GConfClient *client,
                              const char *escaped_network)
{
	char *			key;
	int				int_auth_method;
	NMDeviceAuthMethod	auth_method = NM_DEVICE_AUTH_METHOD_OPEN_SYSTEM;
	int				we_auth_alg = IW_AUTH_ALG_OPEN_SYSTEM;

	g_return_if_fail (client != NULL);
	g_return_if_fail (escaped_network != NULL);

	if (nm_gconf_get_int_helper (client,
							GCONF_PATH_WIRELESS_NETWORKS,
							"auth_method",
							escaped_network,
							&int_auth_method))
		auth_method = (NMDeviceAuthMethod) int_auth_method;

	if (auth_method == NM_DEVICE_AUTH_METHOD_SHARED_KEY)
		we_auth_alg = IW_AUTH_ALG_SHARED_KEY;

	key = g_strdup_printf ("%s/%s/%sauth_algorithm",
					   GCONF_PATH_WIRELESS_NETWORKS,
					   escaped_network,
					   WEP_PREFIX);
	gconf_client_set_int (client, key, we_auth_alg, NULL);
	g_free (key);

	/* Remove the old auth_method key */
	unset_nm_gconf_key (client, escaped_network, "auth_method");
}

static char *
get_key_from_keyring (const char *essid, int *item_id)
{
	GnomeKeyringResult	ret;
	GList *			found_list = NULL;
	GnomeKeyringFound *	found;
	char *			key;

	g_return_val_if_fail (essid != NULL, NULL);

	ret = gnome_keyring_find_itemsv_sync (GNOME_KEYRING_ITEM_GENERIC_SECRET,
					&found_list,
					"essid",
					GNOME_KEYRING_ATTRIBUTE_TYPE_STRING,
					essid,
					NULL);
	if (ret != GNOME_KEYRING_RESULT_OK)
		return NULL;

	found = (GnomeKeyringFound *) found_list->data;
	key = g_strdup (found->secret);
	if (item_id)
		*item_id = found->item_id;
	gnome_keyring_found_list_free (found_list);

	return key;
}

static void
set_key_in_keyring (const char *essid,
                    const char *key)
{
	GnomeKeyringAttributeList *	attributes;
	GnomeKeyringAttribute		attr;
	GnomeKeyringResult			ret;
	const char *				name;
	guint32					item_id;

	name = g_strdup_printf (_("Passphrase for wireless network %s"), essid);

	attributes = gnome_keyring_attribute_list_new ();
	attr.name = g_strdup ("essid");
	attr.type = GNOME_KEYRING_ATTRIBUTE_TYPE_STRING;
	attr.value.string = g_strdup (essid);
	g_array_append_val (attributes, attr);

	ret = gnome_keyring_item_create_sync (NULL,
								   GNOME_KEYRING_ITEM_GENERIC_SECRET,
								   name,
								   attributes,
								   key,
								   TRUE,
								   &item_id);
	if (ret != GNOME_KEYRING_RESULT_OK)
	{
		nm_warning ("%s:%d (%s): Error converting encryption key for '%s'.  Ret=%d",
			__FILE__, __LINE__, __func__, essid, ret);
	}

	gnome_keyring_attribute_list_free (attributes);
}

static void
convert_no_encryption (GConfClient *client,
                       const char *escaped_network)
{
	g_return_if_fail (client != NULL);
	g_return_if_fail (escaped_network != NULL);

	set_entry_cipher (client, escaped_network, IW_AUTH_CIPHER_NONE);

	/* Remove the old auth_method key if it's present */
	unset_nm_gconf_key (client, escaped_network, "auth_method");
}

static void
generic_convert_wep_entry (GConfClient *client,
                           const char *escaped_network,
                           const char *essid,
                           IEEE_802_11_Cipher *first_cipher,
                           IEEE_802_11_Cipher *second_cipher)
{
	char *				key;
	int					key_item_id = -1;
	int					real_we_cipher = IW_AUTH_CIPHER_WEP104;
	IEEE_802_11_Cipher *	real_cipher = NULL;
	char *				hashed_key = NULL;

	g_return_if_fail (client != NULL);
	g_return_if_fail (escaped_network != NULL);
	g_return_if_fail (essid != NULL);
	g_return_if_fail (first_cipher != NULL);

	key = get_key_from_keyring (essid, &key_item_id);

	/* Try to validate key with first cipher */
	if (ieee_802_11_cipher_validate (first_cipher, essid, key) == 0)
	{
		if ((hashed_key = ieee_802_11_cipher_hash (first_cipher, essid, key)))
			real_cipher = first_cipher;
	}

	if (second_cipher && !hashed_key)
	{
		/* Try second cipher then */
		if (ieee_802_11_cipher_validate (second_cipher, essid, key) == 0)
			if ((hashed_key = ieee_802_11_cipher_hash (second_cipher, essid, key)))
				real_cipher = second_cipher;
	}

	if (real_cipher && hashed_key)
	{
		real_we_cipher = ieee_802_11_cipher_get_we_cipher (real_cipher);
		/* Set the converted key in the keyring */
		set_key_in_keyring (essid, hashed_key);
	}
	else
	{
		/* Couldn't convert the key, so remove it from
		 * the keyring and let the user enter it later.
		 */
		nm_warning ("%s:%d (%s): Could not convert old WEP key for network '%s'.",
			__FILE__, __LINE__, __func__, essid);
		gnome_keyring_item_delete_sync (NULL, key_item_id);
	}
	g_free (key);

	/* Set new WE cipher */
	set_entry_cipher (client, escaped_network, real_we_cipher);

	/* Set the authentication algorithm */
	convert_entry_auth_algorithm (client, escaped_network);
}

static void
convert_one_entry (GConfClient *client,
                   const char *essid)
{
	int			we_cipher;
	GConfValue *	addrs_value = NULL;
	char *		escaped_network;
	char *		key;
	int			int_key_type;
	NMEncKeyType	key_type = NM_ENC_TYPE_NONE;
	IEEE_802_11_Cipher * first_cipher = NULL;
	IEEE_802_11_Cipher * second_cipher = NULL;

	g_return_if_fail (client != NULL);
	g_return_if_fail (essid != NULL);

	if (!(escaped_network = gconf_escape_key (essid, strlen (essid))) || strlen (escaped_network) < 0)
	{
		nm_warning ("%s:%d (%s): couldn't unescape network name '%s'.",
				__FILE__, __LINE__, __func__, essid);
		return;
	}

	/* Ignore any entry that looks like it doesn't need conversion */
	if (nm_gconf_get_int_helper (client,
                                   GCONF_PATH_WIRELESS_NETWORKS,
                                   "we_cipher",
                                   escaped_network,
                                   &we_cipher))
		goto out;

	/* Grab the key type off this old entry so we know how to convert it */
	if (nm_gconf_get_int_helper (client,
                                   GCONF_PATH_WIRELESS_NETWORKS,
                                   "key_type",
                                   escaped_network,
                                   &int_key_type))
	{
		key_type = (NMEncKeyType) int_key_type;
	}

	/* Convert the list of stored access point BSSIDs */
	key = g_strdup_printf ("%s/%s/addresses", GCONF_PATH_WIRELESS_NETWORKS, escaped_network);
	if ((addrs_value = gconf_client_get (client, key, NULL)))
	{
		if ((addrs_value->type == GCONF_VALUE_LIST) && (gconf_value_get_list_type (addrs_value) == GCONF_VALUE_STRING))
		{
			GSList *	list;
			char *	conv_key;

			list = gconf_client_get_list (client, key, GCONF_VALUE_STRING, NULL);
			conv_key = g_strdup_printf ("%s/%s/bssids", GCONF_PATH_WIRELESS_NETWORKS, escaped_network);
			gconf_client_set_list (client, conv_key, GCONF_VALUE_STRING, list, NULL);
			g_free (conv_key);
			g_slist_foreach (list, (GFunc) g_free, NULL);
			g_slist_free (list);
		}
		gconf_value_free (addrs_value);
	}
	gconf_client_unset (client, key, NULL);
	g_free (key);

	/* Convert security information, if any */
	switch (key_type)
	{
		case NM_ENC_TYPE_UNKNOWN:
		case NM_ENC_TYPE_NONE:
			convert_no_encryption (client, escaped_network);
			break;
		case NM_ENC_TYPE_HEX_KEY:
			first_cipher = cipher_wep128_hex_new ();
			second_cipher = cipher_wep64_hex_new ();
			break;
		case NM_ENC_TYPE_ASCII_KEY:
			first_cipher = cipher_wep128_ascii_new ();
			second_cipher = cipher_wep64_ascii_new ();
			break;
		case NM_ENC_TYPE_128_BIT_PASSPHRASE:
			first_cipher = cipher_wep128_passphrase_new ();
			second_cipher = cipher_wep64_passphrase_new ();
			break;
		default:
			break;
	}

	if (first_cipher)
	{
		/* Do the actual key conversion */
		generic_convert_wep_entry (client, escaped_network, essid, first_cipher, second_cipher);
		ieee_802_11_cipher_unref (first_cipher);
		if (second_cipher)
			ieee_802_11_cipher_unref (second_cipher);
	}
	unset_nm_gconf_key (client, escaped_network, "key_type");

out:
	g_free (escaped_network);

	return;
}

void
nma_compat_convert_oldformat_entries (GConfClient *client)
{
	GSList *	dir_list = NULL;
	GSList *	elt;

	g_return_if_fail (client != NULL);

	if (!(dir_list = gconf_client_all_dirs (client, GCONF_PATH_WIRELESS_NETWORKS, NULL)))
		return;

	for (elt = dir_list; elt; elt = g_slist_next (elt))
	{
		char			key[100];
		GConfValue *	value;
		char *		dir = (char *) (elt->data);

		g_snprintf (&key[0], 99, "%s/essid", dir);
		if ((value = gconf_client_get (client, key, NULL)))
		{
			if (value->type == GCONF_VALUE_STRING)
			{
				const char *essid = gconf_value_get_string (value);
				convert_one_entry (client, essid);
			}
			gconf_value_free (value);
		}
		g_free (dir);
	}
	g_slist_free (dir_list);

}
