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
#include <iwlib.h>

#include "applet.h"
#include "nm-gconf-wso.h"
#include "nm-gconf-wso-wpa-psk.h"
#include "nm-gconf-wso-private.h"
#include "dbus-helpers.h"
#include "gconf-helpers.h"

#define WPA_PSK_PREFIX "wpa_psk_"

#define NM_GCONF_WSO_WPA_PSK_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_GCONF_WSO_WPA_PSK, NMGConfWSOWPA_PSKPrivate))

struct _NMGConfWSOWPA_PSKPrivate
{
	int		wpa_version;
	int		key_mgt;
};

NMGConfWSOWPA_PSK *
nm_gconf_wso_wpa_psk_new_deserialize_dbus (DBusMessageIter *iter, int we_cipher)
{
	NMGConfWSOWPA_PSK *	security = NULL;
	char *			key = NULL;
	int				key_len;
	int				wpa_version;
	int				key_mgt;

	g_return_val_if_fail (iter != NULL, NULL);
	g_return_val_if_fail ((we_cipher == NM_AUTH_TYPE_WPA_PSK_AUTO || we_cipher == IW_AUTH_CIPHER_TKIP) || (we_cipher == IW_AUTH_CIPHER_CCMP), NULL);

	if (!nmu_security_deserialize_wpa_psk (iter, &key, &key_len, &wpa_version, &key_mgt))
		goto out;

	/* Success, build up our security object */
	security = g_object_new (NM_TYPE_GCONF_WSO_WPA_PSK, NULL);
	nm_gconf_wso_set_we_cipher (NM_GCONF_WSO (security), we_cipher);
	nm_gconf_wso_set_key (NM_GCONF_WSO (security), key, key_len);
	security->priv->wpa_version = wpa_version;
	security->priv->key_mgt = key_mgt;

out:
	return security;
}

NMGConfWSOWPA_PSK *
nm_gconf_wso_wpa_psk_new_deserialize_gconf (GConfClient *client, const char *network, int we_cipher)
{
	NMGConfWSOWPA_PSK *	security = NULL;
	int				wpa_version;
	int				key_mgt;

	g_return_val_if_fail (client != NULL, NULL);
	g_return_val_if_fail (network != NULL, NULL);
	g_return_val_if_fail ((we_cipher == NM_AUTH_TYPE_WPA_PSK_AUTO || we_cipher == IW_AUTH_CIPHER_TKIP) || (we_cipher == IW_AUTH_CIPHER_CCMP), NULL);

	if (!nm_gconf_get_int_helper (client,
							GCONF_PATH_WIRELESS_NETWORKS,
							WPA_PSK_PREFIX"wpa_version",
							network,
							&wpa_version))
		goto out;

	if (!nm_gconf_get_int_helper (client,
							GCONF_PATH_WIRELESS_NETWORKS,
							WPA_PSK_PREFIX"key_mgt",
							network,
							&key_mgt))
		goto out;

	/* Success, build up our security object */
	security = g_object_new (NM_TYPE_GCONF_WSO_WPA_PSK, NULL);
	nm_gconf_wso_set_we_cipher (NM_GCONF_WSO (security), we_cipher);
	security->priv->wpa_version = wpa_version;
	security->priv->key_mgt = key_mgt;

out:
	return security;
}

static gboolean 
real_serialize_dbus (NMGConfWSO *instance, DBusMessageIter *iter)
{
	NMGConfWSOWPA_PSK * self = NM_GCONF_WSO_WPA_PSK (instance);

	if (!nmu_security_serialize_wpa_psk (iter,
			nm_gconf_wso_get_key (instance),
			self->priv->wpa_version,
			self->priv->key_mgt))
		return FALSE;
	return TRUE;
}

static gboolean 
real_serialize_gconf (NMGConfWSO *instance, GConfClient *client, const char *network)
{
	NMGConfWSOWPA_PSK *	self = NM_GCONF_WSO_WPA_PSK (instance);
	char *			key;

	key = g_strdup_printf ("%s/%s/%swpa_version", GCONF_PATH_WIRELESS_NETWORKS, network, WPA_PSK_PREFIX);
	gconf_client_set_int (client, key, self->priv->wpa_version, NULL);
	g_free (key);

	key = g_strdup_printf ("%s/%s/%skey_mgt", GCONF_PATH_WIRELESS_NETWORKS, network, WPA_PSK_PREFIX);
	gconf_client_set_int (client, key, self->priv->key_mgt, NULL);
	g_free (key);

	return TRUE;
}

static void
nm_gconf_wso_wpa_psk_init (NMGConfWSOWPA_PSK * self)
{
	self->priv = NM_GCONF_WSO_WPA_PSK_GET_PRIVATE (self);
	self->priv->wpa_version = IW_AUTH_WPA_VERSION_WPA;
	self->priv->key_mgt = IW_AUTH_KEY_MGMT_PSK;
}

static void
nm_gconf_wso_wpa_psk_class_init (NMGConfWSOWPA_PSKClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMGConfWSOClass *par_class = NM_GCONF_WSO_CLASS (klass);

	par_class->serialize_dbus_func = real_serialize_dbus;
	par_class->serialize_gconf_func = real_serialize_gconf;

	g_type_class_add_private (object_class, sizeof (NMGConfWSOWPA_PSKPrivate));
}

GType
nm_gconf_wso_wpa_psk_get_type (void)
{
	static GType type = 0;
	if (type == 0) {
		static const GTypeInfo info = {
			sizeof (NMGConfWSOWPA_PSKClass),
			NULL,	/* base_init */
			NULL,	/* base_finalize */
			(GClassInitFunc) nm_gconf_wso_wpa_psk_class_init,
			NULL,	/* class_finalize */
			NULL,	/* class_data */
			sizeof (NMGConfWSOWPA_PSK),
			0,		/* n_preallocs */
			(GInstanceInitFunc) nm_gconf_wso_wpa_psk_init,
			NULL		/* value_table */
		};
		type = g_type_register_static (NM_TYPE_GCONF_WSO,
								 "NMGConfWSOWPA_PSK",
								 &info, 0);
	}
	return type;
}
