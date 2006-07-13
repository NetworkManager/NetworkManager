/* NetworkManager -- Network link manager
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
 * (C) Copyright 2006 Thiago Jung Bauermann <thiago.bauermann@gmail.com>
 */

/* This file is heavily based on nm-gconf-wso-wpa-eap.c */

#include <glib.h>
#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <iwlib.h>

#include "applet.h"
#include "nm-gconf-wso.h"
#include "nm-gconf-wso-leap.h"
#include "nm-gconf-wso-private.h"
#include "dbus-helpers.h"
#include "gconf-helpers.h"

#define LEAP_PREFIX "leap_"

#define NM_GCONF_WSO_LEAP_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_GCONF_WSO_LEAP, NMGConfWSOLEAPPrivate))

struct _NMGConfWSOLEAPPrivate
{
	const char *	username;
	const char *	key_mgmt;
};


NMGConfWSOLEAP *
nm_gconf_wso_leap_new_deserialize_dbus (DBusMessageIter *iter, int we_cipher)
{
	NMGConfWSOLEAP *	security = NULL;
	char *			username = NULL;
	char *			password = NULL;
	char *			key_mgmt = NULL;

	g_return_val_if_fail (we_cipher == NM_AUTH_TYPE_LEAP, NULL);
	g_return_val_if_fail (iter != NULL, NULL);

	if (!nmu_security_deserialize_leap (iter, &username, &password, &key_mgmt))
		goto out;

	/* Success, build up our security object */
	security = g_object_new (NM_TYPE_GCONF_WSO_LEAP, NULL);
	nm_gconf_wso_set_we_cipher (NM_GCONF_WSO (security), we_cipher);
	if (password)
		   nm_gconf_wso_set_key (NM_GCONF_WSO (security), password, strlen(password));
	if (username)
		   security->priv->username = g_strdup (username);
	if (key_mgmt)
		   security->priv->key_mgmt = g_strdup (key_mgmt);

out:
	return security;
}


NMGConfWSOLEAP *
nm_gconf_wso_leap_new_deserialize_gconf (GConfClient *client, const char *network, int we_cipher)
{
	NMGConfWSOLEAP *	security = NULL;
	char *			username = NULL;
	char *			key_mgmt = NULL;

	g_return_val_if_fail (client != NULL, NULL);
	g_return_val_if_fail (network != NULL, NULL);
	g_return_val_if_fail ((we_cipher == NM_AUTH_TYPE_LEAP), NULL);

	nm_gconf_get_string_helper (client,
						   GCONF_PATH_WIRELESS_NETWORKS,
						   LEAP_PREFIX"username",
						   network,
						   &username);

	nm_gconf_get_string_helper (client,
						   GCONF_PATH_WIRELESS_NETWORKS,
						   LEAP_PREFIX"key_mgmt",
						   network,
						   &key_mgmt);

	/* Success, build up our security object */
	security = g_object_new (NM_TYPE_GCONF_WSO_LEAP, NULL);
	nm_gconf_wso_set_we_cipher (NM_GCONF_WSO (security), we_cipher);
	security->priv->username = username;
	security->priv->key_mgmt = key_mgmt;

	return security;
}


static gboolean 
real_serialize_dbus (NMGConfWSO *instance, DBusMessageIter *iter)
{
	NMGConfWSOLEAP * self = NM_GCONF_WSO_LEAP (instance);

	if (!nmu_security_serialize_leap (iter, self->priv->username,
			nm_gconf_wso_get_key(instance), self->priv->key_mgmt))
		return FALSE;
	return TRUE;
}

static gboolean 
real_serialize_gconf (NMGConfWSO *instance, GConfClient *client, const char *network)
{
	NMGConfWSOLEAP *	self = NM_GCONF_WSO_LEAP (instance);
	char *			key;

	key = g_strdup_printf ("%s/%s/%susername", GCONF_PATH_WIRELESS_NETWORKS, network, LEAP_PREFIX);
	gconf_client_set_string (client, key, self->priv->username, NULL);
	g_free (key);

	key = g_strdup_printf ("%s/%s/%skey_mgmt", GCONF_PATH_WIRELESS_NETWORKS, network, LEAP_PREFIX);
	gconf_client_set_string (client, key, self->priv->key_mgmt, NULL);
	g_free (key);

	return TRUE;
}


static void
nm_gconf_wso_leap_init (NMGConfWSOLEAP *self)
{
	self->priv = NM_GCONF_WSO_LEAP_GET_PRIVATE (self);
}


static void
nm_gconf_wso_leap_class_init (NMGConfWSOLEAPClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMGConfWSOClass *par_class = NM_GCONF_WSO_CLASS (klass);

	par_class->serialize_dbus_func = real_serialize_dbus;
	par_class->serialize_gconf_func = real_serialize_gconf;

	g_type_class_add_private (object_class, sizeof (NMGConfWSOLEAPPrivate));
}


GType
nm_gconf_wso_leap_get_type (void)
{
	static GType type = 0;
	if (type == 0) {
		static const GTypeInfo info = {
			sizeof (NMGConfWSOLEAPClass),
			NULL,	/* base_init */
			NULL,	/* base_finalize */
			(GClassInitFunc) nm_gconf_wso_leap_class_init,
			NULL,	/* class_finalize */
			NULL,	/* class_data */
			sizeof (NMGConfWSOLEAP),
			0,		/* n_preallocs */
			(GInstanceInitFunc) nm_gconf_wso_leap_init,
			NULL		/* value_table */
		};
		type = g_type_register_static (NM_TYPE_GCONF_WSO,
								 "NMGConfWSOLEAP",
								 &info, 0);
	}
	return type;
}
