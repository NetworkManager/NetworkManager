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
#include "nm-gconf-wso-wep.h"
#include "nm-gconf-wso-private.h"
#include "dbus-helpers.h"
#include "gconf-helpers.h"

#define WEP_PREFIX	"wep_"

#define NM_GCONF_WSO_WEP_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_GCONF_WSO_WEP, NMGConfWSOWEPPrivate))

struct _NMGConfWSOWEPPrivate
{
	int		auth_algorithm;

	gboolean	dispose_has_run;
};

NMGConfWSOWEP *
nm_gconf_wso_wep_new_deserialize_dbus (DBusMessageIter *iter, int we_cipher)
{
	NMGConfWSOWEP *	security = NULL;
	char *			key = NULL;
	int				key_len;
	int				auth_algorithm;

	g_return_val_if_fail (iter != NULL, NULL);
	g_return_val_if_fail ((we_cipher == IW_AUTH_CIPHER_WEP40) || (we_cipher == IW_AUTH_CIPHER_WEP104), NULL);

	if (!nmu_security_deserialize_wep (iter, &key, &key_len, &auth_algorithm))
		goto out;

	/* Success, build up our security object */
	security = g_object_new (NM_TYPE_GCONF_WSO_WEP, NULL);
	nm_gconf_wso_set_we_cipher (NM_GCONF_WSO (security), we_cipher);
	nm_gconf_wso_set_key (NM_GCONF_WSO (security), key, key_len);
	security->priv->auth_algorithm = auth_algorithm;

out:
	return security;
}

NMGConfWSOWEP *
nm_gconf_wso_wep_new_deserialize_gconf (GConfClient *client, const char *network, int we_cipher)
{
	NMGConfWSOWEP *	security = NULL;
	int				auth_algorithm;

	g_return_val_if_fail (client != NULL, NULL);
	g_return_val_if_fail (network != NULL, NULL);
	g_return_val_if_fail ((we_cipher == IW_AUTH_CIPHER_WEP40) || (we_cipher == IW_AUTH_CIPHER_WEP104), NULL);

	if (!nm_gconf_get_int_helper (client,
							GCONF_PATH_WIRELESS_NETWORKS,
							WEP_PREFIX"auth_algorithm",
							network,
							&auth_algorithm))
		goto out;

	/* Success, build up our security object */
	security = g_object_new (NM_TYPE_GCONF_WSO_WEP, NULL);
	nm_gconf_wso_set_we_cipher (NM_GCONF_WSO (security), we_cipher);
	security->priv->auth_algorithm = auth_algorithm;

out:
	return security;
}

static gboolean 
real_serialize_dbus (NMGConfWSO *instance, DBusMessageIter *iter)
{
	NMGConfWSOWEP * self = NM_GCONF_WSO_WEP (instance);

	if (!nmu_security_serialize_wep (iter,
			nm_gconf_wso_get_key (instance),
			self->priv->auth_algorithm))
		return FALSE;
	return TRUE;
}

static gboolean 
real_serialize_gconf (NMGConfWSO *instance, GConfClient *client, const char *network)
{
	NMGConfWSOWEP *self = NM_GCONF_WSO_WEP (instance);
	char *		key;

	key = g_strdup_printf ("%s/%s/%sauth_algorithm", GCONF_PATH_WIRELESS_NETWORKS, network, WEP_PREFIX);
	gconf_client_set_int (client, key, self->priv->auth_algorithm, NULL);
	g_free (key);

	return TRUE;
}

static void
nm_gconf_wso_wep_init (NMGConfWSOWEP * self)
{
	self->priv = NM_GCONF_WSO_WEP_GET_PRIVATE (self);
	self->priv->auth_algorithm = IW_AUTH_ALG_OPEN_SYSTEM;
	self->priv->dispose_has_run = FALSE;
}

static void
nm_gconf_wso_wep_class_init (NMGConfWSOWEPClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMGConfWSOClass *par_class = NM_GCONF_WSO_CLASS (klass);

	par_class->serialize_dbus_func = real_serialize_dbus;
	par_class->serialize_gconf_func = real_serialize_gconf;

	g_type_class_add_private (object_class, sizeof (NMGConfWSOWEPPrivate));
}

GType
nm_gconf_wso_wep_get_type (void)
{
	static GType type = 0;
	if (type == 0) {
		static const GTypeInfo info = {
			sizeof (NMGConfWSOWEPClass),
			NULL,	/* base_init */
			NULL,	/* base_finalize */
			(GClassInitFunc) nm_gconf_wso_wep_class_init,
			NULL,	/* class_finalize */
			NULL,	/* class_data */
			sizeof (NMGConfWSOWEP),
			0,		/* n_preallocs */
			(GInstanceInitFunc) nm_gconf_wso_wep_init,
			NULL		/* value_table */
		};
		type = g_type_register_static (NM_TYPE_GCONF_WSO,
								"NMGConfWSOWEP",
								&info, 0);
	}
	return type;
}
