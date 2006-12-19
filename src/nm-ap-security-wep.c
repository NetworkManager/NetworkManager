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

#include "nm-ap-security.h"
#include "nm-ap-security-wep.h"
#include "nm-ap-security-private.h"
#include "dbus-helpers.h"
#include "nm-device-802-11-wireless.h"
#include "nm-utils.h"
#include "nm-supplicant-config.h"

#define NM_AP_SECURITY_WEP_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_AP_SECURITY_WEP, NMAPSecurityWEPPrivate))

struct _NMAPSecurityWEPPrivate
{
	int		auth_algorithm;
};

static int get_auth_algorithm (NMAPSecurityWEP *security)
{
	return security->priv->auth_algorithm;
}

static void set_description (NMAPSecurityWEP *security)
{
	NMAPSecurity * parent = NM_AP_SECURITY (security);

	if (nm_ap_security_get_we_cipher (parent) == IW_AUTH_CIPHER_WEP40)
		nm_ap_security_set_description (parent, _("40-bit WEP"));
	else
		nm_ap_security_set_description (parent, _("104-bit WEP"));

}

NMAPSecurityWEP *
nm_ap_security_wep_new_deserialize (DBusMessageIter *iter, int we_cipher)
{
	NMAPSecurityWEP *	security = NULL;
	char *			key = NULL;
	int				key_len;
	int				auth_algorithm;

	g_return_val_if_fail (iter != NULL, NULL);
	g_return_val_if_fail ((we_cipher == IW_AUTH_CIPHER_WEP40) || (we_cipher == IW_AUTH_CIPHER_WEP104), NULL);

	if (!nmu_security_deserialize_wep (iter, &key, &key_len, &auth_algorithm))
		goto out;

	/* Success, build up our security object */
	security = g_object_new (NM_TYPE_AP_SECURITY_WEP, NULL);
	nm_ap_security_set_we_cipher (NM_AP_SECURITY (security), we_cipher);
	if (key)
		nm_ap_security_set_key (NM_AP_SECURITY (security), key, key_len);
	security->priv->auth_algorithm = auth_algorithm;

	set_description (security);

out:
	return security;
}

NMAPSecurityWEP *
nm_ap_security_wep_new_from_ap (NMAccessPoint *ap, int we_cipher)
{
	NMAPSecurityWEP *	security = NULL;

	g_return_val_if_fail (ap != NULL, NULL);
	g_return_val_if_fail ((we_cipher == IW_AUTH_CIPHER_WEP40) || (we_cipher == IW_AUTH_CIPHER_WEP104), NULL);

	security = g_object_new (NM_TYPE_AP_SECURITY_WEP, NULL);
	nm_ap_security_set_we_cipher (NM_AP_SECURITY (security), we_cipher);
	security->priv->auth_algorithm = IW_AUTH_ALG_OPEN_SYSTEM;

	set_description (security);

	return security;
}

static int 
real_serialize (NMAPSecurity *instance, DBusMessageIter *iter)
{
	NMAPSecurityWEP *	self = NM_AP_SECURITY_WEP (instance);

	if (!nmu_security_serialize_wep (iter,
			nm_ap_security_get_key (instance),
			self->priv->auth_algorithm))
		return -1;
	return 0;
}

static gboolean 
real_write_supplicant_config (NMAPSecurity *instance,
                              NMSupplicantConfig * config,
                              gboolean adhoc)
{
	gboolean     success = FALSE;
	const char * key = nm_ap_security_get_key (instance);
	char *       bin_key = NULL;

	/* WEP network setup */
	if (!nm_supplicant_config_add_option (config, "key_mgmt", "NONE", -1))
		goto out;

	/*
	 * If the user selected "Shared" (aka restricted) key, set it explicitly.  Otherwise,
	 * let wpa_supplicant default to the right thing, which is an open key.
	 */
	if (get_auth_algorithm (NM_AP_SECURITY_WEP (instance)) == IW_AUTH_ALG_SHARED_KEY) {
		if (!nm_supplicant_config_add_option (config, "auth_alg", "SHARED", -1))
			goto out;
	}

	bin_key = cipher_hexstr2bin(key, strlen (key));
	if (bin_key == NULL) {
		nm_warning ("Not enough memory to convert key.");
		goto out;
	}

	if (!nm_supplicant_config_add_option (config, "wep_key0", bin_key, -1)) {
		g_free (bin_key);
		goto out;
	}
	g_free (bin_key);

	if (!nm_supplicant_config_add_option (config, "wep_tx_keyidx", "0", -1))
		goto out;

	success = TRUE;

out:
	return success;
}

static guint32
real_get_default_capabilities (NMAPSecurity *instance)
{
	guint32	caps = NM_802_11_CAP_NONE;

	switch (nm_ap_security_get_we_cipher (instance))
	{
		case IW_AUTH_CIPHER_WEP40:
			caps |= (NM_802_11_CAP_PROTO_WEP | NM_802_11_CAP_CIPHER_WEP40);
			break;
		case IW_AUTH_CIPHER_WEP104:
			caps |= (NM_802_11_CAP_PROTO_WEP | NM_802_11_CAP_CIPHER_WEP104);
			break;
		default:
			break;
	}
	return caps;
}

static gboolean
real_get_authentication_required (NMAPSecurity *instance)
{
	/* WEP really requires authentication in Shared mode only */
	return (get_auth_algorithm (NM_AP_SECURITY_WEP (instance)) == IW_AUTH_ALG_SHARED_KEY);
}

static NMAPSecurity *
real_copy_constructor (NMAPSecurity *instance)
{
	NMAPSecurityWEP * dst = g_object_new (NM_TYPE_AP_SECURITY_WEP, NULL);
	NMAPSecurityWEP * self = NM_AP_SECURITY_WEP (instance);

	dst->priv->auth_algorithm = self->priv->auth_algorithm;
	nm_ap_security_copy_properties (NM_AP_SECURITY (self), NM_AP_SECURITY (dst));
	return NM_AP_SECURITY (dst);
}

static void
nm_ap_security_wep_init (NMAPSecurityWEP * self)
{
	self->priv = NM_AP_SECURITY_WEP_GET_PRIVATE (self);
	self->priv->auth_algorithm = IW_AUTH_ALG_OPEN_SYSTEM;
}

static void
nm_ap_security_wep_class_init (NMAPSecurityWEPClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMAPSecurityClass *par_class = NM_AP_SECURITY_CLASS (klass);

	par_class->copy_constructor_func = real_copy_constructor;
	par_class->serialize_func = real_serialize;
	par_class->write_supplicant_config_func = real_write_supplicant_config;
	par_class->get_default_capabilities_func = real_get_default_capabilities;
	par_class->get_authentication_required_func = real_get_authentication_required;

	g_type_class_add_private (object_class, sizeof (NMAPSecurityWEPPrivate));
}

GType
nm_ap_security_wep_get_type (void)
{
	static GType type = 0;
	if (type == 0) {
		static const GTypeInfo info = {
			sizeof (NMAPSecurityWEPClass),
			NULL,	/* base_init */
			NULL,	/* base_finalize */
			(GClassInitFunc) nm_ap_security_wep_class_init,
			NULL,	/* class_finalize */
			NULL,	/* class_data */
			sizeof (NMAPSecurityWEP),
			0,		/* n_preallocs */
			(GInstanceInitFunc) nm_ap_security_wep_init,
			NULL		/* value_table */
		};
		type = g_type_register_static (NM_TYPE_AP_SECURITY,
								 "NMAPSecurityWEP",
								 &info, 0);
	}
	return type;
}
