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
 * (C) Copyright 2006 Novell, Inc.
 */

#include <glib.h>
#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <iwlib.h>

#include "nm-ap-security.h"
#include "nm-ap-security-wpa-eap.h"
#include "nm-ap-security-private.h"
#include "dbus-helpers.h"
#include "nm-device-802-11-wireless.h"
#include "NetworkManagerUtils.h"

#define NM_AP_SECURITY_WPA_EAP_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_AP_SECURITY_WPA_EAP, NMAPSecurityWPA_EAPPrivate))

struct _NMAPSecurityWPA_EAPPrivate
{
	int		eap_method;
	int		wpa_version;
	int		key_mgmt;
	char *	identity;
	char *	passwd;
	char *	anon_identity;
	char *	private_key_passwd;
	char *	private_key_file;
	char *	client_cert_file;
	char *	ca_cert_file;
};


NMAPSecurityWPA_EAP *
nm_ap_security_wpa_eap_new_deserialize (DBusMessageIter *iter)
{
	NMAPSecurityWPA_EAP *	security = NULL;
	int					eap_method;
	int					wpa_version;
	char *				identity = NULL;
	char *				passwd = NULL;
	char *				anon_identity = NULL;
	char *				private_key_passwd = NULL;
	char *				private_key_file = NULL;
	char *				client_cert_file = NULL;
	char *				ca_cert_file = NULL;

	g_return_val_if_fail (iter != NULL, NULL);

	if (!nmu_security_deserialize_wpa_eap (iter, &eap_method, &identity, &passwd, &anon_identity,
								    &private_key_passwd, &private_key_file, &client_cert_file, 
								    &ca_cert_file, &wpa_version))
		goto out;

	/* Success, build up our security object */
	security = g_object_new (NM_TYPE_AP_SECURITY_WPA_EAP, NULL);
	nm_ap_security_set_we_cipher (NM_AP_SECURITY (security), NM_AUTH_TYPE_WPA_EAP);
	nm_ap_security_set_key (NM_AP_SECURITY (security), "FIXME", 5); /* FIXME: what do we do for Enterprise? */
	security->priv->eap_method = eap_method;
	security->priv->wpa_version = wpa_version;
	security->priv->key_mgmt = IW_AUTH_KEY_MGMT_802_1X;
	security->priv->identity = g_strdup (identity);
	security->priv->passwd = g_strdup (passwd);
	security->priv->anon_identity = g_strdup (anon_identity);
	security->priv->private_key_passwd = g_strdup (private_key_passwd);
	security->priv->private_key_file = g_strdup (private_key_file);
	security->priv->client_cert_file = g_strdup (client_cert_file);
	security->priv->ca_cert_file = g_strdup (ca_cert_file);

	if (wpa_version == IW_AUTH_WPA_VERSION_WPA2)
		nm_ap_security_set_description (NM_AP_SECURITY (security), _("WPA2 Enterprise"));
	else
		nm_ap_security_set_description (NM_AP_SECURITY (security), _("WPA Enterprise"));

out:
	return security;
}


NMAPSecurityWPA_EAP *
nm_ap_security_wpa_eap_new_from_ap (NMAccessPoint *ap)
{
	NMAPSecurityWPA_EAP *	security = NULL;
	guint32				caps;

	g_return_val_if_fail (ap != NULL, NULL);

	security = g_object_new (NM_TYPE_AP_SECURITY_WPA_EAP, NULL);
	nm_ap_security_set_we_cipher (NM_AP_SECURITY (security), NM_AUTH_TYPE_WPA_EAP);

	caps = nm_ap_get_capabilities (ap);
	if (caps & NM_802_11_CAP_PROTO_WPA2)
	{
		security->priv->wpa_version = IW_AUTH_WPA_VERSION_WPA2;
		nm_ap_security_set_description (NM_AP_SECURITY (security), _("WPA2 Enterprise"));
	}
	else
	{
		security->priv->wpa_version = IW_AUTH_WPA_VERSION_WPA;
		nm_ap_security_set_description (NM_AP_SECURITY (security), _("WPA Enterprise"));
	}

	return security;
}


static int 
real_serialize (NMAPSecurity *instance, DBusMessageIter *iter)
{
	NMAPSecurityWPA_EAP * self = NM_AP_SECURITY_WPA_EAP (instance);

	if (!nmu_security_serialize_wpa_eap (iter,
								  self->priv->eap_method,
								  self->priv->identity,
								  self->priv->passwd,
								  self->priv->anon_identity,
								  self->priv->private_key_passwd,
								  self->priv->private_key_file,
								  self->priv->client_cert_file,
								  self->priv->ca_cert_file,
								  self->priv->wpa_version))
		return -1;
	return 0;
}


static const char *
get_eap_method (int eap_method)
{
	switch (eap_method)
	{
		case NM_EAP_METHOD_PEAP:
			return "PEAP";
		case NM_EAP_METHOD_TLS:
			return "TLS";
		case NM_EAP_METHOD_TTLS:
			return "TTLS";
		default:
			g_warning ("Unmatched eap_method=%d!", eap_method);
			return "TLS";
	}
}


static gboolean 
real_write_supplicant_config (NMAPSecurity *instance,
                              struct wpa_ctrl *ctrl,
                              int nwid,
                              gboolean user_created)
{
	NMAPSecurityWPA_EAP * self = NM_AP_SECURITY_WPA_EAP (instance);
	gboolean			success = FALSE;
	char *			msg;
	const char *		identity = self->priv->identity;
	const char *		anon_identity = self->priv->anon_identity;
	const char *		passwd = self->priv->passwd;
	const char *		private_key_passwd = self->priv->private_key_passwd;
	const char *		private_key_file = self->priv->private_key_file;
	const char *		ca_cert_file = self->priv->ca_cert_file;
	const char *		client_cert_file = self->priv->client_cert_file;
	int				wpa_version = self->priv->wpa_version;
	int				cipher = nm_ap_security_get_we_cipher (instance);
	int 				key_mgmt = self->priv->key_mgmt;
	int				eap_method = self->priv->eap_method;

	g_return_val_if_fail (cipher == NM_AUTH_TYPE_WPA_EAP, FALSE);
	g_return_val_if_fail (key_mgmt == IW_AUTH_KEY_MGMT_802_1X, FALSE);
	g_return_val_if_fail (wpa_version == IW_AUTH_WPA_VERSION_WPA
				    || wpa_version == IW_AUTH_WPA_VERSION_WPA2, FALSE);
	g_return_val_if_fail (eap_method == NM_EAP_METHOD_MD5
				    || eap_method == NM_EAP_METHOD_MSCHAP
				    || eap_method == NM_EAP_METHOD_OTP
				    || eap_method == NM_EAP_METHOD_GTC
				    || eap_method == NM_EAP_METHOD_PEAP
				    || eap_method == NM_EAP_METHOD_TLS
				    || eap_method == NM_EAP_METHOD_TTLS, FALSE);

	/* WPA-EAP network setup */

	if (self->priv->wpa_version == IW_AUTH_WPA_VERSION_WPA)
	{
		if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL, "SET_NETWORK %i proto WPA", nwid))
			goto out;
	}
	else
	{
		if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL, "SET_NETWORK %i proto WPA2", nwid))
			goto out;
	}

	if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL, "SET_NETWORK %i key_mgmt WPA-EAP", nwid))
		goto out;

	if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL, "SET_NETWORK %i eap %s", nwid, get_eap_method (eap_method)))
		goto out;

	if (identity && strlen (identity) > 0)
		if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL, "SET_NETWORK %i identity \"%s\"", nwid, identity))
			goto out;

	if (passwd && strlen (passwd) > 0)
		if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL, "SET_NETWORK %i password \"%s\"", nwid, passwd))
			goto out;

	if (anon_identity && strlen (anon_identity) > 0)
		if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL, "SET_NETWORK %i anonymous_identity \"%s\"", nwid, anon_identity))
			goto out;

	if (private_key_file && private_key_passwd && strlen (private_key_file) > 0 && strlen (private_key_passwd) > 0)
	{
		if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL, "SET_NETWORK %i private_key \"%s\"", nwid, private_key_file))
			goto out;

		msg = g_strdup_printf ("SET_NETWORK %i private_key_passwd <key>", nwid);
		if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, msg, "SET_NETWORK %i private_key_passwd \"%s\"", nwid, private_key_passwd))
		{
			g_free (msg);
			goto out;
		}
		g_free (msg);
	}

	if (client_cert_file && strlen (client_cert_file) > 0)
		if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL, "SET_NETWORK %i client_cert \"%s\"", nwid, client_cert_file))
			goto out;

	if (ca_cert_file && strlen (ca_cert_file) > 0)
		if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL, "SET_NETWORK %i ca_cert \"%s\"", nwid, ca_cert_file))
			goto out;

#if 0	/* Right now we always let wpa_supplicant sort out the pairwise and group cipher */
	/*
	 * FIXME: Technically, the pairwise cipher does not need to be the same as
	 * the group cipher.  Fixing this requires changes in the UI.
	 */
	if (cipher == IW_AUTH_CIPHER_TKIP)
		pairwise_cipher = group_cipher = "TKIP";
	else if (cipher == IW_AUTH_CIPHER_CCMP)
		pairwise_cipher = group_cipher = "CCMP";
	else if (cipher == IW_AUTH_CIPHER_NONE)
		pairwise_cipher = group_cipher = "NONE";

	/* Ad-Hoc requires pairwise cipher of NONE */
	if (user_created)
		pairwise_cipher = "NONE";

	/* If user selected "Automatic", we let wpa_supplicant sort it out */
	if (cipher != NM_AUTH_TYPE_WPA_PSK_AUTO)
	{
		if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL,
				"SET_NETWORK %i pairwise %s", nwid, pairwise_cipher))
			goto out;

		if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL,
				"SET_NETWORK %i group %s", nwid, group_cipher))
			goto out;
	}
#endif

	success = TRUE;

out:
	return success;
}

static guint32
real_get_default_capabilities (NMAPSecurity *instance)
{
	NMAPSecurityWPA_EAP *self = NM_AP_SECURITY_WPA_EAP (instance);
	guint32			caps = NM_802_11_CAP_NONE;

	if (self->priv->wpa_version == IW_AUTH_WPA_VERSION_WPA)
		caps |= NM_802_11_CAP_PROTO_WPA | NM_802_11_CAP_CIPHER_TKIP;
	else if (self->priv->wpa_version == IW_AUTH_WPA_VERSION_WPA2)
		caps |= NM_802_11_CAP_PROTO_WPA2 | NM_802_11_CAP_CIPHER_CCMP;

	if (self->priv->key_mgmt == IW_AUTH_KEY_MGMT_802_1X)
		caps |= NM_802_11_CAP_KEY_MGMT_802_1X;

	return caps;
}

static NMAPSecurity *
real_copy_constructor (NMAPSecurity *instance)
{
	NMAPSecurityWPA_EAP * dst = g_object_new (NM_TYPE_AP_SECURITY_WPA_EAP, NULL);
	NMAPSecurityWPA_EAP * self = NM_AP_SECURITY_WPA_EAP (instance);

	dst->priv->eap_method = self->priv->eap_method;
	dst->priv->wpa_version = self->priv->wpa_version;
	dst->priv->key_mgmt = self->priv->key_mgmt;
	dst->priv->identity = self->priv->identity;
	dst->priv->passwd = self->priv->passwd;
	dst->priv->anon_identity = self->priv->anon_identity;
	dst->priv->private_key_passwd = self->priv->private_key_passwd;
	dst->priv->private_key_file = self->priv->private_key_file;
	dst->priv->client_cert_file = self->priv->client_cert_file;
	dst->priv->ca_cert_file = self->priv->ca_cert_file;

	nm_ap_security_copy_properties (NM_AP_SECURITY (self), NM_AP_SECURITY (dst));

	return NM_AP_SECURITY (dst);
}


static void
nm_ap_security_wpa_eap_init (NMAPSecurityWPA_EAP * self)
{
	self->priv = NM_AP_SECURITY_WPA_EAP_GET_PRIVATE (self);
	self->priv->eap_method = NM_EAP_METHOD_TLS;
	self->priv->wpa_version = IW_AUTH_WPA_VERSION_WPA;
	self->priv->key_mgmt = IW_AUTH_KEY_MGMT_802_1X;
	self->priv->identity = NULL;
	self->priv->passwd = NULL;
	self->priv->anon_identity = NULL;
	self->priv->private_key_passwd = NULL;
	self->priv->private_key_file = NULL;
	self->priv->client_cert_file = NULL;
	self->priv->ca_cert_file = NULL;
}


static void
nm_ap_security_wpa_eap_class_init (NMAPSecurityWPA_EAPClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMAPSecurityClass *par_class = NM_AP_SECURITY_CLASS (klass);

	par_class->copy_constructor_func = real_copy_constructor;
	par_class->serialize_func = real_serialize;
	par_class->write_supplicant_config_func = real_write_supplicant_config;
	par_class->get_default_capabilities_func = real_get_default_capabilities;

	g_type_class_add_private (object_class, sizeof (NMAPSecurityWPA_EAPPrivate));
}


GType
nm_ap_security_wpa_eap_get_type (void)
{
	static GType type = 0;
	if (type == 0) {
		static const GTypeInfo info = {
			sizeof (NMAPSecurityWPA_EAPClass),
			NULL,	/* base_init */
			NULL,	/* base_finalize */
			(GClassInitFunc) nm_ap_security_wpa_eap_class_init,
			NULL,	/* class_finalize */
			NULL,	/* class_data */
			sizeof (NMAPSecurityWPA_EAP),
			0,		/* n_preallocs */
			(GInstanceInitFunc) nm_ap_security_wpa_eap_init,
			NULL		/* value_table */
		};
		type = g_type_register_static (NM_TYPE_AP_SECURITY,
					       		 "NMAPSecurityWPA_EAP",
					       		 &info, 0);
	}
	return type;
}
