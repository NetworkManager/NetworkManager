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
#include "nm-ap-security-wpa-psk.h"
#include "nm-ap-security-private.h"
#include "dbus-helpers.h"
#include "nm-device-802-11-wireless.h"
#include "NetworkManagerUtils.h"

#define NM_AP_SECURITY_WPA_PSK_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_AP_SECURITY_WPA_PSK, NMAPSecurityWPA_PSKPrivate))

struct _NMAPSecurityWPA_PSKPrivate
{
	int		wpa_version;
	int		key_mgt;
};

static void set_description (NMAPSecurityWPA_PSK *security)
{
	NMAPSecurity * parent = NM_AP_SECURITY (security);
	int			we_cipher = nm_ap_security_get_we_cipher (parent);

	if (security->priv->wpa_version == IW_AUTH_WPA_VERSION_WPA)
	{
		if (we_cipher == IW_AUTH_CIPHER_TKIP)
			nm_ap_security_set_description (parent, _("WPA TKIP"));
		else if (we_cipher == IW_AUTH_CIPHER_CCMP)
			nm_ap_security_set_description (parent, _("WPA CCMP"));
		else
			nm_ap_security_set_description (parent, _("WPA Automatic"));
	}
	else if (security->priv->wpa_version == IW_AUTH_WPA_VERSION_WPA2)
	{
		if (we_cipher == IW_AUTH_CIPHER_TKIP)
			nm_ap_security_set_description (parent, _("WPA2 TKIP"));
		else if (we_cipher == IW_AUTH_CIPHER_CCMP)
			nm_ap_security_set_description (parent, _("WPA2 CCMP"));
		else
			nm_ap_security_set_description (parent, _("WPA2 Automatic"));
	}
}

NMAPSecurityWPA_PSK *
nm_ap_security_wpa_psk_new_deserialize (DBusMessageIter *iter, int we_cipher)
{
	NMAPSecurityWPA_PSK *	security = NULL;
	char *				key = NULL;
	int					key_len;
	int					wpa_version;
	int					key_mgt;

	g_return_val_if_fail (iter != NULL, NULL);
	g_return_val_if_fail (we_cipher == NM_AUTH_TYPE_WPA_PSK_AUTO || we_cipher == IW_AUTH_CIPHER_TKIP || we_cipher == IW_AUTH_CIPHER_CCMP, NULL);

	if (!nmu_security_deserialize_wpa_psk (iter, &key, &key_len, &wpa_version, &key_mgt))
		goto out;

	/* Success, build up our security object */
	security = g_object_new (NM_TYPE_AP_SECURITY_WPA_PSK, NULL);
	nm_ap_security_set_we_cipher (NM_AP_SECURITY (security), we_cipher);
	if (key)
		nm_ap_security_set_key (NM_AP_SECURITY (security), key, key_len);
	security->priv->wpa_version = wpa_version;
	security->priv->key_mgt = key_mgt;

	set_description (security);

out:
	return security;
}

NMAPSecurityWPA_PSK *
nm_ap_security_wpa_psk_new_from_ap (NMAccessPoint *ap, int we_cipher)
{
	NMAPSecurityWPA_PSK *	security = NULL;
	guint32				caps;

	g_return_val_if_fail (ap != NULL, NULL);
	g_return_val_if_fail (we_cipher == NM_AUTH_TYPE_WPA_PSK_AUTO || we_cipher == IW_AUTH_CIPHER_TKIP || (we_cipher == IW_AUTH_CIPHER_CCMP), NULL);

	security = g_object_new (NM_TYPE_AP_SECURITY_WPA_PSK, NULL);
	nm_ap_security_set_we_cipher (NM_AP_SECURITY (security), we_cipher);

	caps = nm_ap_get_capabilities (ap);
	if (caps & NM_802_11_CAP_PROTO_WPA2)
		security->priv->wpa_version = IW_AUTH_WPA_VERSION_WPA2;
	else if (caps & NM_802_11_CAP_PROTO_WPA)
		security->priv->wpa_version = IW_AUTH_WPA_VERSION_WPA;
	security->priv->key_mgt = IW_AUTH_KEY_MGMT_PSK;

	set_description (security);

	return security;
}

static int 
real_serialize (NMAPSecurity *instance, DBusMessageIter *iter)
{
	NMAPSecurityWPA_PSK * self = NM_AP_SECURITY_WPA_PSK (instance);

	if (!nmu_security_serialize_wpa_psk (iter,
			nm_ap_security_get_key (instance),
			self->priv->wpa_version,
			self->priv->key_mgt))
		return -1;
	return 0;
}

static gboolean 
real_write_supplicant_config (NMAPSecurity *instance,
                              struct wpa_ctrl *ctrl,
                              int nwid,
                              gboolean adhoc)
{
	NMAPSecurityWPA_PSK * self = NM_AP_SECURITY_WPA_PSK (instance);
	gboolean			success = FALSE;
	char *			msg = NULL;
	const char *		key = nm_ap_security_get_key (instance);
	int				cipher = nm_ap_security_get_we_cipher (instance);
	char *			key_mgmt = "WPA-PSK";
	char *			pairwise_cipher = NULL;
	char *			group_cipher = NULL;

	/* WPA-PSK network setup */

	if (self->priv->wpa_version == IW_AUTH_WPA_VERSION_WPA)
	{
		if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL,
				"SET_NETWORK %i proto WPA", nwid))
			goto out;
	}
	else if (self->priv->wpa_version == IW_AUTH_WPA_VERSION_WPA2)
	{
		if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL,
				"SET_NETWORK %i proto WPA2", nwid))
			goto out;
	}

	/* Ad-Hoc has to be WPA-NONE */
	if (adhoc)
		key_mgmt = "WPA-NONE";

	if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL,
			"SET_NETWORK %i key_mgmt %s", nwid, key_mgmt))
		goto out;

	msg = g_strdup_printf ("SET_NETWORK %i psk <key>", nwid);
	if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, msg,
			"SET_NETWORK %i psk %s", nwid, key))
	{
		g_free (msg);
		goto out;
	}
	g_free (msg);

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
	if (adhoc)
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

	success = TRUE;

out:
	return success;
}

static guint32
real_get_default_capabilities (NMAPSecurity *instance)
{
	NMAPSecurityWPA_PSK * self = NM_AP_SECURITY_WPA_PSK (instance);
	guint32			caps = NM_802_11_CAP_NONE;
	int				we_cipher = nm_ap_security_get_we_cipher (instance);

	if (we_cipher == IW_AUTH_CIPHER_TKIP)
		caps |= NM_802_11_CAP_CIPHER_TKIP;
	else if (we_cipher == IW_AUTH_CIPHER_CCMP)
		caps |= NM_802_11_CAP_CIPHER_CCMP;
	else if (we_cipher == NM_AUTH_TYPE_WPA_PSK_AUTO)
		caps |= (NM_802_11_CAP_CIPHER_TKIP | NM_802_11_CAP_CIPHER_CCMP);

	if (self->priv->wpa_version == IW_AUTH_WPA_VERSION_WPA)
		caps |= NM_802_11_CAP_PROTO_WPA;
	else if (self->priv->wpa_version == IW_AUTH_WPA_VERSION_WPA2)
		caps |= NM_802_11_CAP_PROTO_WPA2;

	if (self->priv->key_mgt == IW_AUTH_KEY_MGMT_PSK)
		caps |= NM_802_11_CAP_KEY_MGMT_PSK;
	return caps;
}

static gboolean
real_get_authentication_required (NMAPSecurity *instance)
{
	/* WPA Personal always requires authentication in the infrastructure mode. */
	return TRUE;
}

static NMAPSecurity *
real_copy_constructor (NMAPSecurity *instance)
{
	NMAPSecurityWPA_PSK * dst = g_object_new (NM_TYPE_AP_SECURITY_WPA_PSK, NULL);
	NMAPSecurityWPA_PSK * self = NM_AP_SECURITY_WPA_PSK (instance);

	dst->priv->wpa_version = self->priv->wpa_version;
	dst->priv->key_mgt = self->priv->key_mgt;
	nm_ap_security_copy_properties (NM_AP_SECURITY (self), NM_AP_SECURITY (dst));
	return NM_AP_SECURITY (dst);
}

static void
nm_ap_security_wpa_psk_init (NMAPSecurityWPA_PSK * self)
{
	self->priv = NM_AP_SECURITY_WPA_PSK_GET_PRIVATE (self);
	self->priv->wpa_version = IW_AUTH_WPA_VERSION_WPA;
	self->priv->key_mgt = IW_AUTH_KEY_MGMT_PSK;
}

static void
nm_ap_security_wpa_psk_class_init (NMAPSecurityWPA_PSKClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMAPSecurityClass *par_class = NM_AP_SECURITY_CLASS (klass);

	par_class->copy_constructor_func = real_copy_constructor;
	par_class->serialize_func = real_serialize;
	par_class->write_supplicant_config_func = real_write_supplicant_config;
	par_class->get_default_capabilities_func = real_get_default_capabilities;
	par_class->get_authentication_required_func = real_get_authentication_required;

	g_type_class_add_private (object_class, sizeof (NMAPSecurityWPA_PSKPrivate));
}

GType
nm_ap_security_wpa_psk_get_type (void)
{
	static GType type = 0;
	if (type == 0) {
		static const GTypeInfo info = {
			sizeof (NMAPSecurityWPA_PSKClass),
			NULL,	/* base_init */
			NULL,	/* base_finalize */
			(GClassInitFunc) nm_ap_security_wpa_psk_class_init,
			NULL,	/* class_finalize */
			NULL,	/* class_data */
			sizeof (NMAPSecurityWPA_PSK),
			0,		/* n_preallocs */
			(GInstanceInitFunc) nm_ap_security_wpa_psk_init,
			NULL		/* value_table */
		};
		type = g_type_register_static (NM_TYPE_AP_SECURITY,
					       		 "NMAPSecurityWPA_PSK",
					       		 &info, 0);
	}
	return type;
}
