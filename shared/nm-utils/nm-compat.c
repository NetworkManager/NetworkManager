/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * (C) Copyright 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-compat.h"

/*****************************************************************************/

static void
_get_keys_cb (const char *key, const char *val, gpointer user_data)
{
	GPtrArray *a = user_data;

	g_ptr_array_add (a, g_strdup (key));
}

static const char **
_get_keys (NMSettingVpn *setting,
           gboolean is_secrets,
           guint *out_length)
{
	guint len;
	const char **keys = NULL;
	GPtrArray *a;

	nm_assert (NM_IS_SETTING_VPN (setting));

	if (is_secrets)
		len = nm_setting_vpn_get_num_secrets (setting);
	else
		len = nm_setting_vpn_get_num_data_items (setting);

	a = g_ptr_array_sized_new (len + 1);

	if (is_secrets)
		nm_setting_vpn_foreach_secret (setting, _get_keys_cb, a);
	else
		nm_setting_vpn_foreach_data_item (setting, _get_keys_cb, a);

	len = a->len;
	if (len) {
		g_ptr_array_sort (a, nm_strcmp_p);
		g_ptr_array_add (a, NULL);
		keys = g_memdup (a->pdata, a->len * sizeof (gpointer));

		/* we need to cache the keys *somewhere*. */
		g_object_set_qdata_full (G_OBJECT (setting),
		                         is_secrets
		                         ? NM_CACHED_QUARK ("libnm._nm_setting_vpn_get_secret_keys")
		                         : NM_CACHED_QUARK ("libnm._nm_setting_vpn_get_data_keys"),
		                         g_ptr_array_free (a, FALSE),
		                         (GDestroyNotify) g_strfreev);
	} else
		g_ptr_array_free (a, TRUE);

	NM_SET_OUT (out_length, len);
	return keys;
}

const char **
_nm_setting_vpn_get_data_keys (NMSettingVpn *setting,
                               guint *out_length)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), NULL);

	return _get_keys (setting, FALSE, out_length);
}

const char **
_nm_setting_vpn_get_secret_keys (NMSettingVpn *setting,
                                 guint *out_length)
{
	g_return_val_if_fail (NM_IS_SETTING_VPN (setting), NULL);

	return _get_keys (setting, TRUE, out_length);
}
