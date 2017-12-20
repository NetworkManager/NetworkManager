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

	g_ptr_array_add (a, (gpointer) key);
}

static const char **
_get_keys (NMSettingVpn *setting,
           gboolean is_secrets,
           guint *out_length)
{
	guint len;
	const char **keys = NULL;
	gs_unref_ptrarray GPtrArray *a = NULL;

	nm_assert (NM_IS_SETTING_VPN (setting));

	a = g_ptr_array_new ();
	if (is_secrets)
		nm_setting_vpn_foreach_secret (setting, _get_keys_cb, a);
	else
		nm_setting_vpn_foreach_data_item (setting, _get_keys_cb, a);
	len = a->len;

	if (a->len) {
		g_ptr_array_sort (a, nm_strcmp_p);
		g_ptr_array_add (a, NULL);
		keys = (const char **) g_ptr_array_free (g_steal_pointer (&a), FALSE);
	}

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
