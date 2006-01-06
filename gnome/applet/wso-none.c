/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
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

#include <dbus/dbus.h>

#include "wireless-security-option.h"
#include "wso-none.h"
#include "wso-private.h"
#include "cipher.h"
#include "dbus-helpers.h"


static gboolean validate_input_func (WirelessSecurityOption *opt, const char *ssid, IEEE_802_11_Cipher ** out_cipher)
{
	g_return_val_if_fail (opt != NULL, FALSE);

	return TRUE;
}

static gboolean append_dbus_params_func (WirelessSecurityOption *opt, const char *ssid, DBusMessage *message)
{
	g_return_val_if_fail (opt != NULL, FALSE);

	nmu_security_serialize_none_with_cipher (message);
	return TRUE;
}

WirelessSecurityOption * wso_none_new (const char *glade_file)
{
	WirelessSecurityOption * opt = NULL;

	g_return_val_if_fail (glade_file != NULL, NULL);

	opt = g_malloc0 (sizeof (WirelessSecurityOption));
	opt->name = g_strdup (_("None"));
	opt->validate_input_func = validate_input_func;
	opt->append_dbus_params_func = append_dbus_params_func;
	return opt;
}


