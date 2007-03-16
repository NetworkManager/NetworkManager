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
#include <string.h>
#include <dbus/dbus.h>
#include "nm-activation-request.h"
#include "nm-device.h"
#include "NetworkManagerDbus.h"
#include "nm-dbus-manager.h"
#include "nm-utils.h"


struct NMActRequest
{
	int				refcount;
	NMDevice *		dev;
	NMAccessPoint *	ap;
	NMIP4Config *		ip4_config;

	gboolean			user_requested;

	DBusPendingCall *	user_key_pcall;
};


NMActRequest * nm_act_request_new (NMDevice *dev, NMAccessPoint *ap, gboolean user_requested)
{
	NMActRequest *	req;

	g_return_val_if_fail (dev != NULL, NULL);

	if (NM_IS_DEVICE_802_11_WIRELESS (dev))
		g_return_val_if_fail (ap != NULL, NULL);

	req = g_malloc0 (sizeof (NMActRequest));
	req->refcount = 1;

	g_object_ref (G_OBJECT (dev));
	req->dev = dev;
	req->ap = ap ? g_object_ref (ap) : NULL;
	req->user_requested = user_requested;

	return req;
}

void nm_act_request_ref (NMActRequest *req)
{
	g_return_if_fail (req != NULL);

	req->refcount++;
}


void nm_act_request_unref (NMActRequest *req)
{
	g_return_if_fail (req != NULL);

	req->refcount--;
	if (req->refcount <= 0) {
		g_object_unref (G_OBJECT (req->dev));
		if (req->ap)
			g_object_unref (req->ap);

		memset (req, 0, sizeof (NMActRequest));
		g_free (req);
	}
}

NMDevice * nm_act_request_get_dev (NMActRequest *req)
{
	g_return_val_if_fail (req != NULL, NULL);

	return req->dev;
}


NMAccessPoint * nm_act_request_get_ap (NMActRequest *req)
{
	g_return_val_if_fail (req != NULL, NULL);

	return req->ap;
}


gboolean nm_act_request_get_user_requested (NMActRequest *req)
{
	g_return_val_if_fail (req != NULL, FALSE);

	return req->user_requested;
}


NMIP4Config * nm_act_request_get_ip4_config (NMActRequest *req)
{
	g_return_val_if_fail (req != NULL, NULL);

	return req->ip4_config;
}

void nm_act_request_set_ip4_config (NMActRequest *req, NMIP4Config *ip4_config)
{
	g_return_if_fail (req != NULL);

	if (req->ip4_config)
	{
		g_object_unref (req->ip4_config);
		req->ip4_config = NULL;
	}

	if (ip4_config)
		req->ip4_config = g_object_ref (ip4_config);
}

DBusPendingCall * nm_act_request_get_user_key_pending_call (NMActRequest *req)
{
	g_return_val_if_fail (req != NULL, NULL);

	return req->user_key_pcall;
}

void nm_act_request_set_user_key_pending_call (NMActRequest *req, DBusPendingCall *pcall)
{
	g_return_if_fail (req != NULL);

	if (req->user_key_pcall)
		dbus_pending_call_unref (req->user_key_pcall);
	req->user_key_pcall = pcall;
	if (req->user_key_pcall)
		dbus_pending_call_ref (req->user_key_pcall);
}
