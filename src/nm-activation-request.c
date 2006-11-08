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
#include "nm-dhcp-manager.h"
#include "nm-utils.h"


struct NMActRequest
{
	int				refcount;
	NMData *			data;
	NMDevice *		dev;
	NMAccessPoint *	ap;
	NMIP4Config *		ip4_config;

	gboolean			user_requested;

	NMActStage		stage;
	DBusPendingCall *	user_key_pcall;

	guint32			dhcp_state;
	guint			dhcp_timeout;
};


NMActRequest * nm_act_request_new (NMData *data, NMDevice *dev, NMAccessPoint *ap, gboolean user_requested)
{
	NMActRequest *	req;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (dev != NULL, NULL);

	if (nm_device_is_802_11_wireless (dev))
		g_return_val_if_fail (ap != NULL, NULL);

	req = g_malloc0 (sizeof (NMActRequest));
	req->refcount = 1;
	req->data = data;

	g_object_ref (G_OBJECT (dev));
	req->dev = dev;

	if (ap)
		nm_ap_ref (ap);
	req->ap = ap;

	req->user_requested = user_requested;
	req->dhcp_state = nm_dhcp_manager_get_state_for_device (data->dhcp_manager, dev);

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
	if (req->refcount <= 0)
	{
		g_object_unref (G_OBJECT (req->dev));
		if (req->ap)
			nm_ap_unref (req->ap);

		if (req->ip4_config)
			nm_ip4_config_unref (req->ip4_config);

		if (req->dhcp_timeout > 0)
		{
			GSource *	source = g_main_context_find_source_by_id (req->data->main_context, req->dhcp_timeout);
			g_source_destroy (source);
		}

		memset (req, 0, sizeof (NMActRequest));
		g_free (req);
	}
}

NMDevice * nm_act_request_get_dev (NMActRequest *req)
{
	g_return_val_if_fail (req != NULL, NULL);

	return req->dev;
}


NMData * nm_act_request_get_data (NMActRequest *req)
{
	g_return_val_if_fail (req != NULL, NULL);

	return req->data;
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
		nm_ip4_config_unref (req->ip4_config);
		req->ip4_config = NULL;
	}
	if (ip4_config)
	{
		nm_ip4_config_ref (ip4_config);
		req->ip4_config = ip4_config;
	}
}

NMActStage nm_act_request_get_stage (NMActRequest *req)
{
	g_return_val_if_fail (req != NULL, NM_ACT_STAGE_UNKNOWN);

	return req->stage;
}

void nm_act_request_set_stage (NMActRequest *req, NMActStage stage)
{
	DBusMessage *		message;
	char *			dev_path;

	g_return_if_fail (req != NULL);

	req->stage = stage;

	g_return_if_fail (req->data);
	g_return_if_fail (req->dev);

	if (!(dev_path = nm_dbus_get_object_path_for_device (req->dev)))
		return;

	if (!(message = dbus_message_new_signal (NM_DBUS_PATH, NM_DBUS_INTERFACE, "DeviceActivationStage")))
	{
		nm_warning ("nm_act_request_set_stage(): Not enough memory for new dbus message!");
		g_free (dev_path);
		return;
	}

	dbus_message_append_args (message, DBUS_TYPE_OBJECT_PATH, &dev_path, DBUS_TYPE_UINT32, &stage, DBUS_TYPE_INVALID);
	g_free (dev_path);

	if (!dbus_connection_send (req->data->dbus_connection, message, NULL))
		nm_warning ("nm_act_request_set_stage(): Could not raise the signal!");

	dbus_message_unref (message);
}

DBusPendingCall * nm_act_request_get_user_key_pending_call (NMActRequest *req)
{
	g_return_val_if_fail (req != NULL, NULL);

	return req->user_key_pcall;
}

void nm_act_request_set_user_key_pending_call (NMActRequest *req, DBusPendingCall *pcall)
{
	g_return_if_fail (req != NULL);

	req->user_key_pcall = pcall;
}

guint8 nm_act_request_get_dhcp_state (NMActRequest *req)
{
	g_return_val_if_fail (req != NULL, 0);

	return req->dhcp_state;
}

void nm_act_request_set_dhcp_state (NMActRequest *req, guint8 dhcp_state)
{
	g_return_if_fail (req != NULL);

	req->dhcp_state = dhcp_state;
}

guint nm_act_request_get_dhcp_timeout (NMActRequest *req)
{
	g_return_val_if_fail (req != NULL, 0);

	return req->dhcp_timeout;
}

void nm_act_request_set_dhcp_timeout (NMActRequest *req, guint dhcp_timeout)
{
	g_return_if_fail (req != NULL);

	req->dhcp_timeout = dhcp_timeout;
}

