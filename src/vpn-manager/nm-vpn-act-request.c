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
#include "nm-vpn-act-request.h"
#include "nm-dbus-vpn.h"


struct NMVPNActRequest
{
	guint			refcount;
	NMVPNActStage		stage;

	NMDevice *		parent_dev;
	NMVPNManager *		manager;
	NMVPNService *		service;
	NMVPNConnection *	vpn;

	char **			password_items;
	int				password_count;
	char **			data_items;
	int				data_count;
	char **			user_routes;
	int				user_routes_count;

	guint			daemon_wait_count;
	guint			callback_id;
	gboolean			canceled;
};


NMVPNActRequest *nm_vpn_act_request_new (NMVPNManager *manager, NMVPNService *service, NMVPNConnection *vpn,
								 NMDevice *parent_dev, char **password_items, int password_count,
								  char **data_items, int data_count, char **user_routes, int user_routes_count)
{
	NMVPNActRequest	*req;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (service != NULL, NULL);
	g_return_val_if_fail (vpn != NULL, NULL);
	g_return_val_if_fail (parent_dev != NULL, NULL);
	g_return_val_if_fail (password_items != NULL, NULL);
	g_return_val_if_fail (data_items != NULL, NULL);

	req = g_malloc0 (sizeof (NMVPNActRequest));
	req->refcount = 1;
	req->stage = NM_VPN_ACT_STAGE_PREPARE;

	req->manager = manager;
	g_object_ref (G_OBJECT (parent_dev));
	req->parent_dev = parent_dev;
	nm_vpn_service_ref (service);
	req->service = service;
	nm_vpn_connection_ref (vpn);
	req->vpn = vpn;

	req->password_items = g_strdupv (password_items);
	req->password_count = password_count;
	req->data_items = g_strdupv (data_items);
	req->data_count = data_count;
	req->user_routes = g_strdupv (user_routes);
	req->user_routes_count = user_routes_count;

	return req;
}


void nm_vpn_act_request_ref (NMVPNActRequest *req)
{
	g_return_if_fail (req != NULL);

	req->refcount++;
}


void nm_vpn_act_request_unref (NMVPNActRequest *req)
{
	g_return_if_fail (req != NULL);

	req->refcount--;
	if (req->refcount == 0)
	{
		g_object_unref (G_OBJECT (req->parent_dev));
		nm_vpn_service_unref (req->service);
		nm_vpn_connection_unref (req->vpn);

		g_strfreev (req->password_items);
		g_strfreev (req->data_items);

		memset (req, 0, sizeof (NMVPNActRequest));
		g_free (req);
	}
}

gboolean nm_vpn_act_request_is_activating (NMVPNActRequest *req)
{
	gboolean	activating = FALSE;

	g_return_val_if_fail (req != NULL, FALSE);

	switch (req->stage)
	{
		case NM_VPN_ACT_STAGE_PREPARE:
		case NM_VPN_ACT_STAGE_CONNECT:
		case NM_VPN_ACT_STAGE_IP_CONFIG_GET:
			activating = TRUE;
			break;

		default:
			break;			
	}

	return activating;
}

gboolean nm_vpn_act_request_is_activated (NMVPNActRequest *req)
{
	g_return_val_if_fail (req != NULL, FALSE);
	
	return (req->stage == NM_VPN_ACT_STAGE_ACTIVATED) ? TRUE : FALSE;
}

gboolean nm_vpn_act_request_is_failed (NMVPNActRequest *req)
{
	g_return_val_if_fail (req != NULL, FALSE);
	
	return (req->stage == NM_VPN_ACT_STAGE_FAILED) ? TRUE : FALSE;
}

NMVPNManager *nm_vpn_act_request_get_manager (NMVPNActRequest *req)
{
	g_return_val_if_fail (req != NULL, NULL);

	return req->manager;
}

NMVPNService * nm_vpn_act_request_get_service (NMVPNActRequest *req)
{
	g_return_val_if_fail (req != NULL, NULL);

	return req->service;
}


NMVPNConnection * nm_vpn_act_request_get_connection (NMVPNActRequest *req)
{
	g_return_val_if_fail (req != NULL, NULL);

	return req->vpn;
}

NMDevice *nm_vpn_act_request_get_parent_dev (NMVPNActRequest *req)
{
	g_return_val_if_fail (req != NULL, NULL);

	return req->parent_dev;
}

const char ** nm_vpn_act_request_get_password_items (NMVPNActRequest *req, guint *count)
{
	g_return_val_if_fail (req != NULL, NULL);
	g_return_val_if_fail (count != NULL, NULL);

	*count = req->password_count;
	return (const char **) (req->password_items);
}

const char ** nm_vpn_act_request_get_data_items (NMVPNActRequest *req, guint *count)
{
	g_return_val_if_fail (req != NULL, NULL);
	g_return_val_if_fail (count != NULL, NULL);

	*count = req->data_count;
	return (const char **) (req->data_items);
}

const char ** nm_vpn_act_request_get_user_routes (NMVPNActRequest *req, guint *count)
{
	g_return_val_if_fail (req != NULL, NULL);
	g_return_val_if_fail (count != NULL, NULL);

	*count = req->user_routes_count;
	return (const char **) (req->user_routes);
}

void nm_vpn_act_request_cancel (NMVPNActRequest *req)
{
	g_return_if_fail (req != NULL);

	req->canceled = TRUE;
}

gboolean nm_vpn_act_request_should_cancel (NMVPNActRequest *req)
{
	g_return_val_if_fail (req != NULL, FALSE);

	return req->canceled;
}

NMVPNActStage nm_vpn_act_request_get_stage (NMVPNActRequest *req)
{
	g_return_val_if_fail (req != NULL, NM_VPN_ACT_STAGE_UNKNOWN);

	return req->stage;
}

void nm_vpn_act_request_set_stage (NMVPNActRequest *req, NMVPNActStage stage)
{
	NMVPNActStage	old_stage;

	g_return_if_fail (req != NULL);

	old_stage = req->stage;
	if (old_stage != stage)
	{
		DBusConnection *dbus_connection = nm_vpn_service_get_dbus_connection (req->service);

		req->stage = stage;
		nm_dbus_vpn_signal_vpn_connection_state_change (dbus_connection, req->vpn, req->stage);
	}
}

guint nm_vpn_act_request_get_daemon_wait_count (NMVPNActRequest *req)
{
	g_return_val_if_fail (req != NULL, 0);

	return req->daemon_wait_count;
}

void nm_vpn_act_request_set_daemon_wait_count (NMVPNActRequest *req, guint count)
{
	g_return_if_fail (req != NULL);

	req->daemon_wait_count = count;
}

guint nm_vpn_act_request_get_callback_id (NMVPNActRequest *req)
{
	g_return_val_if_fail (req != NULL, 0);

	return req->callback_id;
}

void nm_vpn_act_request_set_callback_id (NMVPNActRequest *req, guint id)
{
	g_return_if_fail (req != NULL);

	req->callback_id = id;
}

