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

#ifndef NM_VPN_ACT_REQUEST_H
#define NM_VPN_ACT_REQUEST_H

#include <glib.h>
#include "NetworkManager.h"
#include "nm-vpn-service.h"
#include "nm-vpn-connection.h"


NMVPNActRequest *	nm_vpn_act_request_new			(NMVPNManager *manager, NMVPNService *service, NMVPNConnection *vpn,
						NMDevice *parent_dev, char **password_items, int password_count, char **data_items, int data_count,
						char **user_routes, int user_routes_count);
void				nm_vpn_act_request_ref			(NMVPNActRequest *req);
void				nm_vpn_act_request_unref			(NMVPNActRequest *req);

gboolean			nm_vpn_act_request_is_activating	(NMVPNActRequest *req);
gboolean			nm_vpn_act_request_is_activated	(NMVPNActRequest *req);
gboolean			nm_vpn_act_request_is_failed		(NMVPNActRequest *req);

NMVPNManager *		nm_vpn_act_request_get_manager	(NMVPNActRequest *req);
NMVPNService *		nm_vpn_act_request_get_service	(NMVPNActRequest *req);
NMVPNConnection *	nm_vpn_act_request_get_connection	(NMVPNActRequest *req);
NMDevice *		nm_vpn_act_request_get_parent_dev	(NMVPNActRequest *req);

const char **		nm_vpn_act_request_get_password_items	(NMVPNActRequest *req, guint *count);
const char **		nm_vpn_act_request_get_data_items	(NMVPNActRequest *req, guint *count);
const char **		nm_vpn_act_request_get_user_routes	(NMVPNActRequest *req, guint *count);

void				nm_vpn_act_request_cancel		(NMVPNActRequest *req);
gboolean			nm_vpn_act_request_should_cancel	(NMVPNActRequest *req);

NMVPNActStage		nm_vpn_act_request_get_stage		(NMVPNActRequest *req);
void				nm_vpn_act_request_set_stage		(NMVPNActRequest *req, NMVPNActStage stage);

guint			nm_vpn_act_request_get_daemon_wait_count	(NMVPNActRequest *req);
void				nm_vpn_act_request_set_daemon_wait_count	(NMVPNActRequest *req, guint count);

guint			nm_vpn_act_request_get_callback_id	(NMVPNActRequest *req);
void				nm_vpn_act_request_set_callback_id	(NMVPNActRequest *req, guint timeout);

#endif
