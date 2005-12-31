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

#ifndef NM_ACTIVATION_REQUEST_H
#define NM_ACTIVATION_REQUEST_H

#include <glib.h>
#include <dbus/dbus.h>
#include "NetworkManager.h"
#include "NetworkManagerMain.h"
#include "nm-device.h"
#include "NetworkManagerAP.h"
#include "nm-ip4-config.h"



NMActRequest *		nm_act_request_new				(NMData *data, NMDevice *dev, NMAccessPoint *ap, gboolean user_requested);
void				nm_act_request_ref				(NMActRequest *req);
void				nm_act_request_unref			(NMActRequest *req);

NMDevice *		nm_act_request_get_dev			(NMActRequest *req);
NMData *			nm_act_request_get_data			(NMActRequest *req);
NMAccessPoint *	nm_act_request_get_ap			(NMActRequest *req);
gboolean			nm_act_request_get_user_requested	(NMActRequest *req);

NMIP4Config *		nm_act_request_get_ip4_config		(NMActRequest *req);
void				nm_act_request_set_ip4_config		(NMActRequest *req, NMIP4Config *ip4_config);

NMActStage		nm_act_request_get_stage			(NMActRequest *req);
void				nm_act_request_set_stage			(NMActRequest *req, NMActStage stage);

DBusPendingCall *	nm_act_request_get_user_key_pending_call	(NMActRequest *req);
void				nm_act_request_set_user_key_pending_call	(NMActRequest *req, DBusPendingCall *pcall);

guint8			nm_act_request_get_dhcp_state		(NMActRequest *req);
void				nm_act_request_set_dhcp_state		(NMActRequest *req, guint8 dhcp_state);

guint			nm_act_request_get_dhcp_timeout	(NMActRequest *req);
void				nm_act_request_set_dhcp_timeout	(NMActRequest *req, guint dhcp_timeout);

#endif
