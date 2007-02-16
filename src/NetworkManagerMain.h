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
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifndef NETWORK_MANAGER_MAIN_H
#define NETWORK_MANAGER_MAIN_H

#include <glib.h>
#include <glib/gthread.h>
#include <dbus/dbus.h>
#include "NetworkManager.h"
#include "NetworkManagerAP.h"
#include "nm-netlink-monitor.h"
#include "nm-named-manager.h"
#include "nm-device.h"
#include "NetworkManagerDbusUtils.h"


typedef struct NMActRequest NMActRequest;
typedef struct NMVPNActRequest NMVPNActRequest;
typedef struct NMVPNManager NMVPNManager;

typedef struct NMData
{
	GIOChannel *			sigterm_iochannel;
	int					sigterm_pipe[2];

	NmNetlinkMonitor *		netlink_monitor;

	NMNamedManager *		named_manager;
	NMVPNManager *			vpn_manager;
	guint32                 nmi_sig_handler_id;

	GMainLoop *			main_loop;

	guint				dev_change_check_idle_id;

	GSList *				dev_list;

	gboolean				wireless_enabled;
	gboolean				modem_active;
	gboolean				asleep;

	GSList *				dialup_list;

	struct NMAccessPointList	*allowed_ap_list;
	struct NMAccessPointList	*invalid_ap_list;
} NMData;


void			nm_schedule_state_change_signal_broadcast	(NMData *data);

int			nm_get_sigterm_pipe						(void);

#endif
