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

#ifndef NETWORK_MANAGER_H
#define NETWORK_MANAGER_H

#include <glib.h>
#include <glib/gthread.h>
#include <hal/libhal.h>
#include "NetworkManagerAP.h"

struct NMData
{
	LibHalContext				*hal_ctx;
	GSList					*dev_list;
	GMutex					*dev_list_mutex;
	struct NMDevice			*active_device;
	gboolean					 state_modified;
	GMutex					*state_modified_mutex;
	GSList					*allowed_ap_list;
	GMutex					*allowed_ap_list_mutex;
	DBusConnection				*dbus_connection;
};

typedef struct NMData NMData;

void		 nm_data_set_state_modified	(NMData *data, gboolean modified);

void		 nm_data_allowed_ap_list_free	(NMData *data);

NMData	*nm_get_global_data			(void);

#endif
