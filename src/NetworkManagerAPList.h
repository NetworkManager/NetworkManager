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

#ifndef NETWORK_MANAGER_AP_LIST_H
#define NETWORK_MANAGER_AP_LIST_H

#include <glib.h>
#include "NetworkManager.h"

NMAccessPoint *nm_ap_list_get_ap_by_essid 	(NMData *data, const char *network);

void			nm_ap_list_update_network	(NMData *data, const char *network);

void			nm_ap_list_populate			(NMData *data);

void			nm_ap_list_free			(GSList *ap_list);

#endif
