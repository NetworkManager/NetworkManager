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
#include "NetworkManagerDevice.h"

typedef enum
{
	NETWORK_TYPE_UNKNOWN = 0,
	NETWORK_TYPE_ALLOWED,
	NETWORK_TYPE_INVALID,
	NETWORK_TYPE_DEVICE
} NMNetworkType;

typedef struct NMAccessPointList	NMAccessPointList;
typedef struct NMAPListIter		NMAPListIter;

NMAccessPointList *	nm_ap_list_new				(NMNetworkType type);
void				nm_ap_list_ref				(NMAccessPointList *list);
void				nm_ap_list_unref			(NMAccessPointList *list);

void				nm_ap_list_append_ap		(NMAccessPointList *list, NMAccessPoint *ap);
void				nm_ap_list_remove_ap		(NMAccessPointList *list, NMAccessPoint *ap);

NMAccessPoint *	nm_ap_list_get_ap_by_essid	(NMAccessPointList *list, const char *network);

void				nm_ap_list_update_network	(NMAccessPointList *list, const char *network, NMData *data);

void				nm_ap_list_populate			(NMAccessPointList *list, NMData *data);

void				nm_ap_list_diff			(NMData *data, NMDevice *dev, NMAccessPointList *old, NMAccessPointList *new);

gboolean			nm_ap_list_lock			(NMAccessPointList *list);
void				nm_ap_list_unlock			(NMAccessPointList *list);

NMAPListIter *		nm_ap_list_iter_new			(NMAccessPointList *list);
NMAccessPoint *	nm_ap_list_iter_get_ap		(NMAPListIter *iter);
NMAccessPoint *	nm_ap_list_iter_next		(NMAPListIter *iter);
void				nm_ap_list_iter_free		(NMAPListIter *iter);

void				nm_ap_list_print_members		(NMAccessPointList *list, const char *name);

#endif
