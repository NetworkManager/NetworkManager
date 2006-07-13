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
#include "NetworkManagerMain.h"
#include "NetworkManagerAP.h"
#include "nm-device.h"
#include "nm-device-802-11-wireless.h"

typedef struct NMAccessPointList	NMAccessPointList;
typedef struct NMAPListIter		NMAPListIter;

NMAccessPointList *	nm_ap_list_new					(NMNetworkType type);
void				nm_ap_list_ref					(NMAccessPointList *list);
void				nm_ap_list_unref				(NMAccessPointList *list);

guint			nm_ap_list_size				(NMAccessPointList *list);
gboolean			nm_ap_list_is_empty				(NMAccessPointList *list);

void				nm_ap_list_append_ap			(NMAccessPointList *list, NMAccessPoint *ap);
void				nm_ap_list_remove_ap			(NMAccessPointList *list, NMAccessPoint *ap);
void				nm_ap_list_remove_ap_by_essid		(NMAccessPointList *list, const char *network);
void				nm_ap_list_remove_duplicate_essids	(NMAccessPointList *list);

NMAccessPoint *	nm_ap_list_get_ap_by_essid		(NMAccessPointList *list, const char *network);
NMAccessPoint *	nm_ap_list_get_ap_by_address		(NMAccessPointList *list, const struct ether_addr *addr);

void				nm_ap_list_copy_properties		(NMAccessPointList *dest, NMAccessPointList *source);
void				nm_ap_list_copy_essids_by_address	(NMData *app_data, NMDevice80211Wireless *dev, NMAccessPointList *dest, NMAccessPointList *source);
void				nm_ap_list_copy_one_essid_by_address	(NMData *app_data, NMDevice80211Wireless *dev, NMAccessPoint *ap, NMAccessPointList *search_list);

gboolean			nm_ap_list_merge_scanned_ap		(NMDevice80211Wireless *dev, NMAccessPointList *list, NMAccessPoint *merge_ap);

NMNetworkType		nm_ap_list_get_type				(NMAccessPointList *list);

gboolean			nm_ap_list_lock				(NMAccessPointList *list);
void				nm_ap_list_unlock				(NMAccessPointList *list);

NMAPListIter *		nm_ap_list_iter_new				(NMAccessPointList *list);
NMAccessPoint *	nm_ap_list_iter_get_ap			(NMAPListIter *iter);
NMAccessPoint *	nm_ap_list_iter_next			(NMAPListIter *iter);
void				nm_ap_list_iter_free			(NMAPListIter *iter);

void				nm_ap_list_print_members			(NMAccessPointList *list, const char *name);

#endif
