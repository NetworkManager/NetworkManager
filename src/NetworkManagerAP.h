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

#ifndef NETWORK_MANAGER_AP_H
#define NETWORK_MANAGER_AP_H

#include <glib.h>
#include <time.h>
#include "NetworkManager.h"
#include "wpa.h"
#include "nm-ap-security.h"

typedef struct NMAccessPoint NMAccessPoint;


NMAccessPoint *	nm_ap_new				(void);
NMAccessPoint *	nm_ap_new_from_ap		(NMAccessPoint *ap);

void				nm_ap_unref			(NMAccessPoint *ap);
void				nm_ap_ref				(NMAccessPoint *ap);

const GTimeVal *	nm_ap_get_timestamp				(const NMAccessPoint *ap);
void				nm_ap_set_timestamp				(NMAccessPoint *ap, glong sec, glong usec);
void				nm_ap_set_timestamp_via_timestamp	(NMAccessPoint *ap, const GTimeVal *timestamp);

const char *		nm_ap_get_essid		(const NMAccessPoint *ap);
void				nm_ap_set_essid		(NMAccessPoint *ap, const char *essid);
/* Get essid in original over-the-air form */
const char *		nm_ap_get_orig_essid	(const NMAccessPoint *ap);

guint32			nm_ap_get_capabilities	(NMAccessPoint *ap);
void				nm_ap_set_capabilities	(NMAccessPoint *ap, guint32 capabilities);

gboolean			nm_ap_get_encrypted		(const NMAccessPoint *ap);

NMAPSecurity *		nm_ap_get_security		(const NMAccessPoint *ap);
void				nm_ap_set_security		(NMAccessPoint *ap, NMAPSecurity *security);

const struct ether_addr * nm_ap_get_address	(const NMAccessPoint *ap);
void				nm_ap_set_address		(NMAccessPoint *ap, const struct ether_addr *addr);

int				nm_ap_get_mode			(const NMAccessPoint *ap);
void				nm_ap_set_mode			(NMAccessPoint *ap, const int mode);

gint8			nm_ap_get_strength		(const NMAccessPoint *ap);
void				nm_ap_set_strength		(NMAccessPoint *ap, gint8 strength);

double			nm_ap_get_freq			(const NMAccessPoint *ap);
void				nm_ap_set_freq			(NMAccessPoint *ap, double freq);

guint16			nm_ap_get_rate			(const NMAccessPoint *ap);
void				nm_ap_set_rate			(NMAccessPoint *ap, guint16 rate);

gboolean			nm_ap_get_invalid		(const NMAccessPoint *ap);
void				nm_ap_set_invalid		(NMAccessPoint *ap, gboolean invalid);

gboolean			nm_ap_get_trusted		(const NMAccessPoint *ap);
void				nm_ap_set_trusted		(NMAccessPoint *ap, gboolean trusted);

gboolean			nm_ap_get_artificial	(const NMAccessPoint *ap);
void				nm_ap_set_artificial	(NMAccessPoint *ap, gboolean artificial);

gboolean			nm_ap_get_broadcast		(const NMAccessPoint *ap);
void				nm_ap_set_broadcast		(NMAccessPoint *ap, gboolean broadcast);

const GTimeVal *	nm_ap_get_last_seen		(const NMAccessPoint *ap);
void				nm_ap_set_last_seen		(NMAccessPoint *ap, const GTimeVal *last_seen);

gboolean			nm_ap_get_user_created	(const NMAccessPoint *ap);
void				nm_ap_set_user_created	(NMAccessPoint *ap, gboolean user_created);

GSList *			nm_ap_get_user_addresses	(const NMAccessPoint *ap);
void				nm_ap_set_user_addresses (NMAccessPoint *ap, GSList *list);

void				nm_ap_add_capabilities_from_security (NMAccessPoint *ap, NMAPSecurity *security);
void				nm_ap_add_capabilities_from_ie (NMAccessPoint *ap, const guint8 *wpa_ie, guint32 length);
void				nm_ap_add_capabilities_for_wep (NMAccessPoint *ap);

/* 
 * NOTE:
 * This is not intended to return true for all APs with manufacturer defaults.  It is intended to return true for
 * only the MOST COMMON manufacturing defaults.
 */
gboolean			nm_ap_has_manufacturer_default_essid	(NMAccessPoint *ap);

#endif
