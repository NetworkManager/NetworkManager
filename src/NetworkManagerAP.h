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

typedef struct NMAccessPoint NMAccessPoint;

#define	NM_AP_PRIORITY_WORST		1000


NMAccessPoint		*nm_ap_new				(void);
NMAccessPoint		*nm_ap_new_from_ap			(NMAccessPoint *ap);

void				 nm_ap_unref				(NMAccessPoint *ap);
void				 nm_ap_ref				(NMAccessPoint *ap);

guint			 nm_ap_get_priority			(NMAccessPoint *ap);
void				 nm_ap_set_priority			(NMAccessPoint *ap, guint priority);

gchar *			 nm_ap_get_essid			(NMAccessPoint *ap);
void				 nm_ap_set_essid			(NMAccessPoint *ap, gchar * essid);

gchar *			 nm_ap_get_wep_key			(NMAccessPoint *ap);
void				 nm_ap_set_wep_key			(NMAccessPoint *ap, gchar * wep_key);

gchar *			 nm_ap_get_address			(NMAccessPoint *ap);
void				 nm_ap_set_address			(NMAccessPoint *ap, gchar * address);

guint8			 nm_ap_get_quality			(NMAccessPoint *ap);
void				 nm_ap_set_quality			(NMAccessPoint *ap, guint8 quality);

double			 nm_ap_get_freq			(NMAccessPoint *ap);
void				 nm_ap_set_freq			(NMAccessPoint *ap, double freq);

guint16			 nm_ap_get_rate			(NMAccessPoint *ap);
void				 nm_ap_set_rate			(NMAccessPoint *ap, guint16 rate);

time_t			 nm_ap_get_stamp			(NMAccessPoint *ap);
void				 nm_ap_set_stamp			(NMAccessPoint *ap, time_t stamp);

#endif
