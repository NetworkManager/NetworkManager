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

typedef struct NMAccessPoint NMAccessPoint;

NMAccessPoint *	nm_ap_new				(void);
NMAccessPoint *	nm_ap_new_from_ap		(NMAccessPoint *ap);

void				nm_ap_unref			(NMAccessPoint *ap);
void				nm_ap_ref				(NMAccessPoint *ap);

const GTimeVal *	nm_ap_get_timestamp		(const NMAccessPoint *ap);
void				nm_ap_set_timestamp		(NMAccessPoint *ap, const GTimeVal *timestamp);

char *			nm_ap_get_essid		(const NMAccessPoint *ap);
void				nm_ap_set_essid		(NMAccessPoint *ap, const char *essid);

char *			nm_ap_get_enc_key_source	(const NMAccessPoint *ap);
char *			nm_ap_get_enc_key_hashed	(const NMAccessPoint *ap);
void				nm_ap_set_enc_key_source	(NMAccessPoint *ap, const char *key, NMEncKeyType type);
NMEncKeyType	nm_ap_get_enc_type		(const NMAccessPoint *ap);

NMDeviceAuthMethod	nm_ap_get_auth_method	(const NMAccessPoint *ap);
void				nm_ap_set_auth_method	(NMAccessPoint *ap, const NMDeviceAuthMethod auth_method);

gboolean			nm_ap_get_encrypted		(const NMAccessPoint *ap);
void				nm_ap_set_encrypted		(NMAccessPoint *ap, gboolean encrypted);

struct ether_addr *	nm_ap_get_address		(const NMAccessPoint *ap);
void				nm_ap_set_address		(NMAccessPoint *ap, const struct ether_addr *addr);

NMNetworkMode		nm_ap_get_mode			(const NMAccessPoint *ap);
void				nm_ap_set_mode			(NMAccessPoint *ap, const NMNetworkMode mode);

gint8			nm_ap_get_strength		(const NMAccessPoint *ap);
void				nm_ap_set_strength		(NMAccessPoint *ap, gint8 strength);

double			nm_ap_get_freq			(const NMAccessPoint *ap);
void				nm_ap_set_freq			(NMAccessPoint *ap, double freq);

guint16			nm_ap_get_rate			(const NMAccessPoint *ap);
void				nm_ap_set_rate			(NMAccessPoint *ap, guint16 rate);

gboolean			nm_ap_get_invalid		(const NMAccessPoint *ap);
void				nm_ap_set_invalid		(NMAccessPoint *ap, gboolean invalid);

gboolean			nm_ap_get_matched		(const NMAccessPoint *ap);
void				nm_ap_set_matched		(NMAccessPoint *ap, gboolean matched);

gboolean			nm_ap_get_trusted		(const NMAccessPoint *ap);
void				nm_ap_set_trusted		(NMAccessPoint *ap, gboolean trusted);

gboolean			nm_ap_get_artificial	(const NMAccessPoint *ap);
void				nm_ap_set_artificial	(NMAccessPoint *ap, gboolean artificial);

const GTimeVal *	nm_ap_get_last_seen		(const NMAccessPoint *ap);
void				nm_ap_set_last_seen		(NMAccessPoint *ap, const GTimeVal *last_seen);

gboolean			nm_ap_get_user_created	(const NMAccessPoint *ap);
void				nm_ap_set_user_created	(NMAccessPoint *ap, gboolean user_created);

GSList *			nm_ap_get_user_addresses	(const NMAccessPoint *ap);
void				nm_ap_set_user_addresses (NMAccessPoint *ap, GSList *list);

/* Helper */
gboolean			nm_ap_is_enc_key_valid	(NMAccessPoint *ap);
gboolean			nm_is_enc_key_valid		(const char *key, NMEncKeyType key_type);

#endif
