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

typedef enum NMAPEncMethod
{
	NM_AP_ENC_METHOD_UNKNOWN = 0,
	NM_AP_ENC_METHOD_NONE,
	NM_AP_ENC_METHOD_HEX_KEY,
	NM_AP_ENC_METHOD_40_BIT_PASSPHRASE,
	NM_AP_ENC_METHOD_104_BIT_PASSPHRASE
} NMAPEncMethod;


NMAccessPoint *	nm_ap_new				(void);
NMAccessPoint *	nm_ap_new_from_ap			(NMAccessPoint *ap);

void				nm_ap_unref				(NMAccessPoint *ap);
void				nm_ap_ref				(NMAccessPoint *ap);

const GTimeVal *	nm_ap_get_timestamp		(NMAccessPoint *ap);
void				nm_ap_set_timestamp		(NMAccessPoint *ap, const GTimeVal *timestamp);

gchar *			nm_ap_get_essid			(NMAccessPoint *ap);
void				nm_ap_set_essid			(NMAccessPoint *ap, gchar *essid);

gchar *			nm_ap_get_enc_key_source	(NMAccessPoint *ap);
gchar *			nm_ap_get_enc_key_hashed	(NMAccessPoint *ap, NMAPEncMethod method);
void				nm_ap_set_enc_key_source	(NMAccessPoint *ap, gchar *key);

gboolean			nm_ap_get_encrypted		(NMAccessPoint *ap);
void				nm_ap_set_encrypted		(NMAccessPoint *ap, gboolean encrypted);

struct ether_addr *	nm_ap_get_address			(NMAccessPoint *ap);
void				nm_ap_set_address			(NMAccessPoint *ap, const struct ether_addr *addr);

guint8			nm_ap_get_quality			(NMAccessPoint *ap);
void				nm_ap_set_quality			(NMAccessPoint *ap, guint8 quality);

double			nm_ap_get_freq			(NMAccessPoint *ap);
void				nm_ap_set_freq			(NMAccessPoint *ap, double freq);

guint16			nm_ap_get_rate			(NMAccessPoint *ap);
void				nm_ap_set_rate			(NMAccessPoint *ap, guint16 rate);

gboolean			nm_ap_get_invalid			(NMAccessPoint *ap);
void				nm_ap_set_invalid			(NMAccessPoint *ap, gboolean invalid);

gboolean			nm_ap_get_matched			(NMAccessPoint *ap);
void				nm_ap_set_matched			(NMAccessPoint *ap, gboolean matched);

NMAPEncMethod		nm_ap_get_enc_method		(NMAccessPoint *ap);
void				nm_ap_set_enc_method		(NMAccessPoint *ap, NMAPEncMethod enc_method);

gboolean			nm_ap_get_enc_method_good	(NMAccessPoint *ap);
void				nm_ap_set_enc_method_good	(NMAccessPoint *ap, gboolean good);

gboolean			nm_ap_get_trusted			(NMAccessPoint *ap);
void				nm_ap_set_trusted			(NMAccessPoint *ap, gboolean trusted);

#endif
