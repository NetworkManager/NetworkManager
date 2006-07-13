/* NetworkManager -- Network link manager
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
 * (C) Copyright 2006 Thiago Jung Bauermann <thiago.bauermann@gmail.com>
 */

/* This file is heavily based on nm-ap-security-wpa-eap.h */

#ifndef NM_AP_SECURITY_LEAP_H
#define NM_AP_SECURITY_LEAP_H

#include <glib-object.h>
#include <dbus/dbus.h>
#include "nm-ap-security.h"

#define NM_TYPE_AP_SECURITY_LEAP			(nm_ap_security_leap_get_type ())
#define NM_AP_SECURITY_LEAP(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_AP_SECURITY_LEAP, NMAPSecurityLEAP))
#define NM_AP_SECURITY_LEAP_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_AP_SECURITY_LEAP, NMAPSecurityLEAPClass))
#define NM_IS_AP_SECURITY_LEAP(obj)			(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_AP_SECURITY_LEAP))
#define NM_IS_AP_SECURITY_LEAP_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_AP_SECURITY_LEAP))
#define NM_AP_SECURITY_LEAP_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_AP_SECURITY_LEAP, NMAPSecurityLEAPClass))

typedef struct _NMAPSecurityLEAP NMAPSecurityLEAP;
typedef struct _NMAPSecurityLEAPClass NMAPSecurityLEAPClass;
typedef struct _NMAPSecurityLEAPPrivate NMAPSecurityLEAPPrivate;

struct _NMAPSecurityLEAP
{
	NMAPSecurity parent;

	/*< private >*/
	NMAPSecurityLEAPPrivate *priv;
};

struct _NMAPSecurityLEAPClass
{
	NMAPSecurityClass parent;
};


GType nm_ap_security_leap_get_type (void);

NMAPSecurityLEAP * nm_ap_security_leap_new_deserialize (DBusMessageIter *iter);

struct NMAccessPoint;
NMAPSecurityLEAP * nm_ap_security_leap_new_from_ap (struct NMAccessPoint *ap);

#endif	/* NM_AP_SECURITY_LEAP_H */
