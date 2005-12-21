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
 * (C) Copyright 2005 Red Hat, Inc.
 */

#ifndef NM_AP_SECURITY_WEP_H
#define NM_AP_SECURITY_WEP_H

#include <glib-object.h>
#include <dbus/dbus.h>
#include "nm-ap-security.h"

#define NM_TYPE_AP_SECURITY_WEP			(nm_ap_security_wep_get_type ())
#define NM_AP_SECURITY_WEP(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_AP_SECURITY_WEP, NMAPSecurityWEP))
#define NM_AP_SECURITY_WEP_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_AP_SECURITY_WEP, NMAPSecurityWEPClass))
#define NM_IS_AP_SECURITY_WEP(obj)			(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_AP_SECURITY_WEP))
#define NM_IS_AP_SECURITY_WEP_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_AP_SECURITY_WEP))
#define NM_AP_SECURITY_WEP_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_AP_SECURITY_WEP, NMAPSecurityWEPClass))

typedef struct _NMAPSecurityWEP NMAPSecurityWEP;
typedef struct _NMAPSecurityWEPClass NMAPSecurityWEPClass;
typedef struct _NMAPSecurityWEPPrivate NMAPSecurityWEPPrivate;

struct _NMAPSecurityWEP
{
	NMAPSecurity parent;

	/*< private >*/
	NMAPSecurityWEPPrivate *priv;
};

struct _NMAPSecurityWEPClass
{
	NMAPSecurityClass parent;
};


GType nm_ap_security_wep_get_type (void);

NMAPSecurityWEP * nm_ap_security_wep_new_deserialize (DBusMessageIter *iter, int we_cipher);

struct NMAccessPoint;
NMAPSecurityWEP * nm_ap_security_wep_new_from_ap (struct NMAccessPoint *ap, int we_cipher);

#endif	/* NM_AP_SECURITY_WEP_H */
