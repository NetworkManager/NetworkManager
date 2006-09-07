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

/* This file is heavily based on nm-gconf-wso-wpa-eap.h */

#ifndef NM_GCONF_WSO_LEAP_H
#define NM_GCONF_WSO_LEAP_H

#include <glib-object.h>
#include <dbus/dbus.h>
#include <gconf/gconf-client.h>

#define NM_TYPE_GCONF_WSO_LEAP			(nm_gconf_wso_leap_get_type ())
#define NM_GCONF_WSO_LEAP(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_GCONF_WSO_LEAP, NMGConfWSOLEAP))
#define NM_GCONF_WSO_LEAP_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_GCONF_WSO_LEAP, NMGConfWSOLEAPClass))
#define NM_IS_GCONF_WSO_LEAP(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_GCONF_WSO_LEAP))
#define NM_IS_GCONF_WSO_LEAP_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_GCONF_WSO_LEAP))
#define NM_GCONF_WSO_LEAP_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_GCONF_WSO_LEAP, NMGConfWSOLEAPClass))

typedef struct _NMGConfWSOLEAP NMGConfWSOLEAP;
typedef struct _NMGConfWSOLEAPClass NMGConfWSOLEAPClass;
typedef struct _NMGConfWSOLEAPPrivate NMGConfWSOLEAPPrivate;

struct _NMGConfWSOLEAP
{
	NMGConfWSO parent;

	/*< private >*/
	NMGConfWSOLEAPPrivate *priv;
};

struct _NMGConfWSOLEAPClass
{
	NMGConfWSOClass parent;
};


GType nm_gconf_wso_leap_get_type (void);

NMGConfWSOLEAP * nm_gconf_wso_leap_new_deserialize_dbus (DBusMessageIter *iter, int we_cipher);

NMGConfWSOLEAP * nm_gconf_wso_leap_new_deserialize_gconf (GConfClient *client, const char *network, int we_cipher);

#endif	/* NM_GCONF_WSO_LEAP_H */
