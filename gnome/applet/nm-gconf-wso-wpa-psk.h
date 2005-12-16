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

#ifndef NM_GCONF_WSO_WPA_PSK_H
#define NM_GCONF_WSO_WPA_PSK_H

#include <glib-object.h>
#include <dbus/dbus.h>
#include <gconf/gconf-client.h>
#include "nm-gconf-wso-wpa-psk.h"

#define NM_TYPE_GCONF_WSO_WPA_PSK			(nm_gconf_wso_wpa_psk_get_type ())
#define NM_GCONF_WSO_WPA_PSK(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_GCONF_WSO_WPA_PSK, NMGConfWSOWPA_PSK))
#define NM_GCONF_WSO_WPA_PSK_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_GCONF_WSO_WPA_PSK, NMGConfWSOWPA_PSKClass))
#define NM_IS_GCONF_WSO_WPA_PSK(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_GCONF_WSO_WPA_PSK))
#define NM_IS_GCONF_WSO_WPA_PSK_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_GCONF_WSO_WPA_PSK))
#define NM_GCONF_WSO_WPA_PSK_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_GCONF_WSO_WPA_PSK, NMGConfWSOWPA_PSKClass))

typedef struct _NMGConfWSOWPA_PSK NMGConfWSOWPA_PSK;
typedef struct _NMGConfWSOWPA_PSKClass NMGConfWSOWPA_PSKClass;
typedef struct _NMGConfWSOWPA_PSKPrivate NMGConfWSOWPA_PSKPrivate;

struct _NMGConfWSOWPA_PSK
{
	NMGConfWSO parent;

	/*< private >*/
	NMGConfWSOWPA_PSKPrivate *priv;
};

struct _NMGConfWSOWPA_PSKClass
{
	NMGConfWSOClass parent;
};


GType nm_gconf_wso_wpa_psk_get_type (void);

NMGConfWSOWPA_PSK * nm_gconf_wso_wpa_psk_new_deserialize_dbus (DBusMessageIter *iter, int we_cipher);

NMGConfWSOWPA_PSK * nm_gconf_wso_wpa_psk_new_deserialize_gconf (GConfClient *client, const char *network, int we_cipher);

#endif	/* NM_GCONF_WSO_WPA_PSK_H */
