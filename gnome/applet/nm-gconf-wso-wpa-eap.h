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
 * (C) Copyright 2006 Novell, Inc.
 */

#ifndef NM_GCONF_WSO_WPA_EAP_H
#define NM_GCONF_WSO_WPA_EAP_H

#include <glib-object.h>
#include <dbus/dbus.h>
#include <gconf/gconf-client.h>
#include "nm-gconf-wso-wpa-eap.h"

#define NM_TYPE_GCONF_WSO_WPA_EAP			(nm_gconf_wso_wpa_eap_get_type ())
#define NM_GCONF_WSO_WPA_EAP(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_GCONF_WSO_WPA_EAP, NMGConfWSOWPA_EAP))
#define NM_GCONF_WSO_WPA_EAP_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_GCONF_WSO_WPA_EAP, NMGConfWSOWPA_EAPClass))
#define NM_IS_GCONF_WSO_WPA_EAP(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_GCONF_WSO_WPA_EAP))
#define NM_IS_GCONF_WSO_WPA_EAP_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_GCONF_WSO_WPA_EAP))
#define NM_GCONF_WSO_WPA_EAP_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_GCONF_WSO_WPA_EAP, NMGConfWSOWPA_EAPClass))

typedef struct _NMGConfWSOWPA_EAP NMGConfWSOWPA_EAP;
typedef struct _NMGConfWSOWPA_EAPClass NMGConfWSOWPA_EAPClass;
typedef struct _NMGConfWSOWPA_EAPPrivate NMGConfWSOWPA_EAPPrivate;

struct _NMGConfWSOWPA_EAP
{
	NMGConfWSO parent;

	/*< private >*/
	NMGConfWSOWPA_EAPPrivate *priv;
};

struct _NMGConfWSOWPA_EAPClass
{
	NMGConfWSOClass parent;
};


GType nm_gconf_wso_wpa_eap_get_type (void);

NMGConfWSOWPA_EAP * nm_gconf_wso_wpa_eap_new_deserialize_dbus (DBusMessageIter *iter, int we_cipher);

NMGConfWSOWPA_EAP * nm_gconf_wso_wpa_eap_new_deserialize_gconf (GConfClient *client, const char *network, int we_cipher);

#endif	/* NM_GCONF_WSO_WPA_EAP_H */
