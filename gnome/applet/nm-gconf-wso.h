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

#ifndef NM_GCONF_WSO_H
#define NM_GCONF_WSO_H

#include <glib-object.h>
#include <gconf/gconf-client.h>
#include <dbus/dbus.h>

#define NM_TYPE_GCONF_WSO			(nm_gconf_wso_get_type ())
#define NM_GCONF_WSO(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_GCONF_WSO, NMGConfWSO))
#define NM_GCONF_WSO_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_GCONF_WSO, NMGConfWSOClass))
#define NM_IS_AP_SECURITY(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_GCONF_WSO))
#define NM_IS_AP_SECURITY_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_GCONF_WSO))
#define NM_GCONF_WSO_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_GCONF_WSO, NMGConfWSOClass))

typedef struct _NMGConfWSO NMGConfWSO;
typedef struct _NMGConfWSOClass NMGConfWSOClass;
typedef struct _NMGConfWSOPrivate NMGConfWSOPrivate;

struct _NMGConfWSO
{
	GObject parent;

	/*< private >*/
	NMGConfWSOPrivate *priv;
};

struct NMDevice;

struct _NMGConfWSOClass
{
	GObjectClass parent;

	/* class members */
	int	(*serialize_dbus_func)	(NMGConfWSO *self, DBusMessageIter *iter);

	int	(*serialize_gconf_func)	(NMGConfWSO *self, GConfClient *client, const char *network);
};


GType nm_gconf_wso_get_type (void);

NMGConfWSO * nm_gconf_wso_new_deserialize_dbus (DBusMessageIter *iter);

NMGConfWSO * nm_gconf_wso_new_deserialize_gconf (GConfClient *client, const char *network);

int nm_gconf_wso_get_we_cipher (NMGConfWSO *self);

const char * nm_gconf_wso_get_key (NMGConfWSO *self);

void nm_gconf_wso_set_key (NMGConfWSO *self, const char *key, int key_len);

int nm_gconf_wso_serialize_dbus (NMGConfWSO *self, DBusMessageIter *iter);

int nm_gconf_wso_serialize_gconf (NMGConfWSO *self, GConfClient *client, const char *network);

#endif	/* NM_GCONF_WSO_H */
