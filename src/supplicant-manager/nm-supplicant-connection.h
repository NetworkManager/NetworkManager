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
 * (C) Copyright 2006 Red Hat, Inc.
 */

#ifndef NM_SUPPLICANT_CONNECTION_H
#define NM_SUPPLICANT_CONNECTION_H

#include <glib-object.h>
#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_SUPPLICANT_CONNECTION            (nm_supplicant_connection_get_type ())
#define NM_SUPPLICANT_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SUPPLICANT_CONNECTION, NMSupplicantConnection))
#define NM_SUPPLICANT_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_SUPPLICANT_CONNECTION, NMSupplicantConnectionClass))
#define NM_IS_SUPPLICANT_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SUPPLICANT_CONNECTION))
#define NM_IS_SUPPLICANT_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_SUPPLICANT_CONNECTION))
#define NM_SUPPLICANT_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_SUPPLICANT_CONNECTION, NMSupplicantConnectionClass))

typedef struct _NMSupplicantConnection NMSupplicantConnection;
typedef struct _NMSupplicantConnectionClass NMSupplicantConnectionClass;
typedef struct _NMSupplicantConnectionPrivate NMSupplicantConnectionPrivate;

struct _NMSupplicantConnection
{
	GObject parent;

	/*< private >*/
	NMSupplicantConnectionPrivate *priv;
};

struct _NMSupplicantConnectionClass
{
	GObjectClass parent;

	/* class members */
};


GType nm_supplicant_connection_get_type (void);

NMSupplicantConnection * nm_supplicant_connection_new (NMDevice *dev);

gboolean nm_supplicant_connection_add_option (NMSupplicantConnection *scfg,
                                              const char * key,
                                              const char * value);

gboolean nm_supplicant_connection_remove_option (NMSupplicantConnection *self,
                                                 const char * key);

G_END_DECLS

#endif	/* NM_SUPPLICANT_CONNECTION_H */
