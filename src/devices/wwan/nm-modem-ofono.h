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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2013 - Canonical Ltd.
 */

#ifndef NM_MODEM_OFONO_H
#define NM_MODEM_OFONO_H

#include "nm-modem.h"

#define NM_TYPE_MODEM_OFONO            (nm_modem_ofono_get_type ())
#define NM_MODEM_OFONO(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MODEM_OFONO, NMModemOfono))
#define NM_IS_MODEM_OFONO(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_MODEM_OFONO))
#define NM_MODEM_OFONO_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_MODEM_OFONO, NMModemOfonoClass))
#define NM_IS_MODEM_OFONO_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_MODEM_OFONO))
#define NM_MODEM_OFONO_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_MODEM_OFONO, NMModemOfonoClass))

#define OFONO_DBUS_SERVICE                      "org.ofono"
#define OFONO_DBUS_PATH                         "/"
#define OFONO_DBUS_INTERFACE                    "org.ofono.Manager"
#define OFONO_DBUS_INTERFACE_MODEM              "org.ofono.Modem"
#define OFONO_DBUS_INTERFACE_CONNECTION_MANAGER "org.ofono.ConnectionManager"
#define OFONO_DBUS_INTERFACE_CONNECTION_CONTEXT "org.ofono.ConnectionContext"
#define OFONO_DBUS_INTERFACE_SIM_MANAGER        "org.ofono.SimManager"

typedef struct _NMModemOfono NMModemOfono;
typedef struct _NMModemOfonoClass NMModemOfonoClass;

GType nm_modem_ofono_get_type (void);

NMModem *nm_modem_ofono_new (const char *path);

#endif /* NM_MODEM_OFONO_H */
