/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * Copyright (C) 2009 - 2011 Red Hat, Inc.
 * Copyright (C) 2009 Novell, Inc.
 */

#ifndef NM_MODEM_GENERIC_H
#define NM_MODEM_GENERIC_H

#include <dbus/dbus-glib.h>
#include <glib-object.h>
#include "nm-modem.h"

G_BEGIN_DECLS

#define NM_TYPE_MODEM_GENERIC            (nm_modem_generic_get_type ())
#define NM_MODEM_GENERIC(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MODEM_GENERIC, NMModemGeneric))
#define NM_MODEM_GENERIC_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_MODEM_GENERIC, NMModemGenericClass))
#define NM_IS_MODEM_GENERIC(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_MODEM_GENERIC))
#define NM_IS_MODEM_GENERIC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_MODEM_GENERIC))
#define NM_MODEM_GENERIC_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_MODEM_GENERIC, NMModemGenericClass))

typedef enum {
    NM_MODEM_STATE_UNKNOWN = 0,
    NM_MODEM_STATE_DISABLED = 10,
    NM_MODEM_STATE_DISABLING = 20,
    NM_MODEM_STATE_ENABLING = 30,
    NM_MODEM_STATE_ENABLED = 40,
    NM_MODEM_STATE_SEARCHING = 50,
    NM_MODEM_STATE_REGISTERED = 60,
    NM_MODEM_STATE_DISCONNECTING = 70,
    NM_MODEM_STATE_CONNECTING = 80,
    NM_MODEM_STATE_CONNECTED = 90,

    NM_MODEM_STATE_LAST = NM_MODEM_STATE_CONNECTED
} NMModemState;

typedef struct {
	NMModem parent;
} NMModemGeneric;

typedef struct {
	NMModemClass parent;
} NMModemGenericClass;

GType nm_modem_generic_get_type (void);

/* Protected */
DBusGProxy *nm_modem_generic_get_proxy (NMModemGeneric *modem,
                                        const gchar *interface);

G_END_DECLS

#endif /* NM_MODEM_GENERIC_H */
