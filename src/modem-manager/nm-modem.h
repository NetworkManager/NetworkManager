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
 * Copyright (C) 2009 Red Hat, Inc.
 * Copyright (C) 2009 Novell, Inc.
 */

#ifndef NM_MODEM_H
#define NM_MODEM_H

#include <dbus/dbus-glib.h>
#include <nm-device.h>
#include "ppp-manager/nm-ppp-manager.h"

G_BEGIN_DECLS

#define NM_TYPE_MODEM			(nm_modem_get_type ())
#define NM_MODEM(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MODEM, NMModem))
#define NM_MODEM_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass),	NM_TYPE_MODEM, NMModemClass))
#define NM_IS_MODEM(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_MODEM))
#define NM_IS_MODEM_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),	NM_TYPE_MODEM))
#define NM_MODEM_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),	NM_TYPE_MODEM, NMModemClass))

#define NM_MODEM_PATH      "path"
#define NM_MODEM_DEVICE    "device"
#define NM_MODEM_IP_METHOD "ip-method"
#define NM_MODEM_ENABLED   "enabled"

typedef struct {
	NMDevice parent;
} NMModem;

typedef struct {
	NMDeviceClass parent;

	const char *(*get_ppp_name) (NMModem *self,
								 NMConnection *connection);

	/* Signals */
	void (*ppp_stats) (NMModem *self, guint32 in_bytes, guint32 out_bytes);
	void (*properties_changed) (NMModem *self, GHashTable *properties);
} NMModemClass;

GType nm_modem_get_type (void);

/* Protected */

NMPPPManager *nm_modem_get_ppp_manager (NMModem *self);
DBusGProxy	 *nm_modem_get_proxy	   (NMModem *self,
										const char *interface);

const char	 *nm_modem_get_ppp_name	   (NMModem *self,
										NMConnection *connection);

gboolean      nm_modem_get_mm_enabled  (NMModem *self);

G_END_DECLS

#endif /* NM_MODEM_H */
