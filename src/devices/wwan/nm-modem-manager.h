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
 * Copyright (C) 2009 - 2014 Red Hat, Inc.
 * Copyright (C) 2009 Novell, Inc.
 * Copyright (C) 2009 Canonical Ltd.
 */

#ifndef NM_MODEM_MANAGER_H
#define NM_MODEM_MANAGER_H

#include <glib-object.h>
#include "nm-modem.h"

#define NM_TYPE_MODEM_MANAGER (nm_modem_manager_get_type ())
#define NM_MODEM_MANAGER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MODEM_MANAGER, NMModemManager))

#define NM_MODEM_MANAGER_MODEM_ADDED "modem-added"

typedef struct _NMModemManagerPrivate NMModemManagerPrivate;

typedef struct {
	GObject parent;
	NMModemManagerPrivate *priv;
} NMModemManager;

typedef struct {
	GObjectClass parent;

	void (*modem_added) (NMModemManager *self, NMModem *modem);
} NMModemManagerClass;

GType nm_modem_manager_get_type (void);

#endif /* NM_MODEM_MANAGER_H */
