/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
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
 * (C) Copyright 2008 Novell, Inc.
 * (C) Copyright 2009 Red Hat, Inc.
 */

#ifndef NM_DEFAULT_WIRED_CONNECTION_H
#define NM_DEFAULT_WIRED_CONNECTION_H

#include "nm-sysconfig-connection.h"
#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEFAULT_WIRED_CONNECTION            (nm_default_wired_connection_get_type ())
#define NM_DEFAULT_WIRED_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEFAULT_WIRED_CONNECTION, NMDefaultWiredConnection))
#define NM_DEFAULT_WIRED_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEFAULT_WIRED_CONNECTION, NMDefaultWiredConnectionClass))
#define NM_IS_DEFAULT_WIRED_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEFAULT_WIRED_CONNECTION))
#define NM_IS_DEFAULT_WIRED_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_DEFAULT_WIRED_CONNECTION))
#define NM_DEFAULT_WIRED_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEFAULT_WIRED_CONNECTION, NMDefaultWiredConnectionClass))

#define NM_DEFAULT_WIRED_CONNECTION_MAC   "mac"
#define NM_DEFAULT_WIRED_CONNECTION_DEVICE "device"
#define NM_DEFAULT_WIRED_CONNECTION_READ_ONLY "read-only"

typedef struct {
	NMSysconfigConnection parent;
} NMDefaultWiredConnection;

typedef struct {
	NMSysconfigConnectionClass parent;
} NMDefaultWiredConnectionClass;

GType nm_default_wired_connection_get_type (void);

NMDefaultWiredConnection *nm_default_wired_connection_new (const GByteArray *mac,
                                                           NMDevice *device,
                                                           gboolean read_only);

NMDevice *nm_default_wired_connection_get_device (NMDefaultWiredConnection *wired);

G_END_DECLS

#endif /* NM_DEFAULT_WIRED_CONNECTION_H */
