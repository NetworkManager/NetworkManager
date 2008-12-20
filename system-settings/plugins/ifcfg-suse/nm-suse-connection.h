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
 */

#ifndef NM_SUSE_CONNECTION_H
#define NM_SUSE_CONNECTION_H

#include <NetworkManager.h>
#include <nm-sysconfig-connection.h>

G_BEGIN_DECLS

#define NM_TYPE_SUSE_CONNECTION            (nm_suse_connection_get_type ())
#define NM_SUSE_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SUSE_CONNECTION, NMSuseConnection))
#define NM_SUSE_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SUSE_CONNECTION, NMSuseConnectionClass))
#define NM_IS_SUSE_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SUSE_CONNECTION))
#define NM_IS_SUSE_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SUSE_CONNECTION))
#define NM_SUSE_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SUSE_CONNECTION, NMSuseConnectionClass))

typedef struct {
	NMSysconfigConnection parent;
} NMSuseConnection;

typedef struct {
	NMSysconfigConnectionClass parent;
} NMSuseConnectionClass;

GType nm_suse_connection_get_type (void);

NMSuseConnection *nm_suse_connection_new (const char *iface,
								  NMDeviceType dev_type);

G_END_DECLS

#endif /* NM_SUSE_CONNECTION_H */
