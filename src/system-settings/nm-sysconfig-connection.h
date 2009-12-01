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

#ifndef NM_SYSCONFIG_CONNECTION_H
#define NM_SYSCONFIG_CONNECTION_H

#include <nm-connection.h>
#include <nm-exported-connection.h>

G_BEGIN_DECLS

#define NM_TYPE_SYSCONFIG_CONNECTION            (nm_sysconfig_connection_get_type ())
#define NM_SYSCONFIG_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SYSCONFIG_CONNECTION, NMSysconfigConnection))
#define NM_SYSCONFIG_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SYSCONFIG_CONNECTION, NMSysconfigConnectionClass))
#define NM_IS_SYSCONFIG_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SYSCONFIG_CONNECTION))
#define NM_IS_SYSCONFIG_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SYSCONFIG_CONNECTION))
#define NM_SYSCONFIG_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SYSCONFIG_CONNECTION, NMSysconfigConnectionClass))

typedef struct {
	NMExportedConnection parent;
} NMSysconfigConnection;

typedef struct {
	NMExportedConnectionClass parent;
} NMSysconfigConnectionClass;

GType nm_sysconfig_connection_get_type (void);

/* Called by a system-settings plugin to update a connection is out of sync
 * with it's backing storage.
 */
gboolean nm_sysconfig_connection_update (NMSysconfigConnection *self,
                                         NMConnection *new_settings,
                                         gboolean signal_update,
                                         GError **error);

G_END_DECLS

#endif /* NM_SYSCONFIG_CONNECTION_H */
