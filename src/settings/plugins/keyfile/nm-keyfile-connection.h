/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service - keyfile plugin
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
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 - 2012 Red Hat, Inc.
 */

#ifndef NM_KEYFILE_CONNECTION_H
#define NM_KEYFILE_CONNECTION_H

#include <nm-settings-connection.h>

G_BEGIN_DECLS

#define NM_TYPE_KEYFILE_CONNECTION            (nm_keyfile_connection_get_type ())
#define NM_KEYFILE_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_KEYFILE_CONNECTION, NMKeyfileConnection))
#define NM_KEYFILE_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_KEYFILE_CONNECTION, NMKeyfileConnectionClass))
#define NM_IS_KEYFILE_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_KEYFILE_CONNECTION))
#define NM_IS_KEYFILE_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_KEYFILE_CONNECTION))
#define NM_KEYFILE_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_KEYFILE_CONNECTION, NMKeyfileConnectionClass))

typedef struct {
	NMSettingsConnection parent;
} NMKeyfileConnection;

typedef struct {
	NMSettingsConnectionClass parent;
} NMKeyfileConnectionClass;

GType nm_keyfile_connection_get_type (void);

NMKeyfileConnection *nm_keyfile_connection_new (NMConnection *source,
                                                const char *filename,
                                                GError **error);

const char *nm_keyfile_connection_get_path (NMKeyfileConnection *self);
void        nm_keyfile_connection_set_path (NMKeyfileConnection *self, const char *path);

G_END_DECLS

#endif /* NM_KEYFILE_CONNECTION_H */
