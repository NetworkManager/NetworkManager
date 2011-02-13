/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 */

#ifndef __NM_REMOTE_CONNECTION_H__
#define __NM_REMOTE_CONNECTION_H__

#include <glib-object.h>
#include <dbus/dbus-glib.h>

#include <nm-connection.h>

G_BEGIN_DECLS

#define NM_TYPE_REMOTE_CONNECTION            (nm_remote_connection_get_type ())
#define NM_REMOTE_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_REMOTE_CONNECTION, NMRemoteConnection))
#define NM_REMOTE_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_REMOTE_CONNECTION, NMRemoteConnectionClass))
#define NM_IS_REMOTE_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_REMOTE_CONNECTION))
#define NM_IS_REMOTE_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_REMOTE_CONNECTION))
#define NM_REMOTE_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_REMOTE_CONNECTION, NMRemoteConnectionClass))

#define NM_REMOTE_CONNECTION_UPDATED         "updated"
#define NM_REMOTE_CONNECTION_REMOVED         "removed"

typedef struct {
	NMConnection parent;
} NMRemoteConnection;

typedef struct {
	NMConnectionClass parent_class;

	/* Signals */
	void (*updated) (NMRemoteConnection *connection,
	                 GHashTable *new_settings);

	void (*removed) (NMRemoteConnection *connection);

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMRemoteConnectionClass;

typedef void (*NMRemoteConnectionCommitFunc) (NMRemoteConnection *connection,
                                              GError *error,
                                              gpointer user_data);

typedef void (*NMRemoteConnectionDeleteFunc) (NMRemoteConnection *connection,
                                              GError *error,
                                              gpointer user_data);

typedef void (*NMRemoteConnectionGetSecretsFunc) (NMRemoteConnection *connection,
                                                  GHashTable *secrets,
                                                  GError *error,
                                                  gpointer user_data);

GType nm_remote_connection_get_type (void);

NMRemoteConnection *nm_remote_connection_new (DBusGConnection *bus,
                                              const char *path);

void nm_remote_connection_commit_changes (NMRemoteConnection *connection,
                                          NMRemoteConnectionCommitFunc callback,
                                          gpointer user_data);

void nm_remote_connection_delete (NMRemoteConnection *connection,
                                  NMRemoteConnectionDeleteFunc callback,
                                  gpointer user_data);

void nm_remote_connection_get_secrets (NMRemoteConnection *connection,
                                       const char *setting_name,
                                       NMRemoteConnectionGetSecretsFunc callback,
                                       gpointer user_data);
G_END_DECLS

#endif  /* __NM_REMOTE_CONNECTION__ */

