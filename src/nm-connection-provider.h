/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details:
 *
 * Copyright (C) 2012 Red Hat, Inc.
 */

#ifndef NM_CONNECTION_PROVIDER_H
#define NM_CONNECTION_PROVIDER_H

#include <glib-object.h>
#include <nm-connection.h>

#define NM_TYPE_CONNECTION_PROVIDER      (nm_connection_provider_get_type ())
#define NM_CONNECTION_PROVIDER(obj)      (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CONNECTION_PROVIDER, NMConnectionProvider))
#define NM_IS_CONNECTION_PROVIDER(obj)   (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CONNECTION_PROVIDER))
#define NM_CONNECTION_PROVIDER_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NM_TYPE_CONNECTION_PROVIDER, NMConnectionProvider))

typedef struct _NMConnectionProvider NMConnectionProvider;

#define NM_CP_SIGNAL_CONNECTION_ADDED        "cp-connection-added"
#define NM_CP_SIGNAL_CONNECTION_UPDATED      "cp-connection-updated"
#define NM_CP_SIGNAL_CONNECTION_REMOVED      "cp-connection-removed"


/**
 * NMConnectionFilterFunc:
 * @provider: The provider requesting the filtering
 * @connection: the connection to be filtered
 * @func_data: the caller-provided data pointer
 *
 * Returns: %TRUE to allow the connection, %FALSE to ignore it
 */
typedef gboolean (*NMConnectionFilterFunc) (NMConnectionProvider *provider,
                                            NMConnection *connection,
                                            gpointer func_data);


struct _NMConnectionProvider {
	GTypeInterface g_iface;

	/* Methods */
	GSList * (*get_best_connections) (NMConnectionProvider *self,
	                                  guint max_requested,
	                                  const char *ctype1,
	                                  const char *ctype2,
	                                  NMConnectionFilterFunc func,
	                                  gpointer func_data);

	const GSList * (*get_connections) (NMConnectionProvider *self);

	NMConnection * (*add_connection) (NMConnectionProvider *self,
	                                  NMConnection *connection,
	                                  gboolean save_to_disk,
	                                  GError **error);

	NMConnection * (*get_connection_by_uuid) (NMConnectionProvider *self,
	                                          const char *uuid);

	/* Signals */
	void (*connection_added)   (NMConnectionProvider *self, NMConnection *connection);

	void (*connection_updated) (NMConnectionProvider *self, NMConnection *connection);

	void (*connection_removed) (NMConnectionProvider *self, NMConnection *connection);

};

GType nm_connection_provider_get_type (void);

/**
 * nm_connection_provider_get:
 *
 * Returns: the global #NMConnectionProvider
 */
NMConnectionProvider *nm_connection_provider_get (void);

/**
 * nm_connection_provider_get_best_connections:
 * @self: the #NMConnectionProvider
 * @max_requested: if non-zero, the maximum number of connections to return
 * @ctype1: an #NMSetting base type (eg NM_SETTING_WIRELESS_SETTING_NAME) to
 *   filter connections against
 * @ctype2: a second #NMSetting base type (eg NM_SETTING_WIRELESS_SETTING_NAME)
 *   to filter connections against
 * @func: caller-supplied function for filtering connections
 * @func_data: caller-supplied data passed to @func
 *
 * Returns: a #GSList of #NMConnection objects in sorted order representing the
 *   "best" or highest-priority connections filtered by @ctype1 and/or @ctype2,
 *   and/or @func.  Caller is responsible for freeing the returned #GSList, but
 *   the contained values do not need to be unreffed.
 */
GSList *nm_connection_provider_get_best_connections (NMConnectionProvider *self,
                                                     guint max_requested,
                                                     const char *ctype1,
                                                     const char *ctype2,
                                                     NMConnectionFilterFunc func,
                                                     gpointer func_data);

/**
 * nm_connection_provider_get_connections:
 * @self: the #NMConnectionProvider
 *
 * Returns: a #GSList of #NMConnection objects representing all known
 *   connections.  Returned list is owned by the connection provider and must
 *   not be freed.
 */
const GSList *nm_connection_provider_get_connections (NMConnectionProvider *self);

/**
 * nm_connection_provider_add_connection:
 * @self: the #NMConnectionProvider
 * @connection: the connection to be added
 * @save_to_disk: whether to store the connection on disk
 * @error: returns any error if adding fails
 *
 * returns: a newly added #NMConnection.
 */
NMConnection *nm_connection_provider_add_connection (NMConnectionProvider *self,
                                                     NMConnection *connection,
                                                     gboolean save_to_disk,
                                                     GError **error);

NMConnection *nm_connection_provider_get_connection_by_uuid (NMConnectionProvider *self,
                                                             const char *uuid);

#endif /* NM_CONNECTION_PROVIDER_H */
