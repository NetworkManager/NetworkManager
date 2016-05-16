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

#ifndef __NETWORKMANAGER_CONNECTION_PROVIDER_H__
#define __NETWORKMANAGER_CONNECTION_PROVIDER_H__

#include "nm-connection.h"

#define NM_TYPE_CONNECTION_PROVIDER               (nm_connection_provider_get_type ())
#define NM_CONNECTION_PROVIDER(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CONNECTION_PROVIDER, NMConnectionProvider))
#define NM_IS_CONNECTION_PROVIDER(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CONNECTION_PROVIDER))
#define NM_CONNECTION_PROVIDER_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NM_TYPE_CONNECTION_PROVIDER, NMConnectionProviderInterface))

#define NM_CP_SIGNAL_CONNECTION_ADDED        "cp-connection-added"
#define NM_CP_SIGNAL_CONNECTION_UPDATED      "cp-connection-updated"
#define NM_CP_SIGNAL_CONNECTION_REMOVED      "cp-connection-removed"


typedef struct {
	GTypeInterface g_iface;

	/* Methods */
	const GSList * (*get_connections) (NMConnectionProvider *self);

	NMConnection * (*add_connection) (NMConnectionProvider *self,
	                                  NMConnection *connection,
	                                  gboolean save_to_disk,
	                                  GError **error);

	NMConnection * (*get_connection_by_uuid) (NMConnectionProvider *self,
	                                          const char *uuid);

	const GSList * (*get_unmanaged_specs) (NMConnectionProvider *self);
} NMConnectionProviderInterface;

GType nm_connection_provider_get_type (void);

/**
 * nm_connection_provider_get:
 *
 * Returns: the global #NMConnectionProvider
 */
NMConnectionProvider *nm_connection_provider_get (void);

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

const GSList *nm_connection_provider_get_unmanaged_specs (NMConnectionProvider *self);

#endif /* __NETWORKMANAGER_CONNECTION_PROVIDER_H__ */
