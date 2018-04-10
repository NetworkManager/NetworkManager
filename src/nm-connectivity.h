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
 * Copyright (C) 2011 Thomas Bechtold <thomasbechtold@jpberlin.de>
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_CONNECTIVITY_H__
#define __NETWORKMANAGER_CONNECTIVITY_H__

#include "nm-dbus-interface.h"

#define NM_CONNECTIVITY_ERROR ((NMConnectivityState) -1)
#define NM_CONNECTIVITY_FAKE  ((NMConnectivityState) -2)

#define NM_TYPE_CONNECTIVITY            (nm_connectivity_get_type ())
#define NM_CONNECTIVITY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CONNECTIVITY, NMConnectivity))
#define NM_CONNECTIVITY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_CONNECTIVITY, NMConnectivityClass))
#define NM_IS_CONNECTIVITY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CONNECTIVITY))
#define NM_IS_CONNECTIVITY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_CONNECTIVITY))
#define NM_CONNECTIVITY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_CONNECTIVITY, NMConnectivityClass))

#define NM_CONNECTIVITY_CONFIG_CHANGED  "config-changed"

typedef struct _NMConnectivityClass NMConnectivityClass;

GType nm_connectivity_get_type (void);

NMConnectivity *nm_connectivity_get (void);

const char *nm_connectivity_state_to_string (NMConnectivityState state);

gboolean nm_connectivity_check_enabled (NMConnectivity *self);

guint nm_connectivity_get_interval (NMConnectivity *self);

typedef struct _NMConnectivityCheckHandle NMConnectivityCheckHandle;

typedef void (*NMConnectivityCheckCallback) (NMConnectivity *self,
                                             NMConnectivityCheckHandle *handle,
                                             NMConnectivityState state,
                                             GError *error,
                                             gpointer user_data);

NMConnectivityCheckHandle *nm_connectivity_check_start (NMConnectivity *self,
                                                        const char *iface,
                                                        NMConnectivityCheckCallback callback,
                                                        gpointer user_data);

void nm_connectivity_check_cancel (NMConnectivityCheckHandle *handle);

#endif /* __NETWORKMANAGER_CONNECTIVITY_H__ */
