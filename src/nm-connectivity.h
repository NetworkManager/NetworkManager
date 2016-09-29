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
 */

#ifndef __NETWORKMANAGER_CONNECTIVITY_H__
#define __NETWORKMANAGER_CONNECTIVITY_H__

#include "nm-dbus-interface.h"

#define NM_TYPE_CONNECTIVITY            (nm_connectivity_get_type ())
#define NM_CONNECTIVITY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CONNECTIVITY, NMConnectivity))
#define NM_CONNECTIVITY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_CONNECTIVITY, NMConnectivityClass))
#define NM_IS_CONNECTIVITY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CONNECTIVITY))
#define NM_IS_CONNECTIVITY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_CONNECTIVITY))
#define NM_CONNECTIVITY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_CONNECTIVITY, NMConnectivityClass))

#define NM_CONNECTIVITY_URI       "uri"
#define NM_CONNECTIVITY_INTERVAL  "interval"
#define NM_CONNECTIVITY_RESPONSE  "response"
#define NM_CONNECTIVITY_STATE     "state"

typedef struct _NMConnectivityClass NMConnectivityClass;

GType nm_connectivity_get_type (void);

const char *nm_connectivity_state_to_string (NMConnectivityState state);

NMConnectivity      *nm_connectivity_new (const char *uri,
                                          guint interval,
                                          const char *response);

void                 nm_connectivity_set_online   (NMConnectivity       *self,
                                                   gboolean              online);

NMConnectivityState  nm_connectivity_get_state    (NMConnectivity       *self);

void                 nm_connectivity_check_async  (NMConnectivity       *self,
                                                   GAsyncReadyCallback   callback,
                                                   gpointer              user_data);
NMConnectivityState  nm_connectivity_check_finish (NMConnectivity       *self,
                                                   GAsyncResult         *result,
                                                   GError              **error);

#endif /* __NETWORKMANAGER_CONNECTIVITY_H__ */
