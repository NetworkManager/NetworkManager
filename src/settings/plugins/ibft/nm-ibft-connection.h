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
 * Copyright 2014 Red Hat, Inc.
 */

#ifndef NM_IBFT_CONNECTION_H
#define NM_IBFT_CONNECTION_H

G_BEGIN_DECLS

#include <nm-settings-connection.h>

#define NM_TYPE_IBFT_CONNECTION            (nm_ibft_connection_get_type ())
#define NM_IBFT_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_IBFT_CONNECTION, NMIbftConnection))
#define NM_IBFT_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_IBFT_CONNECTION, NMIbftConnectionClass))
#define NM_IS_IBFT_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_IBFT_CONNECTION))
#define NM_IS_IBFT_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_IBFT_CONNECTION))
#define NM_IBFT_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_IBFT_CONNECTION, NMIbftConnectionClass))

typedef struct {
	NMSettingsConnection parent;
} NMIbftConnection;

typedef struct {
	NMSettingsConnectionClass parent;
} NMIbftConnectionClass;

GType nm_ibft_connection_get_type (void);

NMIbftConnection *nm_ibft_connection_new (const GPtrArray *block,
                                          GError **error);

G_END_DECLS

#endif /* NM_IBFT_CONNECTION_H */
