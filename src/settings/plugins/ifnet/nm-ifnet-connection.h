/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Mu Qiao <qiaomuf@gmail.com>
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
 * Copyright (C) 1999-2010 Gentoo Foundation, Inc.
 */

#ifndef __NETWORKMANAGER_IFNET_CONNECTION_H__
#define __NETWORKMANAGER_IFNET_CONNECTION_H__

#include <nm-settings-connection.h>
#include "net_parser.h"

G_BEGIN_DECLS

#define NM_TYPE_IFNET_CONNECTION            (nm_ifnet_connection_get_type ())
#define NM_IFNET_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_IFNET_CONNECTION, NMIfnetConnection))
#define NM_IFNET_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_IFNET_CONNECTION, NMIfnetConnectionClass))
#define NM_IS_IFNET_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_IFNET_CONNECTION))
#define NM_IS_IFNET_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_IFNET_CONNECTION))
#define NM_IFNET_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_IFNET_CONNECTION, NMIfnetConnectionClass))

typedef struct {
	NMSettingsConnection parent;
} NMIfnetConnection;

typedef struct {
	NMSettingsConnectionClass parent;
} NMIfnetConnectionClass;

GType nm_ifnet_connection_get_type (void);

NMIfnetConnection *nm_ifnet_connection_new (NMConnection *source,
                                            const char *conn_name);

const char *nm_ifnet_connection_get_conn_name (NMIfnetConnection *connection);

G_END_DECLS
#endif				/* NM_IFNET_CONNECTION_H */
