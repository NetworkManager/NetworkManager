/*
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
 * Copyright 2014 Red Hat, Inc.
 */

#ifndef __NM_SIMPLE_CONNECTION_H__
#define __NM_SIMPLE_CONNECTION_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-connection.h"

G_BEGIN_DECLS

#define NM_TYPE_SIMPLE_CONNECTION            (nm_simple_connection_get_type ())
#define NM_SIMPLE_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SIMPLE_CONNECTION, NMSimpleConnection))
#define NM_SIMPLE_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SIMPLE_CONNECTION, NMSimpleConnectionClass))
#define NM_IS_SIMPLE_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SIMPLE_CONNECTION))
#define NM_IS_SIMPLE_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SIMPLE_CONNECTION))
#define NM_SIMPLE_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SIMPLE_CONNECTION, NMSimpleConnectionClass))

/**
 * NMSimpleConnection:
 */
struct _NMSimpleConnection {
	GObject parent;
};

typedef struct {
	GObjectClass parent_class;

	/*< private >*/
	gpointer padding[4];
} NMSimpleConnectionClass;

GType nm_simple_connection_get_type (void);

NMConnection *nm_simple_connection_new           (void);

NMConnection *nm_simple_connection_new_from_dbus (GVariant      *dict,
                                                  GError       **error);

NMConnection *nm_simple_connection_new_clone     (NMConnection  *connection);

G_END_DECLS

#endif  /* __NM_SIMPLE_CONNECTION__ */
