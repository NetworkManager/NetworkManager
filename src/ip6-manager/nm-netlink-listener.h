/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Netlink socket listener
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
 * Copyright (C) 2005 - 2009 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 * Copyright (C) 2005 Ray Strode
 */

#ifndef NM_NETLINK_LISTENER_H
#define NM_NETLINK_LISTENER_H

#include <glib.h>
#include <glib-object.h>

#include "nm-netlink.h"

G_BEGIN_DECLS

#define NM_TYPE_NETLINK_LISTENER	    (nm_netlink_listener_get_type ())
#define NM_NETLINK_LISTENER(obj)	    (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_NETLINK_LISTENER, NMNetlinkListener))
#define NM_NETLINK_LISTENER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_NETLINK_LISTENER, NMNetlinkListenerClass))
#define NM_IS_NETLINK_LISTENER(obj)	 (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_NETLINK_LISTENER))
#define NM_IS_NETLINK_LISTENER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_NETLINK_LISTENER))
#define NM_NETLINK_LISTENER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_NETLINK_LISTENER, NMNetlinkListenerClass))
#define NM_NETLINK_LISTENER_ERROR	   (nm_netlink_listener_error_quark ())

typedef enum {
	NM_NETLINK_LISTENER_ERROR_GENERIC = 0,
	NM_NETLINK_LISTENER_ERROR_NETLINK_ALLOC_HANDLE,
	NM_NETLINK_LISTENER_ERROR_NETLINK_CONNECT,
	NM_NETLINK_LISTENER_ERROR_NETLINK_JOIN_GROUP,
	NM_NETLINK_LISTENER_ERROR_NETLINK_ALLOC_LINK_CACHE,
	NM_NETLINK_LISTENER_ERROR_PROCESSING_MESSAGE,
	NM_NETLINK_LISTENER_ERROR_BAD_ALLOC,
	NM_NETLINK_LISTENER_ERROR_WAITING_FOR_SOCKET_DATA,
	NM_NETLINK_LISTENER_ERROR_LINK_CACHE_UPDATE
} NMNetlinkListenerError;

typedef struct {
	GObject parent;
} NMNetlinkListener;

typedef struct {
	GObjectClass parent_class;

	/* Signals */
	void (*notification) (NMNetlinkListener *listener, struct nl_msg *msg);
	void (*error)        (NMNetlinkListener *listener, GError *error);
} NMNetlinkListenerClass;

GType	nm_netlink_listener_get_type	(void)	G_GNUC_CONST;
GQuark	nm_netlink_listener_error_quark	(void)	G_GNUC_CONST;

NMNetlinkListener *nm_netlink_listener_get (void);

gboolean           nm_netlink_listener_subscribe        (NMNetlinkListener *listener,
														 int group,
														 GError **error);
void               nm_netlink_listener_unsubscribe      (NMNetlinkListener *listener,
														 int group);

G_END_DECLS

#endif  /* NM_NETLINK_LISTENER_H */
