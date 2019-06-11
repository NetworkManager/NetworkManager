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
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_LLDP_LISTENER__
#define __NM_LLDP_LISTENER__

#define NM_TYPE_LLDP_LISTENER            (nm_lldp_listener_get_type ())
#define NM_LLDP_LISTENER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_LLDP_LISTENER, NMLldpListener))
#define NM_LLDP_LISTENER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_LLDP_LISTENER, NMLldpListenerClass))
#define NM_IS_LLDP_LISTENER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_LLDP_LISTENER))
#define NM_IS_LLDP_LISTENER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_LLDP_LISTENER))
#define NM_LLDP_LISTENER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_LLDP_LISTENER, NMLldpListenerClass))

#define NM_LLDP_LISTENER_NEIGHBORS "neighbors"

typedef struct _NMLldpListenerClass NMLldpListenerClass;

GType nm_lldp_listener_get_type (void);
NMLldpListener *nm_lldp_listener_new (void);
gboolean nm_lldp_listener_start (NMLldpListener *self, int ifindex, GError **error);
void nm_lldp_listener_stop (NMLldpListener *self);
gboolean nm_lldp_listener_is_running (NMLldpListener *self);

GVariant *nm_lldp_listener_get_neighbors (NMLldpListener *self);

#endif /* __NM_LLDP_LISTENER__ */
