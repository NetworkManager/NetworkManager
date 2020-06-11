// SPDX-License-Identifier: GPL-2.0+
/*
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

GVariant *nmtst_lldp_parse_from_raw (const guint8 *raw_data,
                                     gsize raw_len);

#endif /* __NM_LLDP_LISTENER__ */
