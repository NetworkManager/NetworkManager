/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_LLDP_LISTENER__
#define __NM_LLDP_LISTENER__

/*****************************************************************************/

typedef void (*NMLldpListenerNotify)(NMLldpListener *self, gpointer user_data);

NMLldpListener *nm_lldp_listener_new(int                  ifindex,
                                     NMLldpListenerNotify notify_callback,
                                     gpointer             notify_user_data,
                                     GError             **error);
void            nm_lldp_listener_destroy(NMLldpListener *self);

int       nm_lldp_listener_get_ifindex(NMLldpListener *self);
GVariant *nm_lldp_listener_get_neighbors(NMLldpListener *self);

/*****************************************************************************/

GVariant *nmtst_lldp_parse_from_raw(const guint8 *raw_data, gsize raw_len);

#endif /* __NM_LLDP_LISTENER__ */
