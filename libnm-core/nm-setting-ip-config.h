/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

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
 * Copyright 2007 - 2014 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef NM_SETTING_IP_CONFIG_H
#define NM_SETTING_IP_CONFIG_H

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

typedef struct NMIPAddress NMIPAddress;

GType        nm_ip_address_get_type            (void);

NMIPAddress *nm_ip_address_new                 (int family,
                                                const char  *addr,
                                                guint prefix,
                                                const char *gateway,
                                                GError **error);
NMIPAddress *nm_ip_address_new_binary          (int family,
                                                gconstpointer addr,
                                                guint prefix,
                                                gconstpointer gateway,
                                                GError **error);

void         nm_ip_address_ref                 (NMIPAddress *address);
void         nm_ip_address_unref               (NMIPAddress *address);
gboolean     nm_ip_address_equal               (NMIPAddress *address,
                                                NMIPAddress *other);
NMIPAddress *nm_ip_address_dup                 (NMIPAddress *address);

int          nm_ip_address_get_family          (NMIPAddress *address);
const char  *nm_ip_address_get_address         (NMIPAddress *address);
void         nm_ip_address_set_address         (NMIPAddress *address,
                                                const char *addr);
void         nm_ip_address_get_address_binary  (NMIPAddress *address,
                                                gpointer addr);
void         nm_ip_address_set_address_binary  (NMIPAddress *address,
                                                gconstpointer addr);
guint        nm_ip_address_get_prefix          (NMIPAddress *address);
void         nm_ip_address_set_prefix          (NMIPAddress *address,
                                                guint prefix);
const char  *nm_ip_address_get_gateway         (NMIPAddress *address);
void         nm_ip_address_set_gateway         (NMIPAddress *address,
                                                const char *gateway);

typedef struct NMIPRoute NMIPRoute;

GType        nm_ip_route_get_type            (void);

NMIPRoute   *nm_ip_route_new                 (int family,
                                              const char *dest,
                                              guint prefix,
                                              const char *next_hop,
                                              guint metric,
                                              GError **error);
NMIPRoute   *nm_ip_route_new_binary          (int family,
                                              gconstpointer dest,
                                              guint prefix,
                                              gconstpointer next_hop,
                                              guint metric,
                                              GError **error);

void         nm_ip_route_ref                 (NMIPRoute  *route);
void         nm_ip_route_unref               (NMIPRoute  *route);
gboolean     nm_ip_route_equal               (NMIPRoute  *route,
                                              NMIPRoute  *other);
NMIPRoute   *nm_ip_route_dup                 (NMIPRoute  *route);

int          nm_ip_route_get_family          (NMIPRoute  *route);
const char  *nm_ip_route_get_dest            (NMIPRoute  *route);
void         nm_ip_route_set_dest            (NMIPRoute  *route,
                                              const char *dest);
void         nm_ip_route_get_dest_binary     (NMIPRoute  *route,
                                              gpointer dest);
void         nm_ip_route_set_dest_binary     (NMIPRoute  *route,
                                              gconstpointer dest);
guint        nm_ip_route_get_prefix          (NMIPRoute  *route);
void         nm_ip_route_set_prefix          (NMIPRoute  *route,
                                              guint prefix);
const char  *nm_ip_route_get_next_hop        (NMIPRoute  *route);
void         nm_ip_route_set_next_hop        (NMIPRoute  *route,
                                              const char *next_hop);
gboolean     nm_ip_route_get_next_hop_binary (NMIPRoute  *route,
                                              gpointer next_hop);
void         nm_ip_route_set_next_hop_binary (NMIPRoute  *route,
                                              gconstpointer next_hop);
guint32      nm_ip_route_get_metric          (NMIPRoute  *route);
void         nm_ip_route_set_metric          (NMIPRoute  *route,
                                              guint32 metric);

G_END_DECLS

#endif /* NM_SETTING_IP_CONFIG_H */
