/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NM_EDITOR_BINDINGS_H
#define NM_EDITOR_BINDINGS_H

void nm_editor_bindings_init (void);

void nm_editor_bind_ip_addresses_with_prefix_to_strv  (int            family,
                                                       gpointer       source,
                                                       const gchar   *source_property,
                                                       gpointer       target,
                                                       const gchar   *target_property,
                                                       GBindingFlags  flags);
void nm_editor_bind_ip_addresses_to_strv              (int            family,
                                                       gpointer       source,
                                                       const gchar   *source_property,
                                                       gpointer       target,
                                                       const gchar   *target_property,
                                                       GBindingFlags  flags);

void nm_editor_bind_ip_gateway_to_string              (int            family,
                                                       NMSettingIPConfig *source,
                                                       gpointer       target,
                                                       const gchar   *target_property,
                                                       const gchar   *target_sensitive_property,
                                                       GBindingFlags  flags);

void nm_editor_bind_ip_route_to_strings               (int            family,
                                                       gpointer       source,
                                                       const gchar   *source_property,
                                                       gpointer       dest_target,
                                                       const gchar   *dest_target_property,
                                                       gpointer       next_hop_target,
                                                       const gchar   *next_hop_target_property,
                                                       gpointer       metric_target,
                                                       const gchar   *metric_target_property,
                                                       GBindingFlags  flags);

void nm_editor_bind_wireless_security_method          (NMConnection  *connection,
                                                       NMSettingWirelessSecurity  *s_wsec,
                                                       gpointer       target,
                                                       const char    *target_property,
                                                       GBindingFlags  flags);
void nm_editor_bind_wireless_security_wep_key         (NMSettingWirelessSecurity  *s_wsec,
                                                       gpointer       entry,
                                                       const char    *entry_property,
                                                       gpointer       key_selector,
                                                       const char    *key_selector_property,
                                                       GBindingFlags  flags);

void nm_editor_bind_vlan_name                         (NMSettingVlan       *s_vlan,
                                                       NMSettingConnection *s_con);

#endif /* NM_EDITOR_BINDINGS_H */
