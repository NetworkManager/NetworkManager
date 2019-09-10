// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NM_EDITOR_BINDINGS_H
#define NM_EDITOR_BINDINGS_H

void nm_editor_bindings_init (void);

void nm_editor_bind_ip_addresses_with_prefix_to_strv  (int            family,
                                                       gpointer       source,
                                                       const char    *source_property,
                                                       gpointer       target,
                                                       const char    *target_property,
                                                       GBindingFlags  flags);
void nm_editor_bind_ip_addresses_to_strv              (int            family,
                                                       gpointer       source,
                                                       const char    *source_property,
                                                       gpointer       target,
                                                       const char    *target_property,
                                                       GBindingFlags  flags);

void nm_editor_bind_ip_gateway_to_string              (int            family,
                                                       NMSettingIPConfig *source,
                                                       gpointer       target,
                                                       const char    *target_property,
                                                       const char    *target_sensitive_property,
                                                       GBindingFlags  flags);

void nm_editor_bind_ip_route_to_strings               (int            family,
                                                       gpointer       source,
                                                       const char    *source_property,
                                                       gpointer       dest_target,
                                                       const char    *dest_target_property,
                                                       gpointer       next_hop_target,
                                                       const char    *next_hop_target_property,
                                                       gpointer       metric_target,
                                                       const char    *metric_target_property,
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
