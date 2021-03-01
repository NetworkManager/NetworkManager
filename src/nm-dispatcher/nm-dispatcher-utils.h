/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DISPATCHER_UTILS_H__
#define __NETWORKMANAGER_DISPATCHER_UTILS_H__

char **nm_dispatcher_utils_construct_envp(const char * action,
                                          GVariant *   connection_dict,
                                          GVariant *   connection_props,
                                          GVariant *   device_props,
                                          GVariant *   device_proxy_props,
                                          GVariant *   device_ip4_props,
                                          GVariant *   device_ip6_props,
                                          GVariant *   device_dhcp4_props,
                                          GVariant *   device_dhcp6_props,
                                          const char * connectivity_state,
                                          const char * vpn_ip_iface,
                                          GVariant *   vpn_proxy_props,
                                          GVariant *   vpn_ip4_props,
                                          GVariant *   vpn_ip6_props,
                                          char **      out_iface,
                                          const char **out_error_message);

#endif /* __NETWORKMANAGER_DISPATCHER_UTILS_H__ */
