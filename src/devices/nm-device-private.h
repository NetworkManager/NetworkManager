/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_PRIVATE_H__
#define __NETWORKMANAGER_DEVICE_PRIVATE_H__

#include "nm-device.h"

/* This file should only be used by subclasses of NMDevice */

enum NMActStageReturn {
	NM_ACT_STAGE_RETURN_FAILURE = 0, /* Hard failure of activation */
	NM_ACT_STAGE_RETURN_SUCCESS,     /* Activation stage done */
	NM_ACT_STAGE_RETURN_POSTPONE,    /* Long-running operation in progress */
	NM_ACT_STAGE_RETURN_IP_WAIT,     /* IP config stage is waiting (state IP_WAIT) */
	NM_ACT_STAGE_RETURN_IP_DONE,     /* IP config stage is done (state IP_DONE),
	                                    For the ip-config stage, this is similar to
	                                    NM_ACT_STAGE_RETURN_SUCCESS, except that no
	                                    IP config should be commited. */
	NM_ACT_STAGE_RETURN_IP_FAIL,     /* IP config stage failed (state IP_FAIL), activation may proceed */
};

#define NM_DEVICE_CAP_NONSTANDARD_CARRIER 0x80000000
#define NM_DEVICE_CAP_IS_NON_KERNEL       0x40000000

#define NM_DEVICE_CAP_INTERNAL_MASK 0xc0000000

void nm_device_arp_announce (NMDevice *self);

NMSettings *nm_device_get_settings (NMDevice *self);

gboolean nm_device_set_ip_ifindex (NMDevice *self, int ifindex);

gboolean nm_device_set_ip_iface (NMDevice *self, const char *iface);

void nm_device_activate_schedule_stage3_ip_config_start (NMDevice *device);

gboolean nm_device_activate_stage3_ip4_start (NMDevice *self);

gboolean nm_device_activate_stage3_ip6_start (NMDevice *self);

gboolean nm_device_bring_up (NMDevice *self, gboolean wait, gboolean *no_firmware);

void nm_device_take_down (NMDevice *self, gboolean block);

gboolean nm_device_take_over_link (NMDevice *self, int ifindex, char **old_name);

gboolean nm_device_hw_addr_set (NMDevice *device,
                                const char *addr,
                                const char *detail,
                                gboolean set_permanent);
gboolean nm_device_hw_addr_set_cloned (NMDevice *device, NMConnection *connection, gboolean is_wifi);
gboolean nm_device_hw_addr_reset (NMDevice *device, const char *detail);

void nm_device_set_firmware_missing (NMDevice *self, gboolean missing);

void nm_device_activate_schedule_stage1_device_prepare (NMDevice *device);
void nm_device_activate_schedule_stage2_device_config (NMDevice *device);

void nm_device_activate_schedule_ip4_config_result(NMDevice *device, NMIP4Config *config);
void nm_device_activate_schedule_ip4_config_timeout (NMDevice *device);

void nm_device_activate_schedule_ip6_config_result (NMDevice *device);
void nm_device_activate_schedule_ip6_config_timeout (NMDevice *device);

gboolean nm_device_activate_ip4_state_in_conf (NMDevice *device);
gboolean nm_device_activate_ip4_state_in_wait (NMDevice *device);
gboolean nm_device_activate_ip4_state_done (NMDevice *device);

gboolean nm_device_activate_ip6_state_in_conf (NMDevice *device);
gboolean nm_device_activate_ip6_state_in_wait (NMDevice *device);
gboolean nm_device_activate_ip6_state_done (NMDevice *device);

void nm_device_set_dhcp_anycast_address (NMDevice *device, const char *addr);

gboolean nm_device_dhcp4_renew (NMDevice *device, gboolean release);
gboolean nm_device_dhcp6_renew (NMDevice *device, gboolean release);

void nm_device_recheck_available_connections (NMDevice *device);

void nm_device_master_check_slave_physical_port (NMDevice *self, NMDevice *slave,
                                                 NMLogDomain log_domain);

void nm_device_set_carrier (NMDevice *self, gboolean carrier);

void nm_device_queue_recheck_assume (NMDevice *device);
void nm_device_queue_recheck_available (NMDevice *device,
                                        NMDeviceStateReason available_reason,
                                        NMDeviceStateReason unavailable_reason);

void nm_device_set_wwan_ip4_config (NMDevice *device, NMIP4Config *config);
void nm_device_set_wwan_ip6_config (NMDevice *device, NMIP6Config *config);

gboolean nm_device_hw_addr_is_explict (NMDevice *device);

void nm_device_ip_method_failed (NMDevice *self, int family, NMDeviceStateReason reason);

gboolean nm_device_ipv6_sysctl_set (NMDevice *self, const char *property, const char *value);

/*****************************************************************************/

gint64 nm_device_get_configured_mtu_from_connection_default (NMDevice *self,
                                                             const char *property_name);

guint32 nm_device_get_configured_mtu_from_connection (NMDevice *device,
                                                      GType setting_type,
                                                      NMDeviceMtuSource *out_source);

guint32 nm_device_get_configured_mtu_for_wired (NMDevice *self, NMDeviceMtuSource *out_source);

void nm_device_commit_mtu (NMDevice *self);

/*****************************************************************************/

#define NM_DEVICE_CLASS_DECLARE_TYPES(klass, conn_type, ...) \
	NM_DEVICE_CLASS (klass)->connection_type = conn_type; \
	{ \
		static const NMLinkType link_types[] = { __VA_ARGS__, NM_LINK_TYPE_NONE }; \
		NM_DEVICE_CLASS (klass)->link_types = link_types; \
	}

gboolean _nm_device_hash_check_invalid_keys (GHashTable *hash, const char *setting_name,
                                             GError **error, const char **whitelist);
#define nm_device_hash_check_invalid_keys(hash, setting_name, error, ...) \
	_nm_device_hash_check_invalid_keys (hash, setting_name, error, ((const char *[]) { __VA_ARGS__, NULL }))

gboolean nm_device_match_parent (NMDevice *device, const char *parent);
gboolean nm_device_match_hwaddr (NMDevice *device,
                                 NMConnection *connection,
                                 gboolean fail_if_no_hwaddr);

#endif /* NM_DEVICE_PRIVATE_H */
