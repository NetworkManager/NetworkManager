/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_PRIVATE_H__
#define __NETWORKMANAGER_DEVICE_PRIVATE_H__

#include "nm-device.h"
#include "nm-l3-config-data.h"

/* This file should only be used by subclasses of NMDevice */

typedef enum {
    NM_DEVICE_STAGE_STATE_INIT      = 0,
    NM_DEVICE_STAGE_STATE_PENDING   = 1,
    NM_DEVICE_STAGE_STATE_COMPLETED = 2,
} NMDeviceStageState;

enum NMActStageReturn {
    NM_ACT_STAGE_RETURN_FAILURE = 0, /* Hard failure of activation */
    NM_ACT_STAGE_RETURN_SUCCESS,     /* Activation stage done */
    NM_ACT_STAGE_RETURN_POSTPONE,    /* Long-running operation in progress */
};

#define NM_DEVICE_CAP_NONSTANDARD_CARRIER 0x80000000
#define NM_DEVICE_CAP_IS_NON_KERNEL       0x40000000

#define NM_DEVICE_CAP_INTERNAL_MASK 0xc0000000

gboolean nm_device_set_ip_ifindex(NMDevice *self, int ifindex);

gboolean nm_device_set_ip_iface(NMDevice *self, const char *iface);

gboolean nm_device_bring_up(NMDevice *self);
gboolean nm_device_bring_up_full(NMDevice *self,
                                 gboolean  block,
                                 gboolean  update_carrier,
                                 gboolean *no_firmware);

void nm_device_take_down(NMDevice *self, gboolean block);

gboolean nm_device_take_over_link(NMDevice *self, int ifindex, char **old_name, GError **error);

gboolean nm_device_hw_addr_set(NMDevice   *device,
                               const char *addr,
                               const char *detail,
                               gboolean    set_permanent);
gboolean nm_device_hw_addr_set_cloned(NMDevice *device, NMConnection *connection, gboolean is_wifi);
gboolean nm_device_hw_addr_reset(NMDevice *device, const char *detail);

void nm_device_set_firmware_missing(NMDevice *self, gboolean missing);

void nm_device_activate_schedule_stage1_device_prepare(NMDevice *device, gboolean do_sync);
void nm_device_activate_schedule_stage2_device_config(NMDevice *device, gboolean do_sync);
void nm_device_activate_schedule_stage3_ip_config(NMDevice *device, gboolean do_sync);

void nm_device_recheck_available_connections(NMDevice *device);

void
nm_device_master_check_slave_physical_port(NMDevice *self, NMDevice *slave, NMLogDomain log_domain);

void nm_device_master_release_slaves_all(NMDevice *self);

void nm_device_set_carrier(NMDevice *self, gboolean carrier);

void nm_device_queue_recheck_assume(NMDevice *device);
void nm_device_queue_recheck_available(NMDevice           *device,
                                       NMDeviceStateReason available_reason,
                                       NMDeviceStateReason unavailable_reason);

gboolean nm_device_hw_addr_is_explict(NMDevice *device);

NMDeviceIPState nm_device_devip_get_state(NMDevice *self, int addr_family);

void nm_device_devip_set_state_full(NMDevice             *self,
                                    int                   addr_family,
                                    NMDeviceIPState       ip_state,
                                    const NML3ConfigData *l3cd,
                                    NMDeviceStateReason   failed_reason);

static inline void
nm_device_devip_set_state(NMDevice             *self,
                          int                   addr_family,
                          NMDeviceIPState       ip_state,
                          const NML3ConfigData *l3cd)
{
    nm_assert(NM_IS_DEVICE(self));
    nm_assert_addr_family_or_unspec(addr_family);
    nm_assert(!l3cd || NM_IS_L3_CONFIG_DATA(l3cd));
    nm_assert(NM_IN_SET(ip_state,
                        NM_DEVICE_IP_STATE_NONE,
                        NM_DEVICE_IP_STATE_PENDING,
                        NM_DEVICE_IP_STATE_READY));

    nm_device_devip_set_state_full(self, addr_family, ip_state, l3cd, NM_DEVICE_STATE_REASON_NONE);
}

static inline void
nm_device_devip_set_failed(NMDevice *self, int addr_family, NMDeviceStateReason reason)
{
    nm_assert(NM_IS_DEVICE(self));
    nm_assert_addr_family_or_unspec(addr_family);
    nm_assert(reason != NM_DEVICE_STATE_REASON_NONE);

    nm_device_devip_set_state_full(self, addr_family, NM_DEVICE_IP_STATE_FAILED, NULL, reason);
}

gboolean nm_device_sysctl_ip_conf_set(NMDevice   *self,
                                      int         addr_family,
                                      const char *property,
                                      const char *value);

NML3ConfigData *nm_device_create_l3_config_data(NMDevice *self, NMIPConfigSource source);

const NML3ConfigData *nm_device_create_l3_config_data_from_connection(NMDevice     *self,
                                                                      NMConnection *connection);

void nm_device_ip_method_dhcp4_start(NMDevice *self);

void nm_device_ip_method_autoconf6_start(NMDevice *self);

/*****************************************************************************/

gint64 nm_device_get_configured_mtu_from_connection_default(NMDevice   *self,
                                                            const char *property_name,
                                                            guint32     max_mtu);

guint32 nm_device_get_configured_mtu_from_connection(NMDevice          *device,
                                                     GType              setting_type,
                                                     NMDeviceMtuSource *out_source);

guint32 nm_device_get_configured_mtu_for_wired(NMDevice          *self,
                                               NMDeviceMtuSource *out_source,
                                               gboolean          *out_force);

guint32 nm_device_get_configured_mtu_wired_parent(NMDevice          *self,
                                                  NMDeviceMtuSource *out_source,
                                                  gboolean          *out_force);

void nm_device_commit_mtu(NMDevice *self);

/*****************************************************************************/

#define NM_DEVICE_DEFINE_LINK_TYPES(...)                                        \
    ((NM_NARG(__VA_ARGS__) == 0) ? NULL : ({                                    \
        static const NMLinkType _types[NM_NARG(__VA_ARGS__) + 1] = {            \
            __VA_ARGS__ _NM_MACRO_COMMA_IF_ARGS(__VA_ARGS__) NM_LINK_TYPE_NONE, \
        };                                                                      \
                                                                                \
        nm_assert(_types[NM_NARG(__VA_ARGS__)] == NM_LINK_TYPE_NONE);           \
        _types;                                                                 \
    }))

gboolean _nm_device_hash_check_invalid_keys(GHashTable        *hash,
                                            const char        *setting_name,
                                            GError           **error,
                                            const char *const *whitelist);
#define nm_device_hash_check_invalid_keys(hash, setting_name, error, ...) \
    _nm_device_hash_check_invalid_keys(hash, setting_name, error, NM_MAKE_STRV(__VA_ARGS__))

gboolean nm_device_match_parent(NMDevice *device, const char *parent);
gboolean nm_device_match_parent_hwaddr(NMDevice     *device,
                                       NMConnection *connection,
                                       gboolean      fail_if_no_hwaddr);

/*****************************************************************************/

void nm_device_auth_request(NMDevice                      *self,
                            GDBusMethodInvocation         *context,
                            NMConnection                  *connection,
                            const char                    *permission,
                            gboolean                       allow_interaction,
                            GCancellable                  *cancellable,
                            NMManagerDeviceAuthRequestFunc callback,
                            gpointer                       user_data);

void nm_device_link_properties_set(NMDevice *self, gboolean reapply);

#endif /* NM_DEVICE_PRIVATE_H */
