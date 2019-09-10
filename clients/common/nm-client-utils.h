// SPDX-License-Identifier: GPL-2.0+
/* nmcli - command-line tool to control NetworkManager
 *
 * Copyright 2010 - 2017 Red Hat, Inc.
 */

#ifndef __NM_CLIENT_UTILS_H__
#define __NM_CLIENT_UTILS_H__

#include "nm-meta-setting.h"
#include "nm-active-connection.h"
#include "nm-device.h"
#include "nm-libnm-core-intern/nm-libnm-core-utils.h"

const NMObject **nmc_objects_sort_by_path (const NMObject *const*objs, gssize len);

const char *nmc_string_is_valid (const char *input, const char **allowed, GError **error);

gboolean nmc_string_to_uint (const char *str,
                             gboolean range_check,
                             unsigned long int min,
                             unsigned long int max,
                             unsigned long int *value);
gboolean nmc_string_to_bool (const char *str, gboolean *val_bool, GError **error);
gboolean nmc_string_to_ternary (const char *str, NMTernary *val, GError **error);

gboolean matches (const char *cmd, const char *pattern);

/* FIXME: don't expose this function on its own, at least not from this file. */
const char *nmc_bond_validate_mode (const char *mode, GError **error);

const char *nm_active_connection_state_reason_to_string (NMActiveConnectionStateReason reason);
const char *nmc_device_state_to_string (NMDeviceState state);
const char *nmc_device_reason_to_string (NMDeviceStateReason reason);
const char *nmc_device_metered_to_string (NMMetered value);

NMActiveConnectionState nmc_activation_get_effective_state (NMActiveConnection *active,
                                                            NMDevice *device,
                                                            const char **reason);

const char *nmc_wifi_strength_bars (guint8 strength);

const char *nmc_password_subst_char (void);

#endif /* __NM_CLIENT_UTILS_H__ */
