/* nmcli - command-line tool to control NetworkManager
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
 * Copyright 2010 - 2017 Red Hat, Inc.
 */

#ifndef __NM_CLIENT_UTILS_H__
#define __NM_CLIENT_UTILS_H__

#include "nm-meta-setting.h"
#include "nm-active-connection.h"
#include "nm-device.h"

typedef enum {
	NMC_TRI_STATE_NO,
	NMC_TRI_STATE_YES,
	NMC_TRI_STATE_UNKNOWN,
} NMCTriStateValue;

const NMObject **nmc_objects_sort_by_path (const NMObject *const*objs, gssize len);

const char *nmc_string_is_valid (const char *input, const char **allowed, GError **error);

gboolean nmc_string_to_uint (const char *str,
                             gboolean range_check,
                             unsigned long int min,
                             unsigned long int max,
                             unsigned long int *value);
gboolean nmc_string_to_bool (const char *str, gboolean *val_bool, GError **error);
gboolean nmc_string_to_tristate (const char *str, NMCTriStateValue *val, GError **error);

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
