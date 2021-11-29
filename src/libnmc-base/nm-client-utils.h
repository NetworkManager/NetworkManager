/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2010 - 2017 Red Hat, Inc.
 */

#ifndef __NM_CLIENT_UTILS_H__
#define __NM_CLIENT_UTILS_H__

#include "nm-active-connection.h"
#include "nm-device.h"
#include "libnm-core-aux-intern/nm-libnm-core-utils.h"

const NMObject **nmc_objects_sort_by_path(const NMObject *const *objs, gssize len);

const char *_nmc_string_is_valid(const char *input, const char *const *allowed, GError **error);

#define nmc_string_is_valid(input, allowed, error) \
    _nmc_string_is_valid((input), NM_CAST_STRV_CC(allowed), (error))

gboolean nmc_string_to_uint(const char        *str,
                            gboolean           range_check,
                            unsigned long int  min,
                            unsigned long int  max,
                            unsigned long int *value);
gboolean nmc_string_to_bool(const char *str, gboolean *val_bool, GError **error);

typedef enum {
    NMC_STRING_TO_TERNARY_FLAGS_NONE               = 0,
    NMC_STRING_TO_TERNARY_FLAGS_IGNORE_FOR_DEFAULT = (1LL << 0),
} NMCStringToTernaryFlags;

gboolean nmc_string_to_ternary_full(const char             *str,
                                    NMCStringToTernaryFlags flags,
                                    NMTernary              *val,
                                    GError                **error);

static inline gboolean
nmc_string_to_ternary(const char *str, NMTernary *val, GError **error)
{
    return nmc_string_to_ternary_full(str, NMC_STRING_TO_TERNARY_FLAGS_NONE, val, error);
}

gboolean matches(const char *cmd, const char *pattern);

/* FIXME: don't expose this function on its own, at least not from this file. */
const char *nmc_bond_validate_mode(const char *mode, GError **error);

const char *nmc_device_state_to_string_with_external(NMDevice *device);

const char *nm_active_connection_state_reason_to_string(NMActiveConnectionStateReason reason);
const char *nmc_device_state_to_string(NMDeviceState state);
const char *nmc_device_reason_to_string(NMDeviceStateReason reason);
const char *nmc_device_metered_to_string(NMMetered value);

NMActiveConnectionState nmc_activation_get_effective_state(NMActiveConnection *active,
                                                           NMDevice           *device,
                                                           const char        **reason);

const char *nmc_wifi_strength_bars(guint8 strength);

const char *nmc_password_subst_char(void);

void nmc_print_qrcode(const char *str);

GHashTable *nmc_utils_parse_passwd_file(char *contents, gssize *out_error_line, GError **error);

GHashTable *
nmc_utils_read_passwd_file(const char *passwd_file, gssize *out_error_line, GError **error);

#endif /* __NM_CLIENT_UTILS_H__ */
