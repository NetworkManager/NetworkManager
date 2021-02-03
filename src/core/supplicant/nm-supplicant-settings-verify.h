/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2006 - 2008 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_SUPPLICANT_SETTINGS_VERIFY_H__
#define __NETWORKMANAGER_SUPPLICANT_SETTINGS_VERIFY_H__

typedef enum {
    NM_SUPPL_OPT_TYPE_INVALID = 0,
    NM_SUPPL_OPT_TYPE_INT,
    NM_SUPPL_OPT_TYPE_BYTES,
    NM_SUPPL_OPT_TYPE_UTF8,
    NM_SUPPL_OPT_TYPE_KEYWORD,
    NM_SUPPL_OPT_TYPE_STRING,
    _NM_SUPPL_OPT_TYPE_NUM,
} NMSupplOptType;

NMSupplOptType
nm_supplicant_settings_verify_setting(const char *key, const char *value, const guint32 len);

#endif /* __NETWORKMANAGER_SUPPLICANT_SETTINGS_VERIFY_H__ */
