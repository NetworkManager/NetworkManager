// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2006 - 2008 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_SUPPLICANT_SETTINGS_VERIFY_H__
#define __NETWORKMANAGER_SUPPLICANT_SETTINGS_VERIFY_H__

typedef enum {
	TYPE_INVALID = 0,
	TYPE_INT,
	TYPE_BYTES,
	TYPE_UTF8,
	TYPE_KEYWORD,
	TYPE_STRING
} OptType;

OptType nm_supplicant_settings_verify_setting (const char * key,
                                               const char * value,
                                               const guint32 len);

#endif /* __NETWORKMANAGER_SUPPLICANT_SETTINGS_VERIFY_H__ */
