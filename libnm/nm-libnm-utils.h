// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2017, 2018 Red Hat, Inc.
 */

#ifndef __NM_LIBNM_UTILS_H__
#define __NM_LIBNM_UTILS_H__

#if !((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_PRIVATE)
#error Cannot use this header.
#endif

/* Markers for deprecated sync code in internal API. */
#define _NM_DEPRECATED_SYNC_METHOD_INTERNAL            NM_DEPRECATED_IN_1_22
#define _NM_DEPRECATED_SYNC_WRITABLE_PROPERTY_INTERNAL NM_DEPRECATED_IN_1_22

char *nm_utils_fixup_vendor_string (const char *desc);
char *nm_utils_fixup_product_string (const char *desc);

#endif /* __NM_LIBNM_UTILS_H__ */
