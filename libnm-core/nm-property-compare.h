// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright 2007 - 2014 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef __NM_PROPERTY_COMPARE_H__
#define __NM_PROPERTY_COMPARE_H__

#if !((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_CORE_PRIVATE)
#error Cannot use this header.
#endif

int nm_property_compare (GVariant *value1, GVariant *value2);

#endif /* __NM_PROPERTY_COMPARE_H__ */
