/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DNSMASQ_UTILS_H__
#define __NETWORKMANAGER_DNSMASQ_UTILS_H__

#include "platform/nm-platform.h"

gboolean nm_dnsmasq_utils_get_range(const NMPlatformIP4Address *addr,
                                    char *                      out_first,
                                    char *                      out_last,
                                    char **                     out_error_desc);

#endif /* __NETWORKMANAGER_DNSMASQ_UTILS_H__ */
