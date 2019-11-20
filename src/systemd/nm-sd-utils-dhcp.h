// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2019 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DHCP_SYSTEMD_UTILS_H__
#define __NETWORKMANAGER_DHCP_SYSTEMD_UTILS_H__

#include "nm-sd.h"

typedef struct {
	uint8_t code;
	uint8_t data_len;
	void *data;
} nm_sd_dhcp_option;

int
nm_sd_dhcp_lease_get_private_options (sd_dhcp_lease *lease, nm_sd_dhcp_option **out_options);

#endif /* __NETWORKMANAGER_DHCP_SYSTEMD_UTILS_H__ */
