/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2019 Red Hat, Inc.
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
