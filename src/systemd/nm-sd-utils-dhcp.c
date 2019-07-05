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

#include "nm-default.h"

#include "nm-sd-utils-dhcp.h"

#include "sd-adapt-core/nm-sd-adapt-core.h"
#include "src/libsystemd-network/dhcp-lease-internal.h"

int
nm_sd_dhcp_lease_get_private_options (sd_dhcp_lease *lease, nm_sd_dhcp_option **out_options)
{
	struct sd_dhcp_raw_option *raw_option;
	int cnt = 0;

	g_return_val_if_fail (lease, -EINVAL);
	g_return_val_if_fail (out_options, -EINVAL);
	g_return_val_if_fail (*out_options == NULL, -EINVAL);

	if (lease->private_options == NULL)
		return -ENODATA;

	LIST_FOREACH (options, raw_option, lease->private_options)
		cnt++;

	*out_options = g_new (nm_sd_dhcp_option, cnt);
	cnt = 0;

	LIST_FOREACH (options, raw_option, lease->private_options) {
		(*out_options)[cnt].code = raw_option->tag;
		(*out_options)[cnt].data = raw_option->data;
		(*out_options)[cnt].data_len = raw_option->length;
		cnt++;
	}

	return cnt;
}
