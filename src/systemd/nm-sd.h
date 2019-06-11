/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2014 - 2016 Red Hat, Inc.
 */

#ifndef __NM_SD_H__
#define __NM_SD_H__

#include "systemd/src/systemd/sd-dhcp-client.h"
#include "systemd/src/systemd/sd-dhcp6-client.h"
#include "systemd/src/systemd/sd-lldp.h"
#include "systemd/src/systemd/sd-ipv4ll.h"

/*****************************************************************************/

guint nm_sd_event_attach_default (void);

/*****************************************************************************
 * expose internal systemd API
 *
 * FIXME: don't use any internal systemd API.
 *****************************************************************************/

struct sd_dhcp_lease;

int dhcp_lease_save(struct sd_dhcp_lease *lease, const char *lease_file);
int dhcp_lease_load(struct sd_dhcp_lease **ret, const char *lease_file);

#endif /* __NM_SD_H__ */

