/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * Copyright 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-dhcp6-config.h"
#include "nm-object-private.h"

G_DEFINE_TYPE (NMDhcp6Config, nm_dhcp6_config, NM_TYPE_DHCP_CONFIG)

static void
nm_dhcp6_config_init (NMDhcp6Config *config)
{
}

static void
nm_dhcp6_config_class_init (NMDhcp6ConfigClass *config_class)
{
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (config_class);

	_nm_object_class_add_interface (nm_object_class, NM_DBUS_INTERFACE_DHCP6_CONFIG);
}
