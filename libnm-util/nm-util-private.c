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
 * (C) Copyright 2014 Red Hat, Inc.
 */

#include "nm-util-private.h"

static const NMUtilPrivateData data = {
	.nm_setting_ip4_config_get_address_label = nm_setting_ip4_config_get_address_label,
	.nm_setting_ip4_config_add_address_with_label = nm_setting_ip4_config_add_address_with_label,
};

/**
 * nm_util_get_private:
 *
 * Entry point for NetworkManager-internal API. Although this symbol is exported,
 * it is only useful if you have access to "nm-util-private.h", which is only
 * available inside the NetworkManager tree.
 *
 * Return value: Who knows? It's a mystery.
 *
 * Since: 0.9.10
 */
const NMUtilPrivateData *
nm_util_get_private (void)
{
	return &data;
}
