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

#ifndef __NM_UTIL_PRIVATE_H__
#define __NM_UTIL_PRIVATE_H__

#include <glib.h>

#include "nm-setting-private.h"

G_BEGIN_DECLS

typedef struct NMUtilPrivateData {
	const char * (*nm_setting_ip4_config_get_address_label)      (NMSettingIP4Config *setting,
	                                                              guint32             i);
	gboolean     (*nm_setting_ip4_config_add_address_with_label) (NMSettingIP4Config *setting,
	                                                              NMIP4Address       *address,
	                                                              const char         *label);
} NMUtilPrivateData;

const NMUtilPrivateData *nm_util_get_private (void);


/**
 * NM_UTIL_PRIVATE_CALL:
 * @call: a call to a private libnm-util function
 *
 * Used to call private libnm-util functions. Eg, if there was a
 * private function called nm_foo_get_bar(), you could call it like:
 *
 *   bar = NM_UTIL_PRIVATE_CALL (nm_foo_get_bar (foo, x, y, z));
 *
 * This macro only exists inside the NetworkManager source tree and
 * is not part of the public API.
 *
 * Since: 0.9.10
 */
#define NM_UTIL_PRIVATE_CALL(call) (nm_util_get_private ()->call)

G_END_DECLS

#endif
