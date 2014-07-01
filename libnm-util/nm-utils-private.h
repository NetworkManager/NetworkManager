/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * Ray Strode <rstrode@redhat.com>
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
 *
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
 * (C) Copyright 2005 - 2008 Red Hat, Inc.
 */

#ifndef __NM_UTILS_PRIVATE_H__
#define __NM_UTILS_PRIVATE_H__

#include "nm-setting-private.h"

gboolean    _nm_utils_string_in_list   (const char *str,
                                        const char **valid_strings);

gboolean    _nm_utils_string_slist_validate (GSList *list,
                                             const char **valid_values);

gboolean    _nm_utils_gvalue_array_validate (GValueArray *elements,
                                             guint n_expected, ...);

void        _nm_value_transforms_register (void);

/***********************************************************/

typedef struct NMUtilsPrivateData {
	const char * (*nm_setting_ip4_config_get_address_label)      (NMSettingIP4Config *setting,
	                                                              guint32             i);
	gboolean     (*nm_setting_ip4_config_add_address_with_label) (NMSettingIP4Config *setting,
	                                                              NMIP4Address       *address,
	                                                              const char         *label);
} NMUtilsPrivateData;

const NMUtilsPrivateData *nm_utils_get_private (void);

/**
 * NM_UTILS_PRIVATE_CALL:
 * @call: a call to a private libnm-util function
 *
 * Used to call private libnm-util functions. Eg, if there was a
 * private function called nm_foo_get_bar(), you could call it like:
 *
 *   bar = NM_UTILS_PRIVATE_CALL (nm_foo_get_bar (foo, x, y, z));
 *
 * This macro only exists inside the NetworkManager source tree and
 * is not part of the public API.
 *
 * Since: 0.9.10
 */
#define NM_UTILS_PRIVATE_CALL(call) (nm_utils_get_private ()->call)

#endif
