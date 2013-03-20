/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NM_CONFIG_DEVICE_H
#define NM_CONFIG_DEVICE_H

#include <glib-object.h>

#define NM_TYPE_CONFIG_DEVICE (nm_config_device_get_type ())
#define NM_CONFIG_DEVICE(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CONFIG_DEVICE, NMConfigDevice))
#define NM_IS_CONFIG_DEVICE(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CONFIG_DEVICE))
#define NM_CONFIG_DEVICE_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NM_TYPE_CONFIG_DEVICE, NMConfigDeviceInterface))

typedef struct _NMConfigDevice NMConfigDevice;
typedef struct _NMConfigDeviceInterface NMConfigDeviceInterface;

struct _NMConfigDeviceInterface {
	GTypeInterface g_iface;

	/* Methods */
	gboolean       (*spec_match_list) (NMConfigDevice *device, const GSList *specs);
	const guint8 * (* get_hw_address) (NMConfigDevice *device, guint *out_len);
};

GType nm_config_device_get_type (void);

gboolean  nm_config_device_spec_match_list (NMConfigDevice *device, const char **config_specs);
char     *nm_config_device_get_hwaddr      (NMConfigDevice *device);

#endif /* NM_CONFIG_DEVICE_H */
