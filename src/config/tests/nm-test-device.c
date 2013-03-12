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

#include "config.h"

#include <string.h>
#include <netinet/ether.h>

#include "nm-test-device.h"
#include "nm-config-device.h"
#include "nm-utils.h"

static void nm_test_device_config_device_interface_init (NMConfigDeviceInterface *iface);

G_DEFINE_TYPE_WITH_CODE (NMTestDevice, nm_test_device, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (NM_TYPE_CONFIG_DEVICE, nm_test_device_config_device_interface_init))

static void
nm_test_device_init (NMTestDevice *self)
{
}

static void
finalize (GObject *object)
{
	NMTestDevice *self = NM_TEST_DEVICE (object);

	g_free (self->hwaddr);
	g_free (self->hwaddr_bytes);

	G_OBJECT_CLASS (nm_test_device_parent_class)->finalize (object);
}

static void
nm_test_device_class_init (NMTestDeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->finalize = finalize;
}

static gboolean
spec_match_list (NMConfigDevice *device, const GSList *specs)
{
	NMTestDevice *self = NM_TEST_DEVICE (device);
	const GSList *iter;
	const char *spec;

	for (iter = specs; iter; iter = iter->next) {
		spec = iter->data;
		if (g_str_has_prefix (spec, "mac:") && !strcmp (spec + 4, self->hwaddr))
			return TRUE;
	}
	return FALSE;
}

static const guint8 *
get_hw_address (NMConfigDevice *device, guint *out_len)
{
	NMTestDevice *self = NM_TEST_DEVICE (device);

	if (out_len)
		*out_len = ETH_ALEN;
	return self->hwaddr_bytes;
}

static void
nm_test_device_config_device_interface_init (NMConfigDeviceInterface *iface)
{
	iface->spec_match_list = spec_match_list;
	iface->get_hw_address = get_hw_address;
}

NMTestDevice *
nm_test_device_new (const char *hwaddr)
{
	NMTestDevice *self = g_object_new (NM_TYPE_TEST_DEVICE, NULL);

	self->hwaddr = g_strdup (hwaddr);
	self->hwaddr_bytes = g_malloc (ETH_ALEN);
	nm_utils_hwaddr_aton (hwaddr, ARPHRD_ETHER, self->hwaddr_bytes);

	return self;
}
