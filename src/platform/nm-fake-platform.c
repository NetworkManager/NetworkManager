/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-platform-fake.c - Fake platform interaction code for testing NetworkManager
 *
 * This program is free software; you can redistribute it and/or modify
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
 * Copyright (C) 2012–2013 Red Hat, Inc.
 */

#include <errno.h>
#include <unistd.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>

#include "nm-fake-platform.h"
#include "nm-logging.h"

#define debug(format, ...) nm_log_dbg (LOGD_PLATFORM, format, __VA_ARGS__)

typedef struct {
	GArray *links;
} NMFakePlatformPrivate;

#define NM_FAKE_PLATFORM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_FAKE_PLATFORM, NMFakePlatformPrivate))

G_DEFINE_TYPE (NMFakePlatform, nm_fake_platform, NM_TYPE_PLATFORM)

/******************************************************************/

void
nm_fake_platform_setup (void)
{
	nm_platform_setup (NM_TYPE_FAKE_PLATFORM);
}

/******************************************************************/

static void
link_init (NMPlatformLink *device, int ifindex, int type, const char *name)
{
	g_assert (!name || strlen (name) < sizeof(device->name));

	memset (device, 0, sizeof (*device));

	device->ifindex = name ? ifindex : 0;
	device->type = type;
	if (name)
		strcpy (device->name, name);
}

static NMPlatformLink *
link_get (NMPlatform *platform, int ifindex)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	NMPlatformLink *device;

	if (ifindex >= priv->links->len)
		goto not_found;
	device = &g_array_index (priv->links, NMPlatformLink, ifindex);
	if (!device->ifindex)
		goto not_found;

	return device;
not_found:
	debug ("link not found: %d", ifindex);
	platform->error = NM_PLATFORM_ERROR_NOT_FOUND;
	return NULL;
}

static GArray *
link_get_all (NMPlatform *platform)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	GArray *links = g_array_sized_new (TRUE, TRUE, sizeof (NMPlatformLink), priv->links->len);
	int i;

	for (i = 0; i < priv->links->len; i++)
		if (g_array_index (priv->links, NMPlatformLink, i).ifindex)
			g_array_append_val (links, g_array_index (priv->links, NMPlatformLink, i));

	return links;
}

static gboolean
link_add (NMPlatform *platform, const char *name, NMLinkType type)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	NMPlatformLink device;

	link_init (&device, priv->links->len, type, name);

	g_array_append_val (priv->links, device);

	if (device.ifindex)
		g_signal_emit_by_name (platform, NM_PLATFORM_LINK_ADDED, &device);

	return TRUE;
}

static gboolean
link_delete (NMPlatform *platform, int ifindex)
{
	NMPlatformLink *device = link_get (platform, ifindex);
	NMPlatformLink deleted_device;

	if (!device)
		return FALSE;

	memcpy (&deleted_device, device, sizeof (deleted_device));
	memset (device, 0, sizeof (*device));

	g_signal_emit_by_name (platform, NM_PLATFORM_LINK_REMOVED, &deleted_device);

	return TRUE;
}

static int
link_get_ifindex (NMPlatform *platform, const char *name)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (platform);
	int i;

	for (i = 0; i < priv->links->len; i++) {
		NMPlatformLink *device = &g_array_index (priv->links, NMPlatformLink, i);

		if (device && !g_strcmp0 (device->name, name))
			return device->ifindex;
	}

	return 0;
}

static const char *
link_get_name (NMPlatform *platform, int ifindex)
{
	NMPlatformLink *device = link_get (platform, ifindex);

	return device ? device->name : NULL;
}

static NMLinkType
link_get_type (NMPlatform *platform, int ifindex)
{
	NMPlatformLink *device = link_get (platform, ifindex);

	return device ? device->type : NM_LINK_TYPE_NONE;
}

/******************************************************************/

static void
nm_fake_platform_init (NMFakePlatform *fake_platform)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (fake_platform);

	priv->links = g_array_new (TRUE, TRUE, sizeof (NMPlatformLink));
}

static gboolean
setup (NMPlatform *platform)
{
	/* skip zero element */
	link_add (platform, NULL, NM_LINK_TYPE_NONE);

	/* add loopback interface */
	link_add (platform, "lo", NM_LINK_TYPE_LOOPBACK);

	/* add some ethernets */
	link_add (platform, "eth0", NM_LINK_TYPE_ETHERNET);
	link_add (platform, "eth1", NM_LINK_TYPE_ETHERNET);
	link_add (platform, "eth2", NM_LINK_TYPE_ETHERNET);

	return TRUE;
}

static void
nm_fake_platform_finalize (GObject *object)
{
	NMFakePlatformPrivate *priv = NM_FAKE_PLATFORM_GET_PRIVATE (object);

	g_array_unref (priv->links);

	G_OBJECT_CLASS (nm_fake_platform_parent_class)->finalize (object);
}

static void
nm_fake_platform_class_init (NMFakePlatformClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMPlatformClass *platform_class = NM_PLATFORM_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMFakePlatformPrivate));

	/* virtual methods */
	object_class->finalize = nm_fake_platform_finalize;

	platform_class->setup = setup;

	platform_class->link_get_all = link_get_all;
	platform_class->link_add = link_add;
	platform_class->link_delete = link_delete;
	platform_class->link_get_ifindex = link_get_ifindex;
	platform_class->link_get_name = link_get_name;
	platform_class->link_get_type = link_get_type;
}
