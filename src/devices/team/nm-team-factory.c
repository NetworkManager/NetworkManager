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
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include <string.h>
#include <gmodule.h>

#include "config.h"
#include "nm-device-factory.h"
#include "nm-team-factory.h"
#include "nm-device-team.h"
#include "nm-logging.h"

static GType nm_team_factory_get_type (void);

static void device_factory_interface_init (NMDeviceFactory *factory_iface);

G_DEFINE_TYPE_EXTENDED (NMTeamFactory, nm_team_factory, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_DEVICE_FACTORY, device_factory_interface_init))

#define NM_TEAM_FACTORY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_TEAM_FACTORY, NMTeamFactoryPrivate))

typedef struct {
	char dummy;
} NMTeamFactoryPrivate;


/************************************************************************/

static NMDevice *
new_link (NMDeviceFactory *factory, NMPlatformLink *plink, GError **error)
{
	if (plink->type == NM_LINK_TYPE_TEAM)
		 return nm_device_team_new (plink);
	return NULL;
}

static NMDevice *
create_virtual_device_for_connection (NMDeviceFactory *factory,
                                      NMConnection *connection,
                                      GError **error)
{
	if (nm_connection_is_type (connection, NM_SETTING_TEAM_SETTING_NAME))
		return nm_device_team_new_for_connection (connection, error);
	return NULL;
}

/************************************************************************/

#define PLUGIN_TYPE NM_DEVICE_TYPE_TEAM

G_MODULE_EXPORT NMDeviceFactory *
nm_device_factory_create (GError **error)
{
	return (NMDeviceFactory *) g_object_new (NM_TYPE_TEAM_FACTORY, NULL);
}

G_MODULE_EXPORT NMDeviceType
nm_device_factory_get_device_type (void)
{
	return PLUGIN_TYPE;
}

/************************************************************************/

static void
nm_team_factory_init (NMTeamFactory *self)
{
}

static void
device_factory_interface_init (NMDeviceFactory *factory_iface)
{
	factory_iface->new_link = new_link;
	factory_iface->create_virtual_device_for_connection = create_virtual_device_for_connection;
}

static void
dispose (GObject *object)
{
	/* Chain up to the parent class */
	G_OBJECT_CLASS (nm_team_factory_parent_class)->dispose (object);
}

static void
nm_team_factory_class_init (NMTeamFactoryClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMTeamFactoryPrivate));

	object_class->dispose = dispose;
}
