/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include <gmodule.h>

#include "nm-manager.h"
#include "devices/nm-device-factory.h"
#include "nm-device-team.h"
#include "platform/nm-platform.h"
#include "nm-core-internal.h"

/*****************************************************************************/

#define NM_TYPE_TEAM_FACTORY (nm_team_factory_get_type())
#define NM_TEAM_FACTORY(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_TEAM_FACTORY, NMTeamFactory))
#define NM_TEAM_FACTORY_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_TEAM_FACTORY, NMTeamFactoryClass))
#define NM_IS_TEAM_FACTORY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_TEAM_FACTORY))
#define NM_IS_TEAM_FACTORY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_TEAM_FACTORY))
#define NM_TEAM_FACTORY_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_TEAM_FACTORY, NMTeamFactoryClass))

typedef struct {
    NMDeviceFactory parent;
} NMTeamFactory;

typedef struct {
    NMDeviceFactoryClass parent;
} NMTeamFactoryClass;

static GType nm_team_factory_get_type(void);

G_DEFINE_TYPE(NMTeamFactory, nm_team_factory, NM_TYPE_DEVICE_FACTORY)

/*****************************************************************************/

NM_DEVICE_FACTORY_DECLARE_TYPES(NM_DEVICE_FACTORY_DECLARE_LINK_TYPES(
    NM_LINK_TYPE_TEAM) NM_DEVICE_FACTORY_DECLARE_SETTING_TYPES(NM_SETTING_TEAM_SETTING_NAME))

G_MODULE_EXPORT NMDeviceFactory *
                nm_device_factory_create(GError **error)
{
    nm_manager_set_capability(NM_MANAGER_GET, NM_CAPABILITY_TEAM);
    return g_object_new(NM_TYPE_TEAM_FACTORY, NULL);
}

/*****************************************************************************/

static NMDevice *
create_device(NMDeviceFactory *     factory,
              const char *          iface,
              const NMPlatformLink *plink,
              NMConnection *        connection,
              gboolean *            out_ignore)
{
    return nm_device_team_new(iface);
}

/*****************************************************************************/

static void
nm_team_factory_init(NMTeamFactory *self)
{}

static void
nm_team_factory_class_init(NMTeamFactoryClass *klass)
{
    NMDeviceFactoryClass *factory_class = NM_DEVICE_FACTORY_CLASS(klass);

    factory_class->create_device       = create_device;
    factory_class->get_supported_types = get_supported_types;
}
