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
 * Copyright 2012 Red Hat, Inc.
 */

#ifndef __NM_SETTING_BRIDGE_PORT_H__
#define __NM_SETTING_BRIDGE_PORT_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_BRIDGE_PORT            (nm_setting_bridge_port_get_type ())
#define NM_SETTING_BRIDGE_PORT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_BRIDGE_PORT, NMSettingBridgePort))
#define NM_SETTING_BRIDGE_PORT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_BRIDGE_PORT, NMSettingBridgePortClass))
#define NM_IS_SETTING_BRIDGE_PORT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_BRIDGE_PORT))
#define NM_IS_SETTING_BRIDGE_PORT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_BRIDGE_PORT))
#define NM_SETTING_BRIDGE_PORT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_BRIDGE_PORT, NMSettingBridgePortClass))

#define NM_SETTING_BRIDGE_PORT_SETTING_NAME "bridge-port"

#define NM_SETTING_BRIDGE_PORT_PRIORITY     "priority"
#define NM_SETTING_BRIDGE_PORT_PATH_COST    "path-cost"
#define NM_SETTING_BRIDGE_PORT_HAIRPIN_MODE "hairpin-mode"

/**
 * NMSettingBridgePort:
 */
struct _NMSettingBridgePort {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	/*< private >*/
	gpointer padding[4];
} NMSettingBridgePortClass;

GType nm_setting_bridge_port_get_type (void);

NMSetting * nm_setting_bridge_port_new              (void);

guint16     nm_setting_bridge_port_get_priority     (NMSettingBridgePort *setting);

guint16     nm_setting_bridge_port_get_path_cost    (NMSettingBridgePort *setting);

gboolean    nm_setting_bridge_port_get_hairpin_mode (NMSettingBridgePort *setting);

G_END_DECLS

#endif /* __NM_SETTING_BRIDGE_PORT_H__ */
