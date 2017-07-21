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
 * Copyright 2011 - 2015 Red Hat, Inc.
 */

#ifndef __NM_SETTING_BRIDGE_H__
#define __NM_SETTING_BRIDGE_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_BRIDGE            (nm_setting_bridge_get_type ())
#define NM_SETTING_BRIDGE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_BRIDGE, NMSettingBridge))
#define NM_SETTING_BRIDGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_BRIDGE, NMSettingBridgeClass))
#define NM_IS_SETTING_BRIDGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_BRIDGE))
#define NM_IS_SETTING_BRIDGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_BRIDGE))
#define NM_SETTING_BRIDGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_BRIDGE, NMSettingBridgeClass))

#define NM_SETTING_BRIDGE_SETTING_NAME "bridge"

#define NM_SETTING_BRIDGE_MAC_ADDRESS    "mac-address"
#define NM_SETTING_BRIDGE_STP            "stp"
#define NM_SETTING_BRIDGE_PRIORITY       "priority"
#define NM_SETTING_BRIDGE_FORWARD_DELAY  "forward-delay"
#define NM_SETTING_BRIDGE_HELLO_TIME     "hello-time"
#define NM_SETTING_BRIDGE_MAX_AGE        "max-age"
#define NM_SETTING_BRIDGE_AGEING_TIME    "ageing-time"
#define NM_SETTING_BRIDGE_GROUP_FORWARD_MASK "group-forward-mask"
#define NM_SETTING_BRIDGE_MULTICAST_SNOOPING "multicast-snooping"

/**
 * NMSettingBridge:
 *
 * Bridging Settings
 */
struct _NMSettingBridge {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	/*< private >*/
	gpointer padding[4];
} NMSettingBridgeClass;

GType nm_setting_bridge_get_type (void);

NMSetting *  nm_setting_bridge_new                (void);

const char * nm_setting_bridge_get_mac_address    (NMSettingBridge *setting);

gboolean     nm_setting_bridge_get_stp            (NMSettingBridge *setting);

guint16      nm_setting_bridge_get_priority       (NMSettingBridge *setting);

guint16      nm_setting_bridge_get_forward_delay  (NMSettingBridge *setting);

guint16      nm_setting_bridge_get_hello_time     (NMSettingBridge *setting);

guint16      nm_setting_bridge_get_max_age        (NMSettingBridge *setting);

guint32      nm_setting_bridge_get_ageing_time    (NMSettingBridge *setting);
NM_AVAILABLE_IN_1_10
guint16      nm_setting_bridge_get_group_forward_mask (NMSettingBridge *setting);

gboolean     nm_setting_bridge_get_multicast_snooping (NMSettingBridge *setting);

G_END_DECLS

#endif /* __NM_SETTING_BRIDGE_H__ */
