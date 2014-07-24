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
 * Copyright 2011 - 2012 Red Hat, Inc.
 */

#ifndef NM_SETTING_BRIDGE_H
#define NM_SETTING_BRIDGE_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_BRIDGE            (nm_setting_bridge_get_type ())
#define NM_SETTING_BRIDGE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_BRIDGE, NMSettingBridge))
#define NM_SETTING_BRIDGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_BRIDGE, NMSettingBridgeClass))
#define NM_IS_SETTING_BRIDGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_BRIDGE))
#define NM_IS_SETTING_BRIDGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_BRIDGE))
#define NM_SETTING_BRIDGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_BRIDGE, NMSettingBridgeClass))

#define NM_SETTING_BRIDGE_SETTING_NAME "bridge"

/**
 * NMSettingBridgeError:
 * @NM_SETTING_BRIDGE_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_SETTING_BRIDGE_ERROR_INVALID_PROPERTY: the property was invalid
 * @NM_SETTING_BRIDGE_ERROR_MISSING_PROPERTY: the property was missing and is
 * required
 *
 * Since: 0.9.8
 */
typedef enum {
	NM_SETTING_BRIDGE_ERROR_UNKNOWN = 0,      /*< nick=UnknownError >*/
	NM_SETTING_BRIDGE_ERROR_INVALID_PROPERTY, /*< nick=InvalidProperty >*/
	NM_SETTING_BRIDGE_ERROR_MISSING_PROPERTY, /*< nick=MissingProperty >*/
} NMSettingBridgeError;

#define NM_SETTING_BRIDGE_ERROR nm_setting_bridge_error_quark ()
GQuark nm_setting_bridge_error_quark (void);

#define NM_SETTING_BRIDGE_INTERFACE_NAME "interface-name"
#define NM_SETTING_BRIDGE_MAC_ADDRESS    "mac-address"
#define NM_SETTING_BRIDGE_STP            "stp"
#define NM_SETTING_BRIDGE_PRIORITY       "priority"
#define NM_SETTING_BRIDGE_FORWARD_DELAY  "forward-delay"
#define NM_SETTING_BRIDGE_HELLO_TIME     "hello-time"
#define NM_SETTING_BRIDGE_MAX_AGE        "max-age"
#define NM_SETTING_BRIDGE_AGEING_TIME    "ageing-time"

typedef struct {
	NMSetting parent;
} NMSettingBridge;

typedef struct {
	NMSettingClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
} NMSettingBridgeClass;

GType nm_setting_bridge_get_type (void);

NMSetting *  nm_setting_bridge_new                (void);

const char * nm_setting_bridge_get_interface_name (NMSettingBridge *setting);

NM_AVAILABLE_IN_0_9_10
const GByteArray *nm_setting_bridge_get_mac_address (NMSettingBridge *setting);

gboolean     nm_setting_bridge_get_stp            (NMSettingBridge *setting);

guint16      nm_setting_bridge_get_priority       (NMSettingBridge *setting);

guint16      nm_setting_bridge_get_forward_delay  (NMSettingBridge *setting);

guint16      nm_setting_bridge_get_hello_time     (NMSettingBridge *setting);

guint16      nm_setting_bridge_get_max_age        (NMSettingBridge *setting);

guint32      nm_setting_bridge_get_ageing_time    (NMSettingBridge *setting);

G_END_DECLS

#endif /* NM_SETTING_BRIDGE_H */
